"""
Unit tests for blockchain.contract.

Uses ``unittest.mock`` to simulate web3.py so no live Ganache or Hardhat
node is required — all tests are fully CI-safe.

Test strategy:
    - ``load_abi`` is tested by writing a real artifact JSON to tmp_path.
    - ``ContractInterface`` methods are tested with a mock Web3 instance
      whose ``eth.contract()`` returns a configured MagicMock.
    - web3 static helpers (to_wei, from_wei, to_checksum_address) are
      patched to their real implementations so unit conversions are correct.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from web3 import Web3

from blockchain.contract import (
    ContractInterface,
    _STATUS_LABELS,
    load_abi,
)

# ─────────────────────────────────────────────────────────────────────────────
# Constants shared across tests
# ─────────────────────────────────────────────────────────────────────────────

# Using Hardhat's deterministic accounts #0 and #1 (always checksummed)
_OWNER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_RECEIVER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_CONTRACT_ADDR = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

# Minimal ABI that satisfies ContractInterface (all methods + events referenced)
_MINIMAL_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "fundWallet",
        "inputs": [{"name": "wallet", "type": "address"}],
        "outputs": [],
        "stateMutability": "payable",
    },
    {
        "type": "function",
        "name": "submitTransaction",
        "inputs": [
            {"name": "receiver", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "txFee", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "approveTransaction",
        "inputs": [{"name": "txHash", "type": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "rejectTransaction",
        "inputs": [
            {"name": "txHash", "type": "bytes32"},
            {"name": "reason", "type": "string"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "getTransaction",
        "inputs": [{"name": "txHash", "type": "bytes32"}],
        "outputs": [
            {
                "components": [
                    {"name": "sender", "type": "address"},
                    {"name": "receiver", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "txFee", "type": "uint256"},
                    {"name": "status", "type": "uint8"},
                    {"name": "timestamp", "type": "uint256"},
                    {"name": "rejectReason", "type": "string"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getBalance",
        "inputs": [{"name": "wallet", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getTxCount",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getTxHashAt",
        "inputs": [{"name": "index", "type": "uint256"}],
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
    },
    {
        "type": "event",
        "name": "TransactionSubmitted",
        "inputs": [
            {"indexed": True, "name": "txHash", "type": "bytes32"},
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": True, "name": "receiver", "type": "address"},
            {"indexed": False, "name": "value", "type": "uint256"},
            {"indexed": False, "name": "txFee", "type": "uint256"},
            {"indexed": False, "name": "timestamp", "type": "uint256"},
        ],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "TransactionApproved",
        "inputs": [
            {"indexed": True, "name": "txHash", "type": "bytes32"},
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": True, "name": "receiver", "type": "address"},
            {"indexed": False, "name": "value", "type": "uint256"},
        ],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "TransactionRejected",
        "inputs": [
            {"indexed": True, "name": "txHash", "type": "bytes32"},
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": False, "name": "reason", "type": "string"},
        ],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "WalletFunded",
        "inputs": [
            {"indexed": True, "name": "wallet", "type": "address"},
            {"indexed": False, "name": "amount", "type": "uint256"},
        ],
        "anonymous": False,
    },
]

_SAMPLE_TX_HASH: bytes = b"\x00" * 31 + b"\x01"  # deterministic 32-byte value


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def artifact_file(tmp_path: Path) -> Path:
    """Write a minimal Hardhat-style artifact JSON to tmp_path."""
    artifact = {
        "abi": _MINIMAL_ABI,
        "bytecode": "0x",
        "contractName": "TransactionContract",
    }
    artifact_path = tmp_path / "TransactionContract.json"
    artifact_path.write_text(json.dumps(artifact))
    return artifact_path


@pytest.fixture()
def mock_w3() -> MagicMock:
    """Mocked Web3 instance with real unit-conversion helpers."""
    w3 = MagicMock()
    # Real conversions so arithmetic in our code is correct
    w3.to_wei.side_effect = Web3.to_wei
    w3.from_wei.side_effect = Web3.from_wei
    # eth.wait_for_transaction_receipt returns a simple mock receipt
    w3.eth.wait_for_transaction_receipt.return_value = MagicMock(name="receipt")
    return w3


@pytest.fixture()
def ci(mock_w3: MagicMock) -> ContractInterface:
    """ContractInterface wired to mock_w3, ABI provided directly."""
    return ContractInterface(mock_w3, _CONTRACT_ADDR, _MINIMAL_ABI)


# ─────────────────────────────────────────────────────────────────────────────
# load_abi
# ─────────────────────────────────────────────────────────────────────────────


class TestLoadAbi:
    """Tests for the ``load_abi`` helper function."""

    def test_loads_valid_artifact(self, artifact_file: Path) -> None:
        """ABI is loaded correctly from a valid Hardhat artifact file."""
        abi = load_abi(artifact_file)
        assert isinstance(abi, list)
        assert len(abi) > 0

    def test_abi_contains_functions(self, artifact_file: Path) -> None:
        """Loaded ABI contains function entries."""
        abi = load_abi(artifact_file)
        fn_names = {entry["name"] for entry in abi if entry.get("type") == "function"}
        assert "fundWallet" in fn_names
        assert "submitTransaction" in fn_names

    def test_raises_if_file_missing(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised when the artifact file does not exist."""
        with pytest.raises(FileNotFoundError, match="not found"):
            load_abi(tmp_path / "nonexistent.json")

    def test_uses_default_path_when_none(self, tmp_path: Path) -> None:
        """Passing no argument uses the default artifact path (which may not exist in CI)."""
        with patch("blockchain.contract._ABI_PATH", tmp_path / "missing.json"):
            with pytest.raises(FileNotFoundError):
                load_abi()


# ─────────────────────────────────────────────────────────────────────────────
# ContractInterface.__init__
# ─────────────────────────────────────────────────────────────────────────────


class TestContractInterfaceInit:
    """Tests for ContractInterface initialisation."""

    def test_stores_checksummed_address(self, mock_w3: MagicMock) -> None:
        """Constructor stores a valid checksummed address."""
        obj = ContractInterface(mock_w3, _CONTRACT_ADDR, _MINIMAL_ABI)
        assert obj.address == Web3.to_checksum_address(_CONTRACT_ADDR)

    def test_calls_eth_contract(self, mock_w3: MagicMock) -> None:
        """Constructor calls w3.eth.contract to create the contract binding."""
        ContractInterface(mock_w3, _CONTRACT_ADDR, _MINIMAL_ABI)
        mock_w3.eth.contract.assert_called_once()

    def test_abi_none_calls_load_abi(self, mock_w3: MagicMock, artifact_file: Path) -> None:
        """When abi=None, load_abi() is called to read from the artifact file."""
        with patch("blockchain.contract._ABI_PATH", artifact_file):
            obj = ContractInterface(mock_w3, _CONTRACT_ADDR, None)
        assert obj is not None


# ─────────────────────────────────────────────────────────────────────────────
# from_deployment_file
# ─────────────────────────────────────────────────────────────────────────────


class TestFromDeploymentFile:
    """Tests for the ``from_deployment_file`` factory classmethod."""

    def test_loads_address_from_json(self, mock_w3: MagicMock, tmp_path: Path) -> None:
        """Factory reads the contract address from deployment.json."""
        deployment = {"address": _CONTRACT_ADDR, "network": "ganache"}
        dep_file = tmp_path / "deployment.json"
        dep_file.write_text(json.dumps(deployment))

        obj = ContractInterface.from_deployment_file(mock_w3, dep_file, _MINIMAL_ABI)
        assert obj.address == Web3.to_checksum_address(_CONTRACT_ADDR)

    def test_raises_if_deployment_file_missing(
        self, mock_w3: MagicMock, tmp_path: Path
    ) -> None:
        """FileNotFoundError if deployment.json does not exist."""
        with pytest.raises(FileNotFoundError, match="not found"):
            ContractInterface.from_deployment_file(
                mock_w3, tmp_path / "missing.json", _MINIMAL_ABI
            )

    def test_uses_default_deployment_path(
        self, mock_w3: MagicMock, tmp_path: Path
    ) -> None:
        """Factory uses default _DEPLOYMENT_PATH when no path is supplied."""
        deployment = {"address": _CONTRACT_ADDR, "network": "ganache"}
        dep_file = tmp_path / "deployment.json"
        dep_file.write_text(json.dumps(deployment))

        with patch("blockchain.contract._DEPLOYMENT_PATH", dep_file):
            obj = ContractInterface.from_deployment_file(mock_w3, abi=_MINIMAL_ABI)
        assert obj.address == Web3.to_checksum_address(_CONTRACT_ADDR)


# ─────────────────────────────────────────────────────────────────────────────
# fund_wallet
# ─────────────────────────────────────────────────────────────────────────────


class TestFundWallet:
    """Tests for ``ContractInterface.fund_wallet``."""

    def test_returns_receipt(self, ci: ContractInterface, mock_w3: MagicMock) -> None:
        """fund_wallet returns the web3 transaction receipt."""
        receipt = ci.fund_wallet(_RECEIVER, amount_ether=1.0, sender=_OWNER)
        assert receipt is mock_w3.eth.wait_for_transaction_receipt.return_value

    def test_passes_correct_wei_value(
        self, ci: ContractInterface, mock_w3: MagicMock
    ) -> None:
        """fund_wallet converts Ether to wei before calling transact."""
        ci.fund_wallet(_RECEIVER, amount_ether=0.5, sender=_OWNER)
        # Retrieve the transact call kwargs — the "value" key should be 0.5 ETH in wei
        transact_call = (
            ci.contract.functions.fundWallet.return_value.transact
        )
        args, kwargs = transact_call.call_args
        tx_params = args[0] if args else kwargs
        assert tx_params["value"] == Web3.to_wei(0.5, "ether")

    def test_calls_fund_wallet_with_checksummed_address(
        self, ci: ContractInterface
    ) -> None:
        """Receiver address is passed checksummed to the contract function."""
        ci.fund_wallet(_RECEIVER.lower(), amount_ether=1.0, sender=_OWNER)
        ci.contract.functions.fundWallet.assert_called_once_with(
            Web3.to_checksum_address(_RECEIVER)
        )


# ─────────────────────────────────────────────────────────────────────────────
# submit_transaction
# ─────────────────────────────────────────────────────────────────────────────


class TestSubmitTransaction:
    """Tests for ``ContractInterface.submit_transaction``."""

    def _setup_submit_event(self, ci: ContractInterface) -> None:
        """Configure the mock contract to return a TransactionSubmitted event."""
        mock_log = MagicMock()
        mock_log.__getitem__ = lambda self, key: {"args": {"txHash": _SAMPLE_TX_HASH}}[key]
        ci.contract.events.TransactionSubmitted.return_value.process_receipt.return_value = (
            [mock_log]
        )

    def test_returns_contract_tx_hash(
        self, ci: ContractInterface, mock_w3: MagicMock
    ) -> None:
        """submit_transaction returns the bytes32 hash from the emitted event."""
        self._setup_submit_event(ci)
        result = ci.submit_transaction(_OWNER, _RECEIVER, 0.5, 0.001)
        assert result == _SAMPLE_TX_HASH

    def test_converts_value_and_fee_to_wei(
        self, ci: ContractInterface, mock_w3: MagicMock
    ) -> None:
        """Value and fee are converted to wei before the contract call."""
        self._setup_submit_event(ci)
        ci.submit_transaction(_OWNER, _RECEIVER, 1.0, 0.01)
        ci.contract.functions.submitTransaction.assert_called_once_with(
            Web3.to_checksum_address(_RECEIVER),
            Web3.to_wei(1.0, "ether"),
            Web3.to_wei(0.01, "ether"),
        )

    def test_raises_if_event_not_emitted(
        self, ci: ContractInterface, mock_w3: MagicMock
    ) -> None:
        """RuntimeError is raised when the event log is empty."""
        ci.contract.events.TransactionSubmitted.return_value.process_receipt.return_value = (
            []
        )
        with pytest.raises(RuntimeError, match="TransactionSubmitted event not emitted"):
            ci.submit_transaction(_OWNER, _RECEIVER, 0.5, 0.001)


# ─────────────────────────────────────────────────────────────────────────────
# approve_transaction / reject_transaction
# ─────────────────────────────────────────────────────────────────────────────


class TestApproveTransaction:
    """Tests for ``ContractInterface.approve_transaction``."""

    def test_returns_receipt(self, ci: ContractInterface, mock_w3: MagicMock) -> None:
        """approve_transaction returns the web3 transaction receipt."""
        receipt = ci.approve_transaction(_SAMPLE_TX_HASH, _OWNER)
        assert receipt is mock_w3.eth.wait_for_transaction_receipt.return_value

    def test_calls_approve_with_tx_hash(self, ci: ContractInterface) -> None:
        """approveTransaction is called with the correct bytes32 hash."""
        ci.approve_transaction(_SAMPLE_TX_HASH, _OWNER)
        ci.contract.functions.approveTransaction.assert_called_once_with(_SAMPLE_TX_HASH)


class TestRejectTransaction:
    """Tests for ``ContractInterface.reject_transaction``."""

    def test_calls_reject_with_reason(self, ci: ContractInterface) -> None:
        """rejectTransaction is called with the hash and reason string."""
        ci.reject_transaction(_SAMPLE_TX_HASH, _OWNER, "Fraud detected")
        ci.contract.functions.rejectTransaction.assert_called_once_with(
            _SAMPLE_TX_HASH, "Fraud detected"
        )

    def test_uses_default_reason(self, ci: ContractInterface) -> None:
        """Default reason 'Policy violation' is used when none is supplied."""
        ci.reject_transaction(_SAMPLE_TX_HASH, _OWNER)
        ci.contract.functions.rejectTransaction.assert_called_once_with(
            _SAMPLE_TX_HASH, "Policy violation"
        )

    def test_returns_receipt(self, ci: ContractInterface, mock_w3: MagicMock) -> None:
        """reject_transaction returns the web3 transaction receipt."""
        receipt = ci.reject_transaction(_SAMPLE_TX_HASH, _OWNER)
        assert receipt is mock_w3.eth.wait_for_transaction_receipt.return_value


# ─────────────────────────────────────────────────────────────────────────────
# get_transaction
# ─────────────────────────────────────────────────────────────────────────────


class TestGetTransaction:
    """Tests for ``ContractInterface.get_transaction``."""

    def _mock_record(self, ci: ContractInterface, status_index: int = 0) -> None:
        """Set up the contract mock to return a tuple matching TxRecord."""
        ci.contract.functions.getTransaction.return_value.call.return_value = (
            _OWNER,                          # sender
            _RECEIVER,                       # receiver
            Web3.to_wei(0.5, "ether"),       # value  (wei)
            Web3.to_wei(0.001, "ether"),     # txFee  (wei)
            status_index,                    # status (uint8)
            1_700_000_000,                   # timestamp
            "",                              # rejectReason
        )

    def test_returns_dict_with_expected_keys(self, ci: ContractInterface) -> None:
        """get_transaction returns a dict with all expected keys."""
        self._mock_record(ci)
        record = ci.get_transaction(_SAMPLE_TX_HASH)
        assert set(record.keys()) == {
            "sender", "receiver", "value_ether", "fee_ether",
            "status", "timestamp", "reject_reason",
        }

    def test_converts_wei_to_ether(self, ci: ContractInterface) -> None:
        """Value and fee are returned as Ether floats, not wei integers."""
        self._mock_record(ci)
        record = ci.get_transaction(_SAMPLE_TX_HASH)
        assert record["value_ether"] == pytest.approx(0.5, rel=1e-9)
        assert record["fee_ether"] == pytest.approx(0.001, rel=1e-9)

    def test_status_pending_label(self, ci: ContractInterface) -> None:
        """Status 0 maps to 'Pending'."""
        self._mock_record(ci, status_index=0)
        assert ci.get_transaction(_SAMPLE_TX_HASH)["status"] == "Pending"

    def test_status_approved_label(self, ci: ContractInterface) -> None:
        """Status 1 maps to 'Approved'."""
        self._mock_record(ci, status_index=1)
        assert ci.get_transaction(_SAMPLE_TX_HASH)["status"] == "Approved"

    def test_status_rejected_label(self, ci: ContractInterface) -> None:
        """Status 2 maps to 'Rejected'."""
        self._mock_record(ci, status_index=2)
        assert ci.get_transaction(_SAMPLE_TX_HASH)["status"] == "Rejected"


# ─────────────────────────────────────────────────────────────────────────────
# get_balance
# ─────────────────────────────────────────────────────────────────────────────


class TestGetBalance:
    """Tests for ``ContractInterface.get_balance``."""

    def test_returns_ether_float(self, ci: ContractInterface) -> None:
        """get_balance converts the returned wei to an Ether float."""
        ci.contract.functions.getBalance.return_value.call.return_value = (
            Web3.to_wei(2.5, "ether")
        )
        balance = ci.get_balance(_OWNER)
        assert balance == pytest.approx(2.5, rel=1e-9)
        assert isinstance(balance, float)

    def test_passes_checksummed_address(self, ci: ContractInterface) -> None:
        """Address is checksummed before the contract call."""
        ci.contract.functions.getBalance.return_value.call.return_value = 0
        ci.get_balance(_OWNER.lower())
        ci.contract.functions.getBalance.assert_called_once_with(
            Web3.to_checksum_address(_OWNER)
        )


# ─────────────────────────────────────────────────────────────────────────────
# get_tx_count / get_tx_hash_at
# ─────────────────────────────────────────────────────────────────────────────


class TestTxCountAndHash:
    """Tests for ``get_tx_count`` and ``get_tx_hash_at``."""

    def test_get_tx_count_returns_int(self, ci: ContractInterface) -> None:
        """get_tx_count returns an integer."""
        ci.contract.functions.getTxCount.return_value.call.return_value = 7
        assert ci.get_tx_count() == 7

    def test_get_tx_hash_at_returns_bytes(self, ci: ContractInterface) -> None:
        """get_tx_hash_at returns bytes."""
        ci.contract.functions.getTxHashAt.return_value.call.return_value = (
            list(_SAMPLE_TX_HASH)
        )
        result = ci.get_tx_hash_at(0)
        assert isinstance(result, bytes)


# ─────────────────────────────────────────────────────────────────────────────
# Events
# ─────────────────────────────────────────────────────────────────────────────


class TestEvents:
    """Tests for event log fetching methods."""

    def _mock_event_logs(
        self, event_mock: MagicMock, args: dict[str, Any]
    ) -> None:
        mock_entry = MagicMock()
        mock_entry.__getitem__ = lambda self, k: args if k == "args" else None
        event_mock.get_logs.return_value = [mock_entry]

    def test_get_submitted_events_returns_list(
        self, ci: ContractInterface
    ) -> None:
        """get_submitted_events returns a list of dicts."""
        args = {
            "txHash": _SAMPLE_TX_HASH,
            "sender": _OWNER,
            "receiver": _RECEIVER,
        }
        self._mock_event_logs(ci.contract.events.TransactionSubmitted, args)
        result = ci.get_submitted_events(from_block=0)
        assert isinstance(result, list)

    def test_get_approved_events_returns_list(self, ci: ContractInterface) -> None:
        """get_approved_events returns a list of dicts."""
        args = {
            "txHash": _SAMPLE_TX_HASH,
            "sender": _OWNER,
            "receiver": _RECEIVER,
        }
        self._mock_event_logs(ci.contract.events.TransactionApproved, args)
        result = ci.get_approved_events(from_block=0)
        assert isinstance(result, list)

    def test_get_rejected_events_returns_list(
        self, ci: ContractInterface
    ) -> None:
        """get_rejected_events returns a list of dicts."""
        args = {"txHash": _SAMPLE_TX_HASH, "sender": _OWNER, "reason": "Fraud"}
        self._mock_event_logs(ci.contract.events.TransactionRejected, args)
        result = ci.get_rejected_events(from_block=0)
        assert isinstance(result, list)


# ─────────────────────────────────────────────────────────────────────────────
# Status label constants
# ─────────────────────────────────────────────────────────────────────────────


class TestStatusLabels:
    """Verify the status label tuple matches the Solidity enum order."""

    def test_status_labels_order(self) -> None:
        """_STATUS_LABELS must be ('Pending', 'Approved', 'Rejected')."""
        assert _STATUS_LABELS == ("Pending", "Approved", "Rejected")

    def test_status_labels_count(self) -> None:
        """Exactly three status labels (matching the Solidity enum)."""
        assert len(_STATUS_LABELS) == 3
