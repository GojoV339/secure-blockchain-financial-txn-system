"""
Shared pytest fixtures for the Wallet Identity Module tests.
"""

import csv
from pathlib import Path

import pytest




@pytest.fixture()
def tmp_keystore(tmp_path: Path) -> Path:
    """Provide a temporary keystore directory for key persistence tests."""
    keystore_dir: Path = tmp_path / "keystore"
    keystore_dir.mkdir()
    return keystore_dir


@pytest.fixture()
def sample_addresses() -> list[str]:
    """Return a list of valid Ethereum-format addresses for testing."""
    return [
        "0xdd487c027448d3364355707d91eefadc2dae9f88",
        "0x3e1b1fe45cb2040b97cdb3191d4933ad1ff0928d",
        "0xb66a63e5ba7a888450af2ede7a47fd99777b647a",
    ]


@pytest.fixture()
def sample_key_pair():
    """Generate a fresh ECDSA key pair for signing tests."""
    from wallet.key_manager import generate_key_pair

    private_key, public_key = generate_key_pair()
    return private_key, public_key


@pytest.fixture()
def sample_tx_data() -> dict[str, str]:
    """Return sample transaction data matching the dataset schema."""
    return {
        "from": "0xdd487c027448d3364355707d91eefadc2dae9f88",
        "to": "0x3e1b1fe45cb2040b97cdb3191d4933ad1ff0928d",
        "value": "0.5",
        "tx_fee": "0.000399",
    }


@pytest.fixture()
def sample_csv(tmp_path: Path) -> Path:
    """Create a temporary CSV file with valid and invalid addresses."""
    csv_file: Path = tmp_path / "test_txs.csv"
    rows = [
        {
            "Record": "0",
            "TxHash": "0xabc123",
            "Block": "5184886",
            "Age": "19 secs ago",
            "From": "0xdd487c027448d3364355707d91eefadc2dae9f88",
            "To": "0x3e1b1fe45cb2040b97cdb3191d4933ad1ff0928d",
            "Value": "0.5 Ether",
            "[TxFee]": "0.000399",
        },
        {
            "Record": "1",
            "TxHash": "0xdef456",
            "Block": "5184886",
            "Age": "19 secs ago",
            "From": "0xb66a63e5ba7a888450af2ede7a47fd99777b647a",
            "To": "BinanceWallet",
            "Value": "0.79841 Ether",
            "[TxFee]": "0.000420",
        },
    ]
    with open(csv_file, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return csv_file


@pytest.fixture()
def empty_csv(tmp_path: Path) -> Path:
    """Create a CSV file with only headers and no data rows."""
    csv_file: Path = tmp_path / "empty_txs.csv"
    with open(csv_file, "w", newline="") as fh:
        fh.write("Record,TxHash,Block,Age,From,To,Value,[TxFee]\n")
    return csv_file


@pytest.fixture()
def missing_columns_csv(tmp_path: Path) -> Path:
    """Create a CSV file missing the required 'From' and 'To' columns."""
    csv_file: Path = tmp_path / "bad_columns.csv"
    with open(csv_file, "w", newline="") as fh:
        fh.write("Record,TxHash,Block,Age,Value\n")
        fh.write("0,0xabc,123,19 secs ago,0.5\n")
    return csv_file


@pytest.fixture()
def test_passphrase() -> str:
    """Return a test passphrase for key encryption tests."""
    return "test-passphrase-for-unit-tests-only"
