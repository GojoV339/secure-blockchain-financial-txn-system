// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  TransactionContract
 * @notice Validates and records financial transactions on-chain.
 *
 * @dev    Architecture:
 *   - Each wallet is funded via {fundWallet}, which credits an internal
 *     balance ledger (no real ETH leaves the contract until withdrawal).
 *   - {submitTransaction} checks the sender has sufficient ledger balance,
 *     reserves the funds, creates a Pending record, and emits
 *     {TransactionSubmitted}.
 *   - The contract owner calls {approveTransaction} or {rejectTransaction}:
 *       Approve  → credits receiver's ledger, emits {TransactionApproved}.
 *       Reject   → refunds sender's ledger, emits {TransactionRejected}.
 *   - All ledger values are stored in wei; helper view functions exist for
 *     the Python layer to convert to Ether.
 *
 * Security notes:
 *   - Only the deploying account (owner) may approve or reject.
 *   - Funds are reserved before the event is emitted to prevent reentrancy.
 *   - Solidity 0.8.x arithmetic reverts on overflow by default.
 */
contract TransactionContract {
    // ────────────────────────────────────────────────────────────
    // Types
    // ────────────────────────────────────────────────────────────

    /// @notice Lifecycle state of a submitted transaction.
    enum Status {
        Pending,
        Approved,
        Rejected
    }

    /// @notice Full record stored on-chain for each submitted transaction.
    struct TxRecord {
        address sender;
        address receiver;
        uint256 value;        // in wei
        uint256 txFee;        // in wei
        Status  status;
        uint256 timestamp;    // block.timestamp at submission
        string  rejectReason; // set only when Rejected
    }

    // ────────────────────────────────────────────────────────────
    // State
    // ────────────────────────────────────────────────────────────

    /// @notice The account that deployed this contract (approves / rejects).
    address public owner;

    /// @notice Internal balance ledger (address → wei).
    mapping(address => uint256) public balances;

    /// @notice Transaction records keyed by their unique hash.
    mapping(bytes32 => TxRecord) private _transactions;

    /// @notice Ordered list of all submitted transaction hashes.
    bytes32[] private _txHashes;

    // ────────────────────────────────────────────────────────────
    // Events
    // ────────────────────────────────────────────────────────────

    /**
     * @notice Emitted when a new transaction is submitted.
     * @param txHash   The unique identifier assigned to this transaction.
     * @param sender   The wallet that submitted the transaction.
     * @param receiver The intended recipient wallet.
     * @param value    Transfer value in wei.
     * @param txFee    Transaction fee in wei.
     * @param timestamp Block timestamp at submission.
     */
    event TransactionSubmitted(
        bytes32 indexed txHash,
        address indexed sender,
        address indexed receiver,
        uint256 value,
        uint256 txFee,
        uint256 timestamp
    );

    /**
     * @notice Emitted when the owner approves a pending transaction.
     * @param txHash   The approved transaction identifier.
     * @param sender   Original sender of the transaction.
     * @param receiver Who receives the credited value.
     * @param value    Approved value in wei.
     */
    event TransactionApproved(
        bytes32 indexed txHash,
        address indexed sender,
        address indexed receiver,
        uint256 value
    );

    /**
     * @notice Emitted when the owner rejects a pending transaction.
     *         Funds are fully refunded to the sender's ledger.
     * @param txHash The rejected transaction identifier.
     * @param sender Original sender (whose balance is refunded).
     * @param reason Human-readable rejection explanation.
     */
    event TransactionRejected(
        bytes32 indexed txHash,
        address indexed sender,
        string  reason
    );

    /**
     * @notice Emitted when ETH is deposited and credited to a wallet.
     * @param wallet  The address whose ledger balance was increased.
     * @param amount  Amount credited in wei.
     */
    event WalletFunded(address indexed wallet, uint256 amount);

    // ────────────────────────────────────────────────────────────
    // Modifiers
    // ────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "TransactionContract: caller is not owner");
        _;
    }

    // ────────────────────────────────────────────────────────────
    // Constructor
    // ────────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ────────────────────────────────────────────────────────────
    // Wallet funding
    // ────────────────────────────────────────────────────────────

    /**
     * @notice Fund a wallet's internal ledger balance.
     *
     * @dev    The caller sends ETH (msg.value) which is credited to
     *         `wallet`'s internal balance.  The ETH is held by the
     *         contract until transactions are approved.
     *
     * @param wallet  The Ethereum address to credit.
     *
     * Emits {WalletFunded}.
     */
    function fundWallet(address wallet) external payable {
        require(msg.value > 0, "TransactionContract: must send ETH to fund");
        require(wallet != address(0), "TransactionContract: invalid wallet address");

        balances[wallet] += msg.value;
        emit WalletFunded(wallet, msg.value);
    }

    // ────────────────────────────────────────────────────────────
    // Transaction lifecycle
    // ────────────────────────────────────────────────────────────

    /**
     * @notice Submit a new transaction for owner approval.
     *
     * @dev    Deducts `value + txFee` from `msg.sender`'s ledger balance
     *         before storing the record, so funds are reserved and cannot
     *         be double-spent.  A unique `txHash` is derived from the
     *         transaction parameters plus the current block context.
     *
     * @param receiver  Destination wallet address.
     * @param value     Transfer amount in wei (must be > 0).
     * @param txFee     Fee amount in wei (may be 0).
     *
     * @return txHash  The unique bytes32 identifier for this transaction.
     *
     * Emits {TransactionSubmitted}.
     */
    function submitTransaction(
        address receiver,
        uint256 value,
        uint256 txFee
    ) external returns (bytes32) {
        require(receiver != address(0), "TransactionContract: invalid receiver");
        require(value > 0, "TransactionContract: value must be greater than zero");

        uint256 total = value + txFee;
        require(
            balances[msg.sender] >= total,
            "TransactionContract: insufficient balance"
        );

        // Reserve funds before emitting to prevent reentrancy issues
        balances[msg.sender] -= total;

        bytes32 txHash = keccak256(
            abi.encodePacked(
                msg.sender,
                receiver,
                value,
                txFee,
                block.timestamp,
                block.number,
                _txHashes.length
            )
        );

        _transactions[txHash] = TxRecord({
            sender:       msg.sender,
            receiver:     receiver,
            value:        value,
            txFee:        txFee,
            status:       Status.Pending,
            timestamp:    block.timestamp,
            rejectReason: ""
        });

        _txHashes.push(txHash);

        emit TransactionSubmitted(
            txHash,
            msg.sender,
            receiver,
            value,
            txFee,
            block.timestamp
        );

        return txHash;
    }

    /**
     * @notice Approve a pending transaction (owner only).
     *
     * @dev    Credits the receiver's ledger balance with the transaction
     *         value.  The `txFee` remains in the contract (simulating a
     *         miner/validator fee).
     *
     * @param txHash  The transaction identifier from {submitTransaction}.
     *
     * Emits {TransactionApproved}.
     */
    function approveTransaction(bytes32 txHash) external onlyOwner {
        TxRecord storage txRecord = _transactions[txHash];

        require(
            txRecord.sender != address(0),
            "TransactionContract: transaction not found"
        );
        require(
            txRecord.status == Status.Pending,
            "TransactionContract: transaction is not pending"
        );

        txRecord.status = Status.Approved;

        // Credit value to receiver; fee stays in contract (simulated miner reward)
        balances[txRecord.receiver] += txRecord.value;

        emit TransactionApproved(
            txHash,
            txRecord.sender,
            txRecord.receiver,
            txRecord.value
        );
    }

    /**
     * @notice Reject a pending transaction and refund the sender (owner only).
     *
     * @dev    Refunds `value + txFee` to the sender's ledger balance and
     *         records the rejection reason on-chain.
     *
     * @param txHash  The transaction identifier from {submitTransaction}.
     * @param reason  Human-readable reason for rejection.
     *
     * Emits {TransactionRejected}.
     */
    function rejectTransaction(
        bytes32 txHash,
        string calldata reason
    ) external onlyOwner {
        TxRecord storage txRecord = _transactions[txHash];

        require(
            txRecord.sender != address(0),
            "TransactionContract: transaction not found"
        );
        require(
            txRecord.status == Status.Pending,
            "TransactionContract: transaction is not pending"
        );

        txRecord.status = Status.Rejected;
        txRecord.rejectReason = reason;

        // Full refund: value + fee returned to sender
        balances[txRecord.sender] += txRecord.value + txRecord.txFee;

        emit TransactionRejected(txHash, txRecord.sender, reason);
    }

    // ────────────────────────────────────────────────────────────
    // View functions
    // ────────────────────────────────────────────────────────────

    /**
     * @notice Retrieve the full record for a submitted transaction.
     * @param txHash  The transaction identifier.
     * @return        The {TxRecord} struct for this transaction.
     */
    function getTransaction(bytes32 txHash)
        external
        view
        returns (TxRecord memory)
    {
        require(
            _transactions[txHash].sender != address(0),
            "TransactionContract: transaction not found"
        );
        return _transactions[txHash];
    }

    /**
     * @notice Return the internal ledger balance (in wei) for a wallet.
     * @param wallet  The address to query.
     * @return        Balance in wei.
     */
    function getBalance(address wallet) external view returns (uint256) {
        return balances[wallet];
    }

    /**
     * @notice Total number of transactions ever submitted.
     * @return Count of submitted transactions.
     */
    function getTxCount() external view returns (uint256) {
        return _txHashes.length;
    }

    /**
     * @notice Return the transaction hash at a given index.
     * @param index  Zero-based index into the submission order.
     * @return       The bytes32 transaction hash.
     */
    function getTxHashAt(uint256 index) external view returns (bytes32) {
        require(
            index < _txHashes.length,
            "TransactionContract: index out of bounds"
        );
        return _txHashes[index];
    }
}
