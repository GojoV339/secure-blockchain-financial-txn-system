"""
Custom exception classes for the Wallet Identity Module.

Each exception maps to a specific failure domain so callers can handle
errors precisely rather than catching broad built-in exceptions.
"""


class WalletBaseError(Exception):
    """Base exception for all wallet module errors."""


class InvalidAddressError(WalletBaseError):
    """Raised when a wallet address fails validation.

    A valid Ethereum address must:
    - Start with '0x' prefix
    - Contain exactly 40 hexadecimal characters after the prefix
    - Total length of 42 characters
    """


class DatasetLoadError(WalletBaseError):
    """Raised when the transaction dataset cannot be loaded or parsed.

    Common causes:
    - File not found at the configured path
    - Missing required columns ('From', 'To')
    - File is empty or corrupted
    """


class KeyGenerationError(WalletBaseError):
    """Raised when ECDSA key pair generation fails.

    This is typically caused by an issue with the underlying
    cryptographic library or invalid curve parameters.
    """


class KeyStorageError(WalletBaseError):
    """Raised when key persistence operations fail.

    Covers both save and load operations:
    - Encrypted private key file not found
    - Wrong passphrase during decryption
    - Filesystem permission errors
    - Corrupted key file
    """


class SignatureError(WalletBaseError):
    """Raised when transaction signing fails.

    Common causes:
    - Invalid private key
    - Malformed transaction data that cannot be serialised
    """


class VerificationError(WalletBaseError):
    """Raised when signature verification fails.

    This covers both cryptographic verification failure and
    structural issues such as signature malleability (high-S value)
    or missing replay-protection fields (nonce).
    """
