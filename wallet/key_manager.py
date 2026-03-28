"""
ECDSA key pair management for the Wallet Identity Module.

Handles generation, encrypted persistence, and loading of elliptic-curve
key pairs (secp256k1) for each wallet address.

Security Design Decisions:
    1. **Encryption at rest** — Private keys are serialised as PEM and
       encrypted with AES-256-CBC using a passphrase-derived key
       (PBKDF2HMAC via ``BestAvailableEncryption``). The passphrase is
       sourced from the ``WALLET_ENCRYPTION_PASSPHRASE`` env var and is
       never stored in code or logged.
    2. **No plaintext keys** — ``generate_key_pair()``, ``save_keys()``,
       and ``load_private_key()`` never log or print key material.
       The ``__repr__`` of key objects from the ``cryptography`` library
       already redacts sensitive data.
    3. **File permissions** — Private key files are written with
       owner-only permissions (0o600) on POSIX systems.
    4. **Rate-limit annotation** — Batch key generation is documented
       for downstream rate limiting when exposed via the Phase 6 Flask API.

Curve choice (secp256k1):
    Matches the Ethereum network's native signing curve, ensuring
    compatibility with real Ethereum wallets and tooling.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from wallet.config import KEYSTORE_PATH, configure_logging, get_encryption_passphrase
from wallet.exceptions import KeyGenerationError, KeyStorageError

logger = configure_logging(__name__)

# Ethereum's native curve
_CURVE: ec.EllipticCurve = ec.SECP256K1()

# File naming conventions inside the keystore
_PRIVATE_KEY_SUFFIX: str = "_private.pem"
_PUBLIC_KEY_SUFFIX: str = "_public.pem"


# Key generation


def generate_key_pair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a new ECDSA key pair on the secp256k1 curve.

    Security:
        - Uses ``cryptography`` library's secure random number generator.
        - The private key object is returned in memory only — it must be
          encrypted before being written to disk via ``save_keys()``.
        - Key material is never logged.

    Rate-limit note (Phase 6):
        When exposed through the Flask API, this function should be
        rate-limited to **10 key pairs per minute per client IP** to
        prevent resource exhaustion from bulk key generation requests.

    Returns:
        A tuple of ``(private_key, public_key)``.

    Raises:
        KeyGenerationError: If the underlying cryptographic library
            fails to generate a valid key pair.
    """
    try:
        private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(_CURVE)
        public_key: ec.EllipticCurvePublicKey = private_key.public_key()
        logger.debug("Generated new ECDSA key pair on secp256k1")
        return private_key, public_key
    except Exception as exc:
        raise KeyGenerationError(f"Failed to generate ECDSA key pair: {exc}") from exc


# Serialisation helpers


def serialize_private_key(
    private_key: ec.EllipticCurvePrivateKey,
    passphrase: str,
) -> bytes:
    """Serialise a private key to PEM format, encrypted with a passphrase.

    Security:
        Uses ``BestAvailableEncryption`` which selects AES-256-CBC
        with PBKDF2-HMAC key derivation. The passphrase is encoded
        to UTF-8 bytes and never stored or logged.

    Args:
        private_key: The ECDSA private key to serialise.
        passphrase: The encryption passphrase (from env var).

    Returns:
        PEM-encoded encrypted private key bytes.

    Raises:
        KeyStorageError: If serialisation fails.
    """
    try:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            ),
        )
    except Exception as exc:
        raise KeyStorageError(f"Failed to serialise private key: {exc}") from exc


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialise a public key to PEM format (unencrypted).

    Public keys are not secret and do not require encryption.

    Args:
        public_key: The ECDSA public key to serialise.

    Returns:
        PEM-encoded public key bytes.

    Raises:
        KeyStorageError: If serialisation fails.
    """
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:
        raise KeyStorageError(f"Failed to serialise public key: {exc}") from exc


# Persistence


def _address_to_filename(address: str) -> str:
    """Convert an Ethereum address to a safe filename component.

    Strips the ``0x`` prefix and lowercases to create a uniform,
    filesystem-safe identifier.

    Args:
        address: A validated Ethereum address (e.g. ``0xabc...``).

    Returns:
        The address without the ``0x`` prefix, lowercased.
    """
    return address.lower().removeprefix("0x")


def save_keys(
    address: str,
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    passphrase: str,
    keystore_dir: Path | None = None,
) -> None:
    """Persist an encrypted private key and public key to disk.

    Security:
        - Private key file is encrypted with the passphrase before writing.
        - On POSIX systems, private key files are set to owner-only read
          permissions (``0o600``) to prevent other users from reading them.
        - The passphrase itself is not written to disk.
        - File paths are derived from the wallet address to prevent
          directory traversal attacks (only hex characters after prefix removal).

    Args:
        address: The wallet address these keys belong to.
        private_key: The ECDSA private key to persist.
        public_key: The corresponding ECDSA public key.
        passphrase: Encryption passphrase for the private key.
        keystore_dir: Directory to write key files into.
            Defaults to ``KEYSTORE_PATH`` from config.

    Raises:
        KeyStorageError: If the directory cannot be created or files
            cannot be written.
    """
    target_dir: Path = keystore_dir or KEYSTORE_PATH
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KeyStorageError(
            f"Cannot create keystore directory '{target_dir}': {exc}"
        ) from exc

    filename_base: str = _address_to_filename(address)

    # --- Private key (encrypted) ---
    private_key_path: Path = target_dir / f"{filename_base}{_PRIVATE_KEY_SUFFIX}"
    encrypted_pem: bytes = serialize_private_key(private_key, passphrase)
    try:
        private_key_path.write_bytes(encrypted_pem)
        # Restrict permissions: owner read-only (POSIX)
        os.chmod(private_key_path, 0o600)
    except OSError as exc:
        raise KeyStorageError(f"Failed to write private key file: {exc}") from exc

    # --- Public key (unencrypted) ---
    public_key_path: Path = target_dir / f"{filename_base}{_PUBLIC_KEY_SUFFIX}"
    public_pem: bytes = serialize_public_key(public_key)
    try:
        public_key_path.write_bytes(public_pem)
    except OSError as exc:
        raise KeyStorageError(f"Failed to write public key file: {exc}") from exc

    logger.info("Keys saved for address %s", address)


# Loading


def load_private_key(
    address: str,
    passphrase: str,
    keystore_dir: Path | None = None,
) -> ec.EllipticCurvePrivateKey:
    """Load and decrypt a private key from disk.

    Security:
        - Decryption requires the correct passphrase. An incorrect
          passphrase raises ``KeyStorageError`` — it does NOT fall back
          to loading unencrypted.
        - The decrypted key object lives only in memory.

    Args:
        address: The wallet address whose private key to load.
        passphrase: The passphrase used during ``save_keys()``.
        keystore_dir: Directory containing key files.
            Defaults to ``KEYSTORE_PATH`` from config.

    Returns:
        The decrypted ECDSA private key.

    Raises:
        KeyStorageError: If the file is not found, the passphrase is
            wrong, or the file is corrupted.
    """
    target_dir: Path = keystore_dir or KEYSTORE_PATH
    filename_base: str = _address_to_filename(address)
    private_key_path: Path = target_dir / f"{filename_base}{_PRIVATE_KEY_SUFFIX}"

    if not private_key_path.exists():
        raise KeyStorageError(
            f"Private key file not found for address {address}: {private_key_path}"
        )

    try:
        pem_data: bytes = private_key_path.read_bytes()
        loaded_key = serialization.load_pem_private_key(
            pem_data,
            password=passphrase.encode("utf-8"),
        )
    except (ValueError, TypeError) as exc:
        raise KeyStorageError(
            f"Failed to decrypt private key for {address} — "
            f"wrong passphrase or corrupted file: {exc}"
        ) from exc
    except OSError as exc:
        raise KeyStorageError(
            f"Failed to read private key file for {address}: {exc}"
        ) from exc

    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        raise KeyStorageError(f"Loaded key for {address} is not an ECDSA private key")

    logger.debug("Loaded private key for address %s", address)
    return loaded_key


def load_public_key(
    address: str,
    keystore_dir: Path | None = None,
) -> ec.EllipticCurvePublicKey:
    """Load a public key from disk.

    Args:
        address: The wallet address whose public key to load.
        keystore_dir: Directory containing key files.
            Defaults to ``KEYSTORE_PATH`` from config.

    Returns:
        The ECDSA public key.

    Raises:
        KeyStorageError: If the file is not found or corrupted.
    """
    target_dir: Path = keystore_dir or KEYSTORE_PATH
    filename_base: str = _address_to_filename(address)
    public_key_path: Path = target_dir / f"{filename_base}{_PUBLIC_KEY_SUFFIX}"

    if not public_key_path.exists():
        raise KeyStorageError(
            f"Public key file not found for address {address}: {public_key_path}"
        )

    try:
        pem_data: bytes = public_key_path.read_bytes()
        loaded_key = serialization.load_pem_public_key(pem_data)
    except (ValueError, TypeError) as exc:
        raise KeyStorageError(
            f"Failed to load public key for {address}: {exc}"
        ) from exc
    except OSError as exc:
        raise KeyStorageError(
            f"Failed to read public key file for {address}: {exc}"
        ) from exc

    if not isinstance(loaded_key, ec.EllipticCurvePublicKey):
        raise KeyStorageError(f"Loaded key for {address} is not an ECDSA public key")

    logger.debug("Loaded public key for address %s", address)
    return loaded_key


# Batch generation


def generate_keys_for_addresses(
    addresses: set[str],
    passphrase: str | None = None,
    keystore_dir: Path | None = None,
) -> int:
    """Generate and persist key pairs for a batch of wallet addresses.

    Skips addresses that already have key files in the keystore to
    support idempotent re-runs.

    Rate-limit note (Phase 6):
        When exposed via the Flask API, this endpoint must be
        rate-limited to **1 request per 5 minutes per client IP**
        because it is computationally expensive. Consider running
        batch generation as a background task (Celery / RQ) rather
        than synchronously in a request handler.

    Args:
        addresses: Set of validated Ethereum addresses.
        passphrase: Encryption passphrase. Defaults to env var.
        keystore_dir: Directory for key files. Defaults to config.

    Returns:
        The number of newly generated key pairs (excludes skipped).

    Raises:
        KeyGenerationError: If key generation fails for any address.
        KeyStorageError: If key persistence fails.
    """
    resolved_passphrase: str = passphrase or get_encryption_passphrase()
    resolved_dir: Path = keystore_dir or KEYSTORE_PATH
    generated_count: int = 0

    for address in addresses:
        filename_base: str = _address_to_filename(address)
        private_path: Path = resolved_dir / f"{filename_base}{_PRIVATE_KEY_SUFFIX}"

        if private_path.exists():
            logger.debug("Keys already exist for %s — skipping", address)
            continue

        private_key, public_key = generate_key_pair()
        save_keys(address, private_key, public_key, resolved_passphrase, resolved_dir)
        generated_count += 1

    logger.info(
        "Batch key generation complete: %d new keys, %d total addresses",
        generated_count,
        len(addresses),
    )
    return generated_count
