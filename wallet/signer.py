"""
Digital signature module for the Wallet Identity system.

Provides transaction signing and verification using ECDSA on secp256k1,
with built-in protections against replay attacks and signature malleability.

Security Design Decisions:

    1. **Replay protection** — Every signed message includes a unique nonce
       (UUID4). The nonce is part of the canonical message that gets signed,
       so a valid signature for one nonce cannot be reused with a different
       nonce. Callers must track used nonces to fully prevent replay
       (e.g. in a database or in-memory set — implemented at the API layer
       in Phase 6).

    2. **Signature malleability protection** — ECDSA signatures (r, s) have
       a malleability property: given a valid signature (r, s), the pair
       (r, N - s) is also valid (where N is the curve order). This module
       enforces **low-S normalisation**: after signing, if s > N/2, it is
       replaced with N - s. During verification, any signature with a
       high-S value is rejected outright before cryptographic verification.
       This follows the same convention as Bitcoin (BIP-62) and Ethereum.

    3. **Canonical serialisation** — Transaction data is serialised to
       JSON with sorted keys and no whitespace to guarantee deterministic
       byte sequences. This prevents an attacker from modifying JSON
       formatting to create a "different" message with the same semantic
       content.

    4. **Signature format** — Signatures are encoded as raw (r || s) bytes
       in big-endian, fixed-width (32 bytes each = 64 bytes total) rather
       than DER. This avoids DER encoding ambiguity and simplifies
       malleability checks.
"""

import json
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from wallet.config import configure_logging
from wallet.exceptions import SignatureError, VerificationError

logger = configure_logging(__name__)

# ---------------------------------------------------------------------------
# secp256k1 curve order (N) — used for low-S normalisation
# ---------------------------------------------------------------------------
_SECP256K1_ORDER: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_HALF_ORDER: int = _SECP256K1_ORDER // 2

# Signature component size in bytes (32 bytes for secp256k1's 256-bit order)
_COMPONENT_SIZE: int = 32
_SIGNATURE_SIZE: int = _COMPONENT_SIZE * 2  # 64 bytes: r (32) + s (32)


# ---------------------------------------------------------------------------
# Nonce generation
# ---------------------------------------------------------------------------


def create_nonce() -> str:
    """Generate a cryptographically random nonce for replay protection.

    Uses UUID4 which is backed by ``os.urandom()`` — a CSPRNG.

    Security:
        Each nonce must be used at most once. The caller (or the
        Phase 6 API layer) is responsible for tracking used nonces
        to reject duplicates. The nonce is embedded in the signed
        message so reusing a signature with a different nonce will
        fail verification.

    Returns:
        A UUID4 string (e.g. ``'550e8400-e29b-41d4-a716-446655440000'``).
    """
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Canonical message construction
# ---------------------------------------------------------------------------


def _build_canonical_message(tx_data: dict[str, Any], nonce: str) -> bytes:
    """Build a deterministic byte representation of transaction + nonce.

    Security:
        - Keys are sorted to ensure identical JSON regardless of
          insertion order.
        - Separators are set to ``(',', ':')`` (no extra whitespace)
          for a compact, canonical form.
        - The nonce is injected under a reserved key ``__nonce__`` to
          prevent collision with transaction fields.

    Args:
        tx_data: Transaction data dictionary.
        nonce: The unique nonce string for this signing operation.

    Returns:
        UTF-8 encoded canonical JSON bytes.

    Raises:
        SignatureError: If the data cannot be serialised to JSON.
    """
    try:
        payload: dict[str, Any] = {**tx_data, "__nonce__": nonce}
        canonical_json: str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return canonical_json.encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SignatureError(
            f"Transaction data cannot be serialised to JSON: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Low-S normalisation
# ---------------------------------------------------------------------------


def _normalise_low_s(r_value: int, s_value: int) -> tuple[int, int]:
    """Normalise signature to low-S form to prevent malleability.

    If ``s > N/2``, replace ``s`` with ``N - s``. Both (r, s) and
    (r, N-s) are mathematically valid ECDSA signatures, but only
    the low-S form is accepted by this module.

    This follows the convention established by Bitcoin BIP-62 and
    adopted by Ethereum to prevent transaction malleability.

    Args:
        r_value: The r component of the ECDSA signature.
        s_value: The s component of the ECDSA signature.

    Returns:
        Tuple of (r, normalised_s) where normalised_s <= N/2.
    """
    if s_value > _SECP256K1_HALF_ORDER:
        s_value = _SECP256K1_ORDER - s_value
        logger.debug("Normalised high-S value to low-S form")
    return r_value, s_value


def _is_low_s(s_value: int) -> bool:
    """Check whether an S value is in low-S form.

    Args:
        s_value: The s component of the ECDSA signature.

    Returns:
        ``True`` if ``s <= N/2``.
    """
    return s_value <= _SECP256K1_HALF_ORDER


# ---------------------------------------------------------------------------
# Signature encoding (raw r||s, fixed-width big-endian)
# ---------------------------------------------------------------------------


def _encode_raw_signature(r_value: int, s_value: int) -> bytes:
    """Encode (r, s) as fixed-width big-endian bytes: r (32B) || s (32B).

    Args:
        r_value: The r component.
        s_value: The s component.

    Returns:
        64-byte signature.
    """
    return (
        r_value.to_bytes(_COMPONENT_SIZE, byteorder="big")
        + s_value.to_bytes(_COMPONENT_SIZE, byteorder="big")
    )


def _decode_raw_signature(signature: bytes) -> tuple[int, int]:
    """Decode a 64-byte raw signature into (r, s) integers.

    Args:
        signature: 64-byte raw signature.

    Returns:
        Tuple of (r, s) integers.

    Raises:
        VerificationError: If the signature length is invalid.
    """
    if len(signature) != _SIGNATURE_SIZE:
        raise VerificationError(
            f"Invalid signature length: expected {_SIGNATURE_SIZE} bytes, "
            f"got {len(signature)}"
        )
    r_value: int = int.from_bytes(signature[:_COMPONENT_SIZE], byteorder="big")
    s_value: int = int.from_bytes(signature[_COMPONENT_SIZE:], byteorder="big")
    return r_value, s_value


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def sign_transaction(
    tx_data: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    nonce: str,
) -> bytes:
    """Sign transaction data with an ECDSA private key.

    The transaction data and nonce are combined into a canonical JSON
    message, then signed with ECDSA-SHA256. The resulting signature
    is normalised to low-S form and returned as 64 raw bytes (r || s).

    Security:
        - Nonce is embedded in the signed message for replay protection.
        - Low-S normalisation prevents signature malleability.
        - Canonical JSON ensures deterministic message bytes.
        - The private key is never logged or returned in error messages.

    Args:
        tx_data: Transaction data dictionary (must be JSON-serialisable).
        private_key: The sender's ECDSA private key (secp256k1).
        nonce: A unique nonce string (use ``create_nonce()``).

    Returns:
        64-byte raw signature (r: 32 bytes || s: 32 bytes, big-endian).

    Raises:
        SignatureError: If signing fails or data cannot be serialised.
    """
    message: bytes = _build_canonical_message(tx_data, nonce)

    try:
        der_signature: bytes = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception as exc:
        raise SignatureError(f"Signing failed: {exc}") from exc

    # Decode DER → (r, s), then normalise to low-S
    r_value, s_value = decode_dss_signature(der_signature)
    r_value, s_value = _normalise_low_s(r_value, s_value)

    logger.debug("Transaction signed successfully")
    return _encode_raw_signature(r_value, s_value)


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_signature(
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
    tx_data: dict[str, Any],
    nonce: str,
) -> bool:
    """Verify an ECDSA signature against transaction data and nonce.

    Reconstructs the canonical message from ``tx_data`` + ``nonce``,
    then verifies the signature. Rejects signatures with high-S values
    (malleability check) before performing cryptographic verification.

    Security:
        - Rejects high-S signatures to prevent malleability attacks.
        - Nonce must match the value used during signing — this is the
          replay-protection gate. The caller should additionally check
          that the nonce has not been seen before.
        - Returns ``False`` on verification failure rather than raising,
          allowing callers to handle rejection gracefully.

    Args:
        signature: 64-byte raw signature (r || s).
        public_key: The signer's ECDSA public key.
        tx_data: The original transaction data dictionary.
        nonce: The nonce used when signing.

    Returns:
        ``True`` if the signature is valid and low-S, ``False`` otherwise.

    Raises:
        VerificationError: If the signature format is structurally invalid
            (wrong length) or if a high-S value is detected (malleability).
    """
    # Decode and check for malleability
    r_value, s_value = _decode_raw_signature(signature)

    if not _is_low_s(s_value):
        raise VerificationError(
            "Signature rejected: high-S value detected (malleability risk). "
            "Only low-S signatures are accepted."
        )

    # Rebuild the canonical message
    message: bytes = _build_canonical_message(tx_data, nonce)

    # Re-encode to DER for the cryptography library's verify()
    der_signature: bytes = encode_dss_signature(r_value, s_value)

    try:
        public_key.verify(
            der_signature,
            message,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        logger.warning("Signature verification failed")
        return False

    logger.debug("Signature verified successfully")
    return True
