"""
Unit tests for wallet.signer.

Covers:
- Sign + verify round-trip (happy path)
- Tampered transaction data fails verification
- Different nonce fails verification (replay protection)
- Wrong public key fails verification
- High-S signature rejection (malleability protection)
- Nonce uniqueness
- Invalid signature length handling
- Non-serialisable data handling
"""

from typing import Any

import pytest


from wallet.exceptions import SignatureError, VerificationError
from wallet.key_manager import generate_key_pair
from wallet.signer import (
    _SECP256K1_HALF_ORDER,
    _SECP256K1_ORDER,
    _build_canonical_message,
    _decode_raw_signature,
    _encode_raw_signature,
    _normalise_low_s,
    create_nonce,
    sign_transaction,
    verify_signature,
)


class TestCreateNonce:
    """Tests for ``create_nonce``."""

    def test_returns_string(self) -> None:
        """Nonce is returned as a string."""
        nonce: str = create_nonce()
        assert isinstance(nonce, str)

    def test_nonces_are_unique(self) -> None:
        """Two consecutive nonces are never the same."""
        nonce_1: str = create_nonce()
        nonce_2: str = create_nonce()
        assert nonce_1 != nonce_2

    def test_nonce_is_uuid4_format(self) -> None:
        """Nonce matches UUID4 format (8-4-4-4-12 hex groups)."""
        nonce: str = create_nonce()
        parts: list[str] = nonce.split("-")
        assert len(parts) == 5
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12]


class TestCanonicalMessage:
    """Tests for ``_build_canonical_message``."""

    def test_deterministic_output(self) -> None:
        """Same data + nonce always produces identical bytes."""
        data: dict[str, str] = {"to": "0xabc", "from": "0xdef"}
        nonce: str = "fixed-nonce"
        assert _build_canonical_message(data, nonce) == _build_canonical_message(
            data, nonce
        )

    def test_key_order_does_not_matter(self) -> None:
        """Different insertion order produces the same canonical bytes."""
        data_a: dict[str, str] = {"from": "0xdef", "to": "0xabc"}
        data_b: dict[str, str] = {"to": "0xabc", "from": "0xdef"}
        nonce: str = "fixed-nonce"
        assert _build_canonical_message(data_a, nonce) == _build_canonical_message(
            data_b, nonce
        )

    def test_nonce_embedded_in_message(self) -> None:
        """Nonce appears in the canonical message bytes."""
        data: dict[str, str] = {"key": "value"}
        nonce: str = "unique-nonce-123"
        message: bytes = _build_canonical_message(data, nonce)
        assert b"unique-nonce-123" in message

    def test_non_serialisable_raises_error(self) -> None:
        """Data that cannot be JSON-serialised raises SignatureError."""
        with pytest.raises(SignatureError, match="cannot be serialised"):
            _build_canonical_message({"key": object()}, "nonce")


class TestLowSNormalisation:
    """Tests for low-S normalisation helpers."""

    def test_low_s_unchanged(self) -> None:
        """A value already <= N/2 is not modified."""
        r_val: int = 12345
        s_val: int = _SECP256K1_HALF_ORDER - 1
        r_out, s_out = _normalise_low_s(r_val, s_val)
        assert r_out == r_val
        assert s_out == s_val

    def test_high_s_normalised(self) -> None:
        """A value > N/2 is replaced with N - s."""
        r_val: int = 12345
        s_val: int = _SECP256K1_HALF_ORDER + 1
        r_out, s_out = _normalise_low_s(r_val, s_val)
        assert r_out == r_val
        assert s_out == _SECP256K1_ORDER - s_val
        assert s_out <= _SECP256K1_HALF_ORDER

    def test_boundary_value(self) -> None:
        """S exactly at N/2 is considered low-S and unchanged."""
        r_val: int = 12345
        s_val: int = _SECP256K1_HALF_ORDER
        _, s_out = _normalise_low_s(r_val, s_val)
        assert s_out == s_val


class TestRawSignatureEncoding:
    """Tests for raw r||s encoding/decoding."""

    def test_round_trip(self) -> None:
        """Encode → decode produces the original (r, s) values."""
        r_val: int = 2**255 - 19
        s_val: int = 2**254 + 7
        encoded: bytes = _encode_raw_signature(r_val, s_val)
        assert len(encoded) == 64
        r_decoded, s_decoded = _decode_raw_signature(encoded)
        assert r_decoded == r_val
        assert s_decoded == s_val

    def test_wrong_length_raises_error(self) -> None:
        """Signature with wrong byte length raises VerificationError."""
        with pytest.raises(VerificationError, match="Invalid signature length"):
            _decode_raw_signature(b"\x00" * 63)

        with pytest.raises(VerificationError, match="Invalid signature length"):
            _decode_raw_signature(b"\x00" * 65)


class TestSignTransaction:
    """Tests for ``sign_transaction``."""

    def test_returns_64_bytes(self, sample_tx_data: dict[str, str]) -> None:
        """Signature is exactly 64 bytes (32B r + 32B s)."""
        private_key, _ = generate_key_pair()
        nonce: str = create_nonce()
        sig: bytes = sign_transaction(sample_tx_data, private_key, nonce)
        assert len(sig) == 64

    def test_signature_is_low_s(self, sample_tx_data: dict[str, str]) -> None:
        """Returned signature always has s <= N/2."""
        private_key, _ = generate_key_pair()
        # Sign multiple times — some may naturally produce high-S
        for _ in range(20):
            nonce: str = create_nonce()
            sig: bytes = sign_transaction(sample_tx_data, private_key, nonce)
            _, s_val = _decode_raw_signature(sig)
            assert s_val <= _SECP256K1_HALF_ORDER


class TestVerifySignature:
    """Tests for ``verify_signature`` — the core security tests."""

    def test_valid_signature_accepted(self, sample_tx_data: dict[str, str]) -> None:
        """Sign → verify round-trip succeeds with correct key and nonce."""
        private_key, public_key = generate_key_pair()
        nonce: str = create_nonce()
        sig: bytes = sign_transaction(sample_tx_data, private_key, nonce)
        assert verify_signature(sig, public_key, sample_tx_data, nonce) is True

    def test_tampered_data_rejected(self, sample_tx_data: dict[str, str]) -> None:
        """Modifying transaction data after signing fails verification."""
        private_key, public_key = generate_key_pair()
        nonce: str = create_nonce()
        sig: bytes = sign_transaction(sample_tx_data, private_key, nonce)

        # Tamper: change the value
        tampered: dict[str, Any] = {**sample_tx_data, "value": "999.0"}
        assert verify_signature(sig, public_key, tampered, nonce) is False

    def test_different_nonce_rejected(self, sample_tx_data: dict[str, str]) -> None:
        """Using a different nonce during verification fails (replay protection)."""
        private_key, public_key = generate_key_pair()
        nonce_sign: str = create_nonce()
        nonce_verify: str = create_nonce()  # Different nonce
        sig: bytes = sign_transaction(sample_tx_data, private_key, nonce_sign)
        assert verify_signature(sig, public_key, sample_tx_data, nonce_verify) is False

    def test_wrong_public_key_rejected(self, sample_tx_data: dict[str, str]) -> None:
        """Signature verified against a different public key fails."""
        private_key_1, _ = generate_key_pair()
        _, public_key_2 = generate_key_pair()  # Different key pair
        nonce: str = create_nonce()
        sig: bytes = sign_transaction(sample_tx_data, private_key_1, nonce)
        assert verify_signature(sig, public_key_2, sample_tx_data, nonce) is False

    def test_high_s_signature_rejected(self, sample_tx_data: dict[str, str]) -> None:
        """A forged high-S signature is rejected with VerificationError."""
        private_key, public_key = generate_key_pair()
        nonce: str = create_nonce()
        sig: bytes = sign_transaction(sample_tx_data, private_key, nonce)

        # Manually flip s to high-S
        r_val, s_val = _decode_raw_signature(sig)
        high_s: int = _SECP256K1_ORDER - s_val  # guaranteed > N/2 since s <= N/2
        forged_sig: bytes = _encode_raw_signature(r_val, high_s)

        with pytest.raises(VerificationError, match="high-S value"):
            verify_signature(forged_sig, public_key, sample_tx_data, nonce)

    def test_invalid_signature_length(self, sample_tx_data: dict[str, str]) -> None:
        """Signature with wrong byte count raises VerificationError."""
        _, public_key = generate_key_pair()
        nonce: str = create_nonce()
        with pytest.raises(VerificationError, match="Invalid signature length"):
            verify_signature(b"\x00" * 32, public_key, sample_tx_data, nonce)

    def test_empty_tx_data(self) -> None:
        """Empty transaction data can still be signed and verified."""
        private_key, public_key = generate_key_pair()
        nonce: str = create_nonce()
        sig: bytes = sign_transaction({}, private_key, nonce)
        assert verify_signature(sig, public_key, {}, nonce) is True

    def test_added_field_rejected(self, sample_tx_data: dict[str, str]) -> None:
        """Adding an extra field to tx_data after signing fails verification."""
        private_key, public_key = generate_key_pair()
        nonce: str = create_nonce()
        sig: bytes = sign_transaction(sample_tx_data, private_key, nonce)

        modified: dict[str, Any] = {**sample_tx_data, "extra": "injected"}
        assert verify_signature(sig, public_key, modified, nonce) is False
