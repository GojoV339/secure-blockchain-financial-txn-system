"""
Unit tests for wallet.key_manager.

Covers:
- Key pair generation on secp256k1
- Serialisation round-trips (private encrypted, public unencrypted)
- Persisted key file save and load
- Wrong passphrase rejection
- Missing key file handling
- Batch generation with skip-existing behaviour
- File permission checks on private keys
"""

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from wallet.exceptions import KeyStorageError
from wallet.key_manager import (
    generate_key_pair,
    generate_keys_for_addresses,
    load_private_key,
    load_public_key,
    save_keys,
    serialize_private_key,
    serialize_public_key,
)


class TestGenerateKeyPair:
    """Tests for ``generate_key_pair``."""

    def test_returns_private_and_public_key(self) -> None:
        """Key pair generation returns both private and public keys."""
        private_key, public_key = generate_key_pair()
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

    def test_uses_secp256k1_curve(self) -> None:
        """Generated keys use the secp256k1 curve (Ethereum standard)."""
        private_key, _ = generate_key_pair()
        assert isinstance(private_key.curve, ec.SECP256K1)

    def test_unique_keys_each_call(self) -> None:
        """Each call generates a distinct key pair."""
        pk1 = serialize_public_key(generate_key_pair()[1])
        pk2 = serialize_public_key(generate_key_pair()[1])
        assert pk1 != pk2


class TestSerialisation:
    """Tests for key serialisation helpers."""

    def test_private_key_is_encrypted(self, test_passphrase: str) -> None:
        """Serialised private key PEM is encrypted (contains ENCRYPTED)."""
        private_key, _ = generate_key_pair()
        pem_bytes: bytes = serialize_private_key(private_key, test_passphrase)
        assert b"ENCRYPTED" in pem_bytes

    def test_public_key_is_pem(self) -> None:
        """Serialised public key is valid PEM format."""
        _, public_key = generate_key_pair()
        pem_bytes: bytes = serialize_public_key(public_key)
        assert pem_bytes.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert b"-----END PUBLIC KEY-----" in pem_bytes


class TestSaveAndLoadKeys:
    """Tests for key persistence (save + load round-trip)."""

    def test_save_and_load_private_key(
        self, tmp_keystore: Path, test_passphrase: str
    ) -> None:
        """Private key survives save → load round-trip."""
        address: str = "0xdd487c027448d3364355707d91eefadc2dae9f88"
        private_key, public_key = generate_key_pair()

        save_keys(address, private_key, public_key, test_passphrase, tmp_keystore)
        loaded: ec.EllipticCurvePrivateKey = load_private_key(
            address, test_passphrase, tmp_keystore
        )

        # Cannot directly compare encrypted PEM (different salt each time)
        # Instead verify loaded key can derive the same public key
        assert serialize_public_key(loaded.public_key()) == serialize_public_key(
            public_key
        )

    def test_save_and_load_public_key(
        self, tmp_keystore: Path, test_passphrase: str
    ) -> None:
        """Public key survives save → load round-trip."""
        address: str = "0x3e1b1fe45cb2040b97cdb3191d4933ad1ff0928d"
        private_key, public_key = generate_key_pair()

        save_keys(address, private_key, public_key, test_passphrase, tmp_keystore)
        loaded: ec.EllipticCurvePublicKey = load_public_key(address, tmp_keystore)

        assert serialize_public_key(loaded) == serialize_public_key(public_key)

    def test_wrong_passphrase_fails(
        self, tmp_keystore: Path, test_passphrase: str
    ) -> None:
        """Loading a private key with the wrong passphrase raises error."""
        address: str = "0xdd487c027448d3364355707d91eefadc2dae9f88"
        private_key, public_key = generate_key_pair()

        save_keys(address, private_key, public_key, test_passphrase, tmp_keystore)

        with pytest.raises(KeyStorageError, match="wrong passphrase"):
            load_private_key(address, "wrong-passphrase", tmp_keystore)

    def test_missing_private_key_file(self, tmp_keystore: Path) -> None:
        """Loading a non-existent private key raises KeyStorageError."""
        with pytest.raises(KeyStorageError, match="not found"):
            load_private_key(
                "0x0000000000000000000000000000000000000000",
                "any-passphrase",
                tmp_keystore,
            )

    def test_missing_public_key_file(self, tmp_keystore: Path) -> None:
        """Loading a non-existent public key raises KeyStorageError."""
        with pytest.raises(KeyStorageError, match="not found"):
            load_public_key(
                "0x0000000000000000000000000000000000000000",
                tmp_keystore,
            )

    def test_private_key_file_permissions(
        self, tmp_keystore: Path, test_passphrase: str
    ) -> None:
        """Private key file is written with owner-only permissions (0600)."""
        address: str = "0xdd487c027448d3364355707d91eefadc2dae9f88"
        private_key, public_key = generate_key_pair()

        save_keys(address, private_key, public_key, test_passphrase, tmp_keystore)

        private_path: Path = (
            tmp_keystore / f"{address.lower().removeprefix('0x')}_private.pem"
        )
        file_mode: int = stat.S_IMODE(os.stat(private_path).st_mode)
        assert file_mode == 0o600, f"Expected 0600, got {oct(file_mode)}"

    def test_keystore_directory_created(
        self, tmp_path: Path, test_passphrase: str
    ) -> None:
        """Keystore directory is created automatically if missing."""
        new_dir: Path = tmp_path / "new_keystore"
        address: str = "0xdd487c027448d3364355707d91eefadc2dae9f88"
        private_key, public_key = generate_key_pair()

        save_keys(address, private_key, public_key, test_passphrase, new_dir)

        assert new_dir.exists()
        assert new_dir.is_dir()


class TestBatchGeneration:
    """Tests for ``generate_keys_for_addresses``."""

    def test_generates_for_all_addresses(
        self,
        tmp_keystore: Path,
        sample_addresses: list[str],
        test_passphrase: str,
    ) -> None:
        """Keys are generated for every address in the input set."""
        count: int = generate_keys_for_addresses(
            set(sample_addresses), test_passphrase, tmp_keystore
        )
        assert count == len(sample_addresses)

        # Verify each address has files
        for address in sample_addresses:
            loaded: ec.EllipticCurvePublicKey = load_public_key(address, tmp_keystore)
            assert isinstance(loaded, ec.EllipticCurvePublicKey)

    def test_skips_existing_addresses(
        self,
        tmp_keystore: Path,
        sample_addresses: list[str],
        test_passphrase: str,
    ) -> None:
        """Second run with same addresses generates zero new keys."""
        generate_keys_for_addresses(
            set(sample_addresses), test_passphrase, tmp_keystore
        )
        second_count: int = generate_keys_for_addresses(
            set(sample_addresses), test_passphrase, tmp_keystore
        )
        assert second_count == 0

    def test_empty_address_set(self, tmp_keystore: Path, test_passphrase: str) -> None:
        """Empty address set generates zero keys without error."""
        count: int = generate_keys_for_addresses(set(), test_passphrase, tmp_keystore)
        assert count == 0
