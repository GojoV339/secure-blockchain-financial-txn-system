"""
Unit tests for wallet.address_loader.

Covers:
- Happy path: valid addresses loaded from CSV
- Filtering: non-hex labels like 'BinanceWallet' excluded
- Validation: address format checks (0x + 40 hex)
- Edge cases: empty CSV, missing columns, non-string input
- Error handling: DatasetLoadError for all failure modes
"""

from pathlib import Path

import pytest

from wallet.address_loader import load_addresses, validate_address
from wallet.exceptions import DatasetLoadError, InvalidAddressError


class TestValidateAddress:
    """Tests for the ``validate_address`` function."""

    def test_valid_lowercase_address(self) -> None:
        """Standard lowercase 0x-prefixed address passes validation."""
        assert validate_address("0xdd487c027448d3364355707d91eefadc2dae9f88") is True

    def test_valid_mixed_case_address(self) -> None:
        """Mixed-case (EIP-55 checksum) address passes validation."""
        assert validate_address("0xDd487C027448D3364355707d91EeFadC2DaE9F88") is True

    def test_valid_uppercase_address(self) -> None:
        """All-uppercase hex address passes validation."""
        assert validate_address("0xDD487C027448D3364355707D91EEFADC2DAE9F88") is True

    def test_missing_0x_prefix(self) -> None:
        """Address without 0x prefix is rejected."""
        assert validate_address("dd487c027448d3364355707d91eefadc2dae9f88") is False

    def test_too_short(self) -> None:
        """Address with fewer than 40 hex chars is rejected."""
        assert validate_address("0xdd487c027448d3364355707d91eefadc") is False

    def test_too_long(self) -> None:
        """Address with more than 40 hex chars is rejected."""
        assert validate_address("0xdd487c027448d3364355707d91eefadc2dae9f88ff") is False

    def test_non_hex_characters(self) -> None:
        """Address containing non-hex characters is rejected."""
        assert validate_address("0xgg487c027448d3364355707d91eefadc2dae9f88") is False

    def test_named_label_rejected(self) -> None:
        """Labels like 'BinanceWallet' are not valid addresses."""
        assert validate_address("BinanceWallet") is False

    def test_empty_string(self) -> None:
        """Empty string is not a valid address."""
        assert validate_address("") is False

    def test_non_string_raises_error(self) -> None:
        """Non-string input raises InvalidAddressError."""
        with pytest.raises(InvalidAddressError, match="must be a string"):
            validate_address(12345)  # type: ignore[arg-type]

    def test_none_raises_error(self) -> None:
        """None input raises InvalidAddressError."""
        with pytest.raises(InvalidAddressError, match="must be a string"):
            validate_address(None)  # type: ignore[arg-type]


class TestLoadAddresses:
    """Tests for the ``load_addresses`` function."""

    def test_load_valid_addresses(self, sample_csv: Path) -> None:
        """Valid hex addresses from both From and To columns are loaded."""
        addresses: set[str] = load_addresses(sample_csv)
        # 3 valid hex addresses: 2 From + 1 valid To (BinanceWallet filtered)
        assert len(addresses) == 3
        assert "0xdd487c027448d3364355707d91eefadc2dae9f88" in addresses
        assert "0x3e1b1fe45cb2040b97cdb3191d4933ad1ff0928d" in addresses
        assert "0xb66a63e5ba7a888450af2ede7a47fd99777b647a" in addresses

    def test_binance_wallet_filtered(self, sample_csv: Path) -> None:
        """Non-address labels like 'BinanceWallet' are excluded."""
        addresses: set[str] = load_addresses(sample_csv)
        assert "BinanceWallet" not in addresses
        assert "binancewallet" not in addresses

    def test_addresses_lowercased(self, sample_csv: Path) -> None:
        """All returned addresses are lowercased for consistency."""
        addresses: set[str] = load_addresses(sample_csv)
        for addr in addresses:
            assert addr == addr.lower()

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Missing CSV file raises DatasetLoadError."""
        with pytest.raises(DatasetLoadError, match="not found"):
            load_addresses(tmp_path / "nonexistent.csv")

    def test_empty_csv_raises_error(self, empty_csv: Path) -> None:
        """CSV with headers but no data rows raises DatasetLoadError."""
        with pytest.raises(DatasetLoadError, match="no rows"):
            load_addresses(empty_csv)

    def test_missing_columns_raises_error(self, missing_columns_csv: Path) -> None:
        """CSV missing 'From' or 'To' columns raises DatasetLoadError."""
        with pytest.raises(DatasetLoadError, match="missing required columns"):
            load_addresses(missing_columns_csv)

    def test_returns_set_type(self, sample_csv: Path) -> None:
        """Return type is a set (no duplicates possible)."""
        addresses = load_addresses(sample_csv)
        assert isinstance(addresses, set)
