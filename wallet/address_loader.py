"""
Address loader for the Wallet Identity Module.

Reads Ethereum transaction datasets and extracts unique, validated
wallet addresses for key pair assignment.

Security:
    - All addresses are validated against the Ethereum address format
      (0x + 40 hex chars) before acceptance.
    - Non-address labels (e.g. 'BinanceWallet') are filtered out
      and logged as warnings — they are NOT silently dropped.
    - Input validation prevents injection of malformed data into
      downstream cryptographic operations.
"""

import re
from pathlib import Path

import pandas as pd

from wallet.config import DATASET_PATH, configure_logging
from wallet.exceptions import DatasetLoadError, InvalidAddressError

logger = configure_logging(__name__)

# Compiled regex for Ethereum address validation (case-insensitive hex)
# Matches: 0x followed by exactly 40 hexadecimal characters
_ETH_ADDRESS_PATTERN: re.Pattern[str] = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Required columns in the transaction dataset
_REQUIRED_COLUMNS: frozenset[str] = frozenset({"From", "To"})


def validate_address(address: str) -> bool:
    """Check whether a string is a valid Ethereum address.

    A valid Ethereum address:
    - Starts with '0x'
    - Is followed by exactly 40 hexadecimal characters
    - Total length is 42 characters

    Security:
        Uses a pre-compiled regex pattern to avoid ReDoS and ensures
        consistent validation across the entire codebase. This function
        is the single validation gate — all other modules should call
        this rather than implementing their own checks.

    Args:
        address: The string to validate.

    Returns:
        ``True`` if the address matches the Ethereum format, ``False``
        otherwise.

    Raises:
        InvalidAddressError: If ``address`` is not a string.
    """
    if not isinstance(address, str):
        raise InvalidAddressError(
            f"Address must be a string, got {type(address).__name__}"
        )
    return bool(_ETH_ADDRESS_PATTERN.match(address))


def load_addresses(
    csv_path: Path | str | None = None,
) -> set[str]:
    """Load and validate unique wallet addresses from a transaction CSV.

    Reads the ``From`` and ``To`` columns, unions them, and filters to
    only valid Ethereum addresses (0x-prefixed, 40-char hex). Non-hex
    labels such as ``BinanceWallet`` are logged as warnings and excluded.

    Security:
        - Validates every address before inclusion.
        - Logs filtering statistics so anomalies are visible in audit logs.
        - Does NOT log actual address values at DEBUG level to avoid
          leaking wallet identities in production log aggregators.

    Rate-limit note (Phase 6):
        When this function is exposed via the Flask API, the endpoint
        should be rate-limited to prevent CSV re-parsing abuse.
        Recommended: 5 requests/minute per client IP.

    Args:
        csv_path: Path to the Ethereum transaction CSV file.
            Defaults to ``DATASET_PATH`` from config.

    Returns:
        A set of unique, validated Ethereum addresses (lowercased for
        consistent comparison).

    Raises:
        DatasetLoadError: If the file is not found, is empty,
            or is missing required columns.
    """
    resolved_path: Path = Path(csv_path) if csv_path else DATASET_PATH

    if not resolved_path.exists():
        raise DatasetLoadError(f"Dataset file not found: {resolved_path}")

    try:
        dataframe: pd.DataFrame = pd.read_csv(
            resolved_path,
            usecols=["From", "To"],
            dtype=str,
        )
    except ValueError as exc:
        raise DatasetLoadError(
            f"Dataset is missing required columns {_REQUIRED_COLUMNS}: {exc}"
        ) from exc
    except pd.errors.EmptyDataError as exc:
        raise DatasetLoadError(f"Dataset file is empty: {resolved_path}") from exc

    if dataframe.empty:
        raise DatasetLoadError(f"Dataset contains no rows: {resolved_path}")

    # Collect all raw address candidates from both columns
    from_addresses: pd.Series = dataframe["From"].dropna()
    to_addresses: pd.Series = dataframe["To"].dropna()
    raw_candidates: set[str] = set(from_addresses) | set(to_addresses)

    total_candidates: int = len(raw_candidates)
    logger.info("Found %d unique address candidates in dataset", total_candidates)

    # Validate and filter
    valid_addresses: set[str] = set()
    filtered_count: int = 0

    for candidate in raw_candidates:
        if validate_address(candidate):
            # Lowercase for consistent storage and comparison
            valid_addresses.add(candidate.lower())
        else:
            filtered_count += 1
            logger.warning("Filtered non-address label: '%s'", candidate)

    logger.info(
        "Address loading complete: %d valid, %d filtered out of %d total",
        len(valid_addresses),
        filtered_count,
        total_candidates,
    )

    return valid_addresses
