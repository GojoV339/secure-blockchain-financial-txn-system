"""
Configuration module for the Wallet Identity system.

Loads all configuration from environment variables (sourced from .env).
This is the single source of truth for paths, encryption settings,
and logging configuration. No secrets are hardcoded.

Security:
    - Encryption passphrase is read from environment at runtime only.
    - If the passphrase env var is missing, a KeyError will propagate
      immediately — fail-fast prevents silent insecure operation.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env file from project root (two levels up from this file)
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

# ---------------------------------------------------------------------------
# Dataset configuration
# ---------------------------------------------------------------------------
DATASET_PATH: Path = _PROJECT_ROOT / os.getenv("DATASET_PATH", "datasets/Eth_Txs.csv")

# ---------------------------------------------------------------------------
# Keystore configuration
# ---------------------------------------------------------------------------
KEYSTORE_PATH: Path = _PROJECT_ROOT / os.getenv("KEYSTORE_PATH", "keystore")

# ---------------------------------------------------------------------------
# Encryption passphrase — loaded on demand, never cached in a global
# ---------------------------------------------------------------------------


def get_encryption_passphrase() -> str:
    """Return the wallet encryption passphrase from the environment.

    Security:
        The passphrase is read each time this function is called so it is
        never stored as a module-level string that could leak via inspection.
        If the env var is unset, a ``KeyError`` is raised immediately to
        prevent silent fallback to an empty or default passphrase.

    Returns:
        The encryption passphrase string.

    Raises:
        KeyError: If ``WALLET_ENCRYPTION_PASSPHRASE`` is not set.
    """
    passphrase: str | None = os.getenv("WALLET_ENCRYPTION_PASSPHRASE")
    if passphrase is None:
        raise KeyError(
            "WALLET_ENCRYPTION_PASSPHRASE environment variable is not set. "
            "Create a .env file or export the variable before running."
        )
    return passphrase


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


def configure_logging(name: str = "wallet") -> logging.Logger:
    """Create and return a configured logger for the wallet module.

    Uses the ``LOG_LEVEL`` environment variable. Outputs structured
    log lines with timestamp, module, level, and message.

    Args:
        name: Logger name, typically the module's ``__name__``.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    logger: logging.Logger = logging.getLogger(name)

    if not logger.handlers:
        handler: logging.StreamHandler = logging.StreamHandler()
        formatter: logging.Formatter = logging.Formatter(
            fmt="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    return logger
