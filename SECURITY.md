# Security Policy

## Key Storage Design

### Encryption at Rest

All private keys are stored encrypted using **AES-256-CBC** with a passphrase-derived key (PBKDF2-HMAC), implemented via the `cryptography` library's `BestAvailableEncryption`. The encryption passphrase is sourced exclusively from the `WALLET_ENCRYPTION_PASSPHRASE` environment variable — it is never hardcoded, logged, or committed to version control.

**Key file format:**
- Private keys: PEM-encoded, PKCS8 format, encrypted (`*_private.pem`)
- Public keys: PEM-encoded, SubjectPublicKeyInfo format, unencrypted (`*_public.pem`)

### File System Protections

Private key files are written with POSIX permission mode `0o600` (owner read/write only). This prevents other users on the same system from reading the key material.

### Passphrase Management

- The passphrase is loaded on-demand via `wallet.config.get_encryption_passphrase()` — it is never cached as a module-level variable.
- If the environment variable is missing, the application fails immediately (`KeyError`) rather than falling back to a default passphrase.
- The `.env` file containing the passphrase is listed in `.gitignore` to prevent accidental commits.

---

## Digital Signature Security

### Replay Protection

Every signed message includes a cryptographically random nonce (UUID4 backed by `os.urandom()`). The nonce is embedded in the canonical JSON payload before signing, making the signature dependent on that specific nonce value.

**Caller responsibilities:**
- Generate a unique nonce via `wallet.signer.create_nonce()` for each transaction.
- Track used nonces (in a database or in-memory set) to reject duplicates.
- The Phase 6 API layer will implement nonce tracking.

### Signature Malleability Protection

ECDSA signatures have an inherent malleability property: for any valid signature `(r, s)`, the pair `(r, N - s)` is also valid where `N` is the curve order. This module enforces **low-S normalisation**:

- **On signing:** If `s > N/2`, replace `s` with `N - s` before returning.
- **On verification:** Reject any signature where `s > N/2` with a `VerificationError`.

This follows the same convention used by Bitcoin (BIP-62) and Ethereum to prevent transaction malleability.

### Signature Format

Signatures use a fixed-width raw encoding (`r || s`, 32 bytes each = 64 bytes total) in big-endian byte order, rather than DER encoding. This eliminates DER encoding ambiguity and makes malleability checks straightforward.

### Canonical Serialisation

Transaction data is serialised to JSON with:
- Sorted keys (`sort_keys=True`)
- Compact separators (`(',', ':')`)

This guarantees deterministic byte sequences regardless of dictionary insertion order, preventing formatting-based signature bypass attacks.

---

## Input Validation

All wallet addresses are validated against the Ethereum address format (`0x` + 40 hex characters) via `wallet.address_loader.validate_address()` before any cryptographic operations. Non-address labels (e.g., `BinanceWallet`) are filtered and logged as warnings.

---

## Secrets Management

| Secret | Storage | Access Method |
|---|---|---|
| Encryption passphrase | `.env` file (gitignored) | `os.getenv()` via `config.get_encryption_passphrase()` |
| Private keys | `keystore/*.pem` (gitignored, encrypted) | `key_manager.load_private_key()` |

**No secrets appear in:**
- Source code
- Log output (private key values are never logged)
- Git history (`.env`, `keystore/`, `*.pem` are all in `.gitignore`)

---

## CI/CD Security Checks

The GitHub Actions pipeline runs on every push and PR to `main`:

1. **Ruff** — Linting and style enforcement
2. **Bandit** — Static analysis for common Python security vulnerabilities
3. **pip-audit** — Dependency CVE scanning
4. **pytest** — Test suite with 80% minimum coverage gate

All four checks must pass before a merge is allowed.

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please open a private issue or contact the repository owner directly. Do not disclose vulnerabilities in public issues.
