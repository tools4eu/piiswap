# piiswap

> **Status: In Development / Testing Phase**
>
> This tool is under active development and not yet production-ready. Core functionality works but edge cases, false positives, and format-specific quirks are still being ironed out. Use at your own discretion and always verify output before relying on it.
>
> Feedback, bug reports, feature requests, and contributions are very welcome! Please open an [issue](https://github.com/tools4eu/piiswap/issues) on GitHub.

Bidirectional PII anonymization pipeline for DFIR case data. Replaces personally identifiable information with consistent tokens so forensic data can be shared or analyzed by AI tools without exposing real identifiers. Tokens can be de-anonymized back to the original values after analysis.

## Features

- **Bidirectional**: anonymize PII → tokens, then de-anonymize tokens → PII
- **Cross-file consistency**: two-pass processing ensures the same person gets the same token across all files
- **Entity resolution**: `john.doe@company.com` and username `john.doe` are automatically linked to the same entity
- **Allowlist**: IPs, hashes, timestamps, MITRE ATT&CK IDs, and protocols are never anonymized
- **Encrypted mapping store**: Fernet-encrypted SQLite database keeps the PII↔token mappings safe at rest
- **Token format**: `ANONUSER001`, `ANONEMAIL003`, etc. — no special characters (safe for XML, SQL, JSON)

## Detected PII types

| Type | Examples |
|------|----------|
| Email | `john.doe@company.com` |
| Phone | `+32 471 12 34 56`, `0471/123456` |
| IBAN | `BE68 5390 0754 7034` |
| API key | `AKIA...`, `ghp_...`, `sk-...` |
| Credential | `password: s3cret!`, `token=abc123` |
| File path | `C:\Users\john\...`, `/home/john/...` (with username) |
| Hostname | `DESKTOP-ABC123`, `SRV-DC01` |
| Username | `john.doe`, `jdoe`, `admin01` |
| Name | First/last names from Belgian + international wordlists |
| Address | Belgian street addresses |

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd DocumentAnonymization

# Install (basic)
pip install -e .

# Install with dev tools (pytest)
pip install -e ".[dev]"

# Install with document format support (docx, pdf, yaml)
pip install -e ".[dev,formats]"

# Install with forensic format support (evtx, pcap)
pip install -e ".[dev,forensics]"

# Install everything
pip install -e ".[all,dev]"
```

## Quick start

Typical workflow in 4 steps:

```bash
# 1. Initialize the mapping database for your case
piiswap init CASE-042

# 2. Scan files to see what PII would be detected (dry-run)
piiswap scan ./evidence -r

# 3. Anonymize — creates a copy with PII replaced by tokens
piiswap anonymize ./evidence -r -o ./evidence_anon

# 4. After analysis, restore original values
piiswap deanonymize ./evidence_anon -r -o ./evidence_restored
```

## CLI commands

### `piiswap init [CASE-ID]`

Create the mapping database. If no CASE-ID is given, the current directory name is used.

```bash
piiswap init CASE-042
piiswap init CASE-042 -p "my-secret-password"   # encrypted database
```

The database is stored at `.piiswap/<case-id>.db`. Use `--password` or the `PIISWAP_KEY` environment variable for encryption.

### `piiswap scan <path> [-r]`

Dry-run: show all detected PII with context, without changing anything.

```bash
piiswap scan ./evidence                  # single file or directory
piiswap scan ./evidence -r               # recursive
piiswap scan ./evidence -r --strict      # only full name pairs (first + last)
piiswap scan ./evidence -r --exclude-types hostname,filepath_user
piiswap scan ./evidence -r --include-types email,phone
piiswap scan ./evidence -r --ioc-file known_iocs.txt
```

### `piiswap anonymize <path> [-r] [-o output]`

Replace PII with tokens. Creates a copy — original files are never modified.

```bash
piiswap anonymize ./evidence -r -o ./evidence_anon
piiswap anonymize report.txt -o report_anon.txt
piiswap anonymize ./evidence -r --dry-run        # same as scan
piiswap anonymize ./evidence -r --strict          # strict name matching
piiswap anonymize ./evidence -r --ioc-file iocs.txt            # protect IOCs
piiswap anonymize ./evidence -r --exclude-types hostname       # skip hostnames
piiswap anonymize data.csv --pii-columns "name,email,phone"   # column-aware
piiswap anonymize data.csv --keep-columns "ip,timestamp"       # keep these columns
```

Default output: `<input>_anon` (directory) or `<name>_anon.<ext>` (file).

### `piiswap deanonymize <path> [-r] [-o output]`

Restore tokens back to original PII values.

```bash
piiswap deanonymize ./evidence_anon -r -o ./evidence_restored
piiswap deanonymize report_anon.md -o report.md --only email,username  # selective
piiswap deanonymize data_anon.csv --pii-columns "name,email"           # column-aware
```

### `piiswap verify <original> <anonymized>`

Check that no PII from the original leaked into the anonymized output.

```bash
piiswap verify ./evidence ./evidence_anon
```

Returns exit code 1 if leaks are found.

### `piiswap status [-c CASE-ID]`

Show mapping statistics: total mappings, entities, processed files, allowlist entries.

### `piiswap mappings [-c CASE-ID]`

List all PII-to-token mappings in a table.

### `piiswap link <token1> <token2>`

Manually merge two entities. Useful when automatic entity resolution missed a connection.

```bash
piiswap link ANONUSER001 ANONEMAIL003    # merge ANONEMAIL003 into ANONUSER001's entity
```

### `piiswap allowlist`

Manage values that should never be anonymized.

```bash
piiswap allowlist add "example.com" --type domain --reason "Company domain"
piiswap allowlist add-domain evil-c2.com --reason "C2 IOC"   # protects domain + emails
piiswap allowlist import-file iocs.txt --type ioc            # bulk import
piiswap allowlist list
piiswap allowlist remove "example.com"
```

## Allowlist (built-in)

The following patterns are automatically protected from anonymization:

- **IP addresses** — IPv4 and IPv6 (forensic indicators)
- **Hashes** — MD5, SHA1, SHA256 (evidence integrity)
- **Timestamps** — ISO 8601, syslog, Windows event formats
- **Protocols** — HTTP, TCP, DNS, SMB, etc.
- **MITRE ATT&CK IDs** — T1059, TA0001, etc.

Additionally, **domain allowlisting** automatically protects emails on that domain:
```bash
piiswap allowlist add-domain evil-c2.com    # suspect@evil-c2.com will NOT be anonymized
```

Add custom entries with `piiswap allowlist add`, or bulk import with `piiswap allowlist import-file`.

## Encryption

The mapping database can be encrypted at rest using Fernet (AES-128-CBC):

```bash
# Option 1: password flag
piiswap init CASE-042 -p "strong-password"
piiswap anonymize ./evidence -r -p "strong-password"

# Option 2: environment variable (recommended)
export PIISWAP_KEY="strong-password"
piiswap init CASE-042
piiswap anonymize ./evidence -r
```

## File format support

| Format | Extensions | Status | Output | Install |
|--------|-----------|--------|--------|---------|
| Plain text | .txt, .log, .csv, .json, .xml, .html, .md, .yaml, .eml, .sql, .sh, .bat, .ps1, .py, .js, .conf, .cfg, .ini, .env, .properties | Supported | Same format | Core |
| Word | .docx | Supported | .docx (formatting preserved) | `.[formats]` |
| PDF | .pdf | Supported (read-only) | .txt | `.[formats]` |
| SQLite | .db, .sqlite, .sqlite3 | Supported | Anonymized .db copy | Core |
| Windows Event Log | .evtx | Supported (read-only) | .xml | `.[forensics]` |
| Network capture | .pcap, .pcapng, .cap | Supported (read-only) | .txt | `.[forensics]` |

**Read-only formats**: PDF, EVTX, and PCAP are binary formats that cannot be modified in-place. The anonymized output is written as plain text (.txt or .xml).

## Platform support

piiswap is cross-platform and runs on:

- **Windows 10/11** — fully tested, `pip install -e .` creates a `piiswap.exe` wrapper
- **Linux** — fully compatible
- **macOS** — expected to work (untested)

All path handling uses `pathlib.Path`, file I/O specifies UTF-8 encoding explicitly, and all dependencies ship with Windows wheels.

On Windows, set the encryption key via environment variable:
```powershell
$env:PIISWAP_KEY = "strong-password"
piiswap anonymize .\evidence -r
```

## Running tests

```bash
pytest                           # all tests
pytest tests/test_detectors/     # detector tests only
pytest -v                        # verbose output
```

## Project status

- **Phase 1** (complete): Core engine, 11 PII detectors, plaintext adapter, encrypted store, CLI
- **Phase 2** (complete): Format adapters (docx, pdf, xlsx, csv, sqlite, evtx, pcap), social media handle detection, allowlist ecosystem (domain-aware, bulk import, IOC file), type filtering, column-aware mode, selective de-anonymization
- **Phase 3** (planned): SpaCy NER and local LLM plugins for context-aware detection

## Staying up to date

piiswap is under active development. New detectors, provider templates, and bug fixes are added regularly. Pull the latest version:

```bash
cd /path/to/piiswap
git pull origin main
pip install -e ".[formats]"
```

Check the [CHANGELOG.md](CHANGELOG.md) for what's new.

## Contributing

This project is in active development. Contributions of any kind are welcome:

- **Bug reports** — found a false positive? PII that slipped through? [Open an issue](https://github.com/tools4eu/piiswap/issues/new?template=bug_report.md)
- **Feature requests** — need support for a specific file format or PII type? [Open an issue](https://github.com/tools4eu/piiswap/issues/new?template=feature_request.md)
- **Provider data samples** — if you work with data from specific providers (telecom, social media, cloud) and notice detection gaps, let us know
- **Pull requests** — code contributions are welcome, especially for new detectors and file format adapters

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
