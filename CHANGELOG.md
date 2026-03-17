# Changelog

All notable changes to piiswap will be documented in this file.

## [0.2.0] - 2026-03-17

### Added
- **Provider templates**: `--template microsoft-signin`, `--template isp-connection`, etc. Auto-configures column-aware anonymization for known provider data formats
- **`piiswap templates`** command: lists all available templates
- **`piiswap new`** command: creates case directory with standard structure
- **Column-aware CSV/Excel**: `--pii-columns` and `--keep-columns` for targeted anonymization
- **Type filtering**: `--include-types` / `--exclude-types` to select specific PII types
- **Selective de-anonymization**: `deanonymize --only email,username`
- **Domain-aware allowlisting**: `allowlist add-domain` protects emails on a domain
- **IOC file import**: `--ioc-file` and `allowlist import-file` for bulk allowlist management
- **Social media handle detector**: @handles, u/handles, profile URLs (9 platforms)
- **Field label detector**: JSON/key-value field names as PII indicators
- **Guided CLI hints**: contextual next-step suggestions after every command
- **File format adapters**: docx, pdf, xlsx, csv, sqlite, evtx, pcap
- Profile URL username replacement fix

### Fixed
- flashtext word boundaries now handle `/` and `\` correctly for URL usernames

## [0.1.0] - 2026-03-16

### Added
- Core anonymization engine with two-pass directory processing
- 10 PII detectors: email, phone, IBAN, API key, credential, file path, hostname, username, name, address
- Entity resolution (email <-> username <-> name linking)
- Encrypted SQLite mapping store (Fernet)
- PlainText adapter for .txt, .log, .json, .xml, .md, etc.
- CLI: init, scan, anonymize, deanonymize, verify, status, mappings, allowlist, link
- Built-in allowlist: IPs, hashes, timestamps, protocols, MITRE ATT&CK IDs
