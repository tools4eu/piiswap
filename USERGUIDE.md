# piiswap User Guide

Practical guide for using piiswap in DFIR investigations.

---

## Table of Contents

1. [What does piiswap do?](#1-what-does-piiswap-do)
2. [Installation](#2-installation)
3. [Setting up a case](#3-setting-up-a-case)
4. [Workflow: step by step](#4-workflow-step-by-step)
5. [Working with Cloud LLMs](#5-working-with-cloud-llms)
6. [Closing a case and starting a new one](#6-closing-a-case-and-starting-a-new-one)
7. [Multiple cases simultaneously](#7-multiple-cases-simultaneously)
8. [Supported file formats](#8-supported-file-formats)
9. [What is and is not anonymized?](#9-what-is-and-is-not-anonymized)
10. [Tips and frequently asked questions](#10-tips-and-frequently-asked-questions)

---

## 1. What does piiswap do?

piiswap replaces personally identifiable information (PII) in forensic files with anonymous tokens:

```
jan.janssens@company.be  →  ANONEMAIL001
+32 471 12 34 56         →  ANONPHONE001
SuperGeheim123!          →  ANONPASS003
```

This makes it possible to:
- Safely share evidence with external parties or cloud LLMs
- Perform AI analysis without exposing real PII
- Translate the tokens back to the original values after analysis

The replacement is **bidirectional** (anonymize and de-anonymize) and **consistent** (the same person always gets the same token, even across multiple files).

---

## 2. Installation

### Requirements
- Python 3.9 or higher
- pip

### Basic installation

```bash
# Clone or copy the project
cd /path/to/piiswap

# Install the basics (text, csv, json, log, etc.)
pip install -e .

# With document support (Word, PDF, Excel)
pip install -e ".[formats]"

# With forensic formats (EVTX, PCAP)
pip install -e ".[forensics]"

# Install everything
pip install -e ".[all]"
```

### Verify it works

```bash
piiswap --version
piiswap --help
```

### Windows-specific

On Windows everything works identically. The installation automatically creates a `piiswap.exe`. For the encryption key via environment variable:

```powershell
$env:PIISWAP_KEY = "my-password"
```

---

## 3. Setting up a case

### Option A: Quick setup with `piiswap new` (recommended)

Create a complete case directory with standard structure in one command:

```bash
piiswap new CASE-2026-042
```

This creates:

```
CASE-2026-042/
├── evidence/           # Drop your files here (DO NOT MODIFY originals)
├── evidence_anon/      # Anonymized output (auto-generated)
├── iocs/               # IOC files for allowlist import
├── llm_output/         # Save LLM analysis results here
├── restored/           # De-anonymized reports (auto-generated)
├── .piiswap/           # Mapping database
└── README.md           # Quick start guide
```

With encryption:

```bash
piiswap new CASE-2026-042 -p "strong-password"
```

### Option B: Manual setup with `piiswap init`

If you already have a case directory:

```bash
cd CASE-2026-042
piiswap init
```

This creates a database in `.piiswap/CASE-2026-042.db`. The case ID is automatically derived from the directory name.

You can also specify a custom case ID:

```bash
piiswap init MyCase
```

> **Important**: The original files are NEVER modified. piiswap always creates a copy.

### With encryption (recommended)

The mapping database contains the link between real PII and tokens. Protect it:

```bash
piiswap init -p "strong-password"
```

Or via environment variable (so you don't need to pass `-p` every time):

```bash
# Linux/Mac
export PIISWAP_KEY="strong-password"

# Windows PowerShell
$env:PIISWAP_KEY = "strong-password"

# Then simply:
piiswap init
```

---

## 4. Workflow: step by step

### Overview

```
┌─────────┐     ┌───────────┐     ┌─────────────┐     ┌──────────────┐
│ Evidence │────>│  Scan     │────>│ Anonymize   │────>│ Anonymized   │
│ (orig.)  │     │ (dry-run) │     │             │     │ files        │
└─────────┘     └───────────┘     └─────────────┘     └──────┬───────┘
                                                              │
                                                    (share with LLM/external)
                                                              │
                                                     ┌────────▼────────┐
                                                     │  LLM Result     │
                                                     │  (with tokens)  │
                                                     └────────┬────────┘
                                                              │
                                                     ┌────────▼────────┐
                                                     │  De-anonymize   │
                                                     │                 │
                                                     └────────┬────────┘
                                                              │
                                                     ┌────────▼────────┐
                                                     │  Final report   │
                                                     │  (real PII)     │
                                                     └─────────────────┘
```

### Step 1: Scan (dry-run)

First review what gets detected, without changing anything:

```bash
piiswap scan evidence/ -r
```

Advanced scan options:

```bash
piiswap scan evidence/ -r --strict                     # only full name pairs
piiswap scan evidence/ -r --include-types email,phone  # only specific types
piiswap scan evidence/ -r --exclude-types hostname     # skip specific types
piiswap scan evidence/ -r --ioc-file known_iocs.txt    # protect IOCs
piiswap scan data.csv --template microsoft-signin      # use provider template
```

The output shows per file which PII was found:

```
evidence/auth.log:
  [username      ] 'jan.janssens' (conf=0.85)
                   ...publickey for jan.janssens from 192...
  [email         ] 'jan.janssens@company.be' (conf=0.95)
                   ...Contact email: jan.janssens@company.be...

Total: 42 PII matches in 8 files
```

### Step 2: Adjust the allowlist (optional)

If the scan detects something you do NOT want to anonymize:

```bash
# Protect a domain + all its emails + subdomains
piiswap allowlist add-domain company.be --reason "Own organization"

# Protect a single value
piiswap allowlist add "admin_backup" --type alias --reason "Generic service account"

# Bulk import IOCs from a file (one per line, or CSV)
piiswap allowlist import-file iocs/known_iocs.txt --type ioc

# Import from a specific CSV column
piiswap allowlist import-file data.csv --type domain --column 2
```

View the current allowlist:

```bash
piiswap allowlist list
```

Remove an entry:

```bash
piiswap allowlist remove "admin_backup"
```

### Step 3: Anonymize

```bash
piiswap anonymize evidence/ -r -o evidence_anon/
```

#### Provider templates

For provider data (CSV/Excel), use a template for automatic column configuration:

```bash
piiswap templates                                          # list available templates
piiswap anonymize data.csv --template microsoft-signin     # Microsoft 365 sign-in logs
piiswap anonymize data.csv --template telegram-user        # Telegram user data
piiswap anonymize data.csv --template isp-connection       # ISP connection logs
```

Templates use **blind mode**: every value in a PII column is anonymized, even if no detector recognizes it. This ensures provider-specific usernames and display names are always caught.

#### Advanced options

```bash
# Dry-run: preview what would be anonymized without making changes
piiswap anonymize evidence/ -r --dry-run

# Protect IOCs from anonymization during the run
piiswap anonymize evidence/ -r -o evidence_anon/ --ioc-file known_iocs.txt

# Only anonymize specific PII types
piiswap anonymize evidence/ -r -o evidence_anon/ --include-types email,phone,iban

# Skip specific PII types
piiswap anonymize evidence/ -r -o evidence_anon/ --exclude-types hostname,filepath_user

# Column-aware mode for CSV/Excel (without template)
piiswap anonymize data.csv -o data_anon.csv --pii-columns "name,email,phone"
piiswap anonymize data.csv -o data_anon.csv --keep-columns "ip,timestamp,hash"
```

> **Note**: Explicit `--pii-columns`/`--keep-columns` always override template settings.

This does the following:
1. **Pass 1**: Scans ALL files and builds the complete mapping store
2. **Pass 2**: Replaces PII with tokens in all files

The output goes into `evidence_anon/` with the same directory structure.

```
CASE-2026-042/
├── evidence/                    # Original (unchanged)
├── evidence_anon/               # Anonymized copy
│   ├── auth.log
│   ├── webserver_access.log
│   └── ...
└── .piiswap/
    └── CASE-2026-042.db         # Mapping database
```

### Step 4: Verify the result

View the created mappings:

```bash
piiswap mappings
```

```
Entity       Type           Token            Raw Value
----------------------------------------------------------------------
PERSON001    email          ANONEMAIL001     jan.janssens@company.be
PERSON001    username       ANONUSER001      jan.janssens
PERSON002    phone          ANONPHONE001     +32 471 12 34 56
...
```

View statistics:

```bash
piiswap status
```

Verify that no PII has leaked:

```bash
piiswap verify evidence/auth.log evidence_anon/auth.log
```

### Step 5: De-anonymize

After analysis (by yourself, an LLM, or an external party) you can translate tokens back:

```bash
piiswap deanonymize evidence_anon/ -r -o evidence_restored/
```

#### Selective de-anonymization

You can restore only specific PII types while keeping others masked. This is useful when sharing results where some PII should remain hidden (e.g., keep passwords masked):

```bash
# Restore only usernames and emails — passwords and IBANs stay masked
piiswap deanonymize llm_output/ -r -o restored/ --only username,email

# Column-aware de-anonymization for CSV/Excel
piiswap deanonymize data_anon.csv -o data.csv --pii-columns "name,email"
piiswap deanonymize data_anon.csv -o data.csv --keep-columns "password,iban"
```

---

## 5. Working with Cloud LLMs

This is the primary use case: analyzing evidence with a cloud LLM (ChatGPT, Claude, Gemini, etc.) without sharing real PII.

### Workflow

```bash
# 1. Anonymize your evidence
piiswap anonymize evidence/ -r -o evidence_anon/

# 2. Send evidence_anon/ files to the LLM
#    (copy-paste, upload, or via API)
#    The LLM only sees tokens: ANONUSER001, ANONEMAIL003, etc.

# 3. Save the LLM result as a file
#    E.g.: analysis_report.md, ioc_overview.xlsx, report.docx
#    The report contains tokens, not real PII

# 4. De-anonymize the LLM result
piiswap deanonymize llm_output/ -r -o rapport_final/
```

### Example

**What the LLM sees** (anonymized):
```
ANONUSER001 logged in via SSH from 192.168.1.50.
Shortly after, a brute-force attack targeted ANONUSER002.
Credential ANONPASS003 was found in the config file.
```

**What you get back after de-anonymization**:
```
jan.janssens logged in via SSH from 192.168.1.50.
Shortly after, a brute-force attack targeted marc.peeters.
Credential SuperGeheim123! was found in the config file.
```

### Supported LLM output formats

| Format | De-anonymization | Formatting preserved |
|--------|:---:|:---:|
| Markdown (.md) | Yes | N/A (text) |
| Plain text (.txt) | Yes | N/A (text) |
| Word (.docx) | Yes | Yes (tables, formatting) |
| Excel (.xlsx) | Yes | Yes (sheets, cells) |
| JSON (.json) | Yes | N/A (text) |
| CSV (.csv) | Yes | N/A (text) |
| PDF (.pdf) | Yes (read) | No (output as .txt) |

### Tips for LLM usage

1. **Do not send the token legend** — the LLM does not need to know that ANONUSER001 = jan.janssens
2. **The LLM can simply refer to ANONUSER001** in its analysis — after de-anonymization this automatically becomes the real name
3. **Multiple reports?** No problem — de-anonymize them all at once with `-r`
4. **IP addresses are intentionally kept in the output** — they are forensic indicators and are not anonymized
5. **Selective de-anonymization**: use `--only username,email` to restore names but keep passwords/IBANs masked in shared reports

---

## 6. Closing a case and starting a new one

### Each case is fully isolated

Each case has:
- Its own **mapping database** (`.piiswap/<case-id>.db`)
- Its own **token numbering** (ANONUSER001 in case A is a different person than ANONUSER001 in case B)
- Its own **allowlist**
- Its own **processed files tracking**

### Closing a case

When a case is finished, you don't need to do anything special. The tokens are not "released" — they only exist within the scope of that single case.

**Options after completion:**

| What | Action | When |
|------|--------|------|
| Keep the mapping database | Do nothing, leave the `.piiswap/` directory | You may need to de-anonymize later |
| Delete the mapping database | Delete the `.piiswap/` directory | Case is fully closed, you no longer need the mappings |
| Delete anonymized files | Delete the `*_anon/` directories | After de-anonymization of all LLM output |
| Archive everything | Zip the entire case directory including `.piiswap/` | Long-term retention |

> **Note**: If you delete the mapping database, you can NEVER de-anonymize again. Keep the database as long as you may still need to translate output back.

### Starting a new case

The easiest way is with `piiswap new`:

```bash
piiswap new CASE-2026-043

# Copy your evidence
cp -r /path/to/new/evidence CASE-2026-043/evidence/

# Continue with the normal workflow
cd CASE-2026-043
piiswap scan evidence/ -r
piiswap anonymize evidence/ -r -o evidence_anon/
```

Or manually:

```bash
mkdir CASE-2026-043
cd CASE-2026-043
piiswap init
```

The new case has:
- Fresh numbering (ANONUSER001, ANONEMAIL001, etc. starting over)
- Empty allowlist
- No connection to previous cases

### Example: two cases side by side

```
cases/
├── CASE-2026-042/
│   ├── evidence/
│   ├── evidence_anon/
│   ├── llm_output/
│   ├── rapport_final/
│   └── .piiswap/
│       └── CASE-2026-042.db     # ANONUSER001 = person A
│
└── CASE-2026-043/
    ├── evidence/
    ├── evidence_anon/
    └── .piiswap/
        └── CASE-2026-043.db     # ANONUSER001 = person B (different person!)
```

**ANONUSER001 in case 042 and ANONUSER001 in case 043 are NOT the same person.** Each case is a completely separate universe.

---

## 7. Multiple cases simultaneously

You can have multiple cases open at the same time. As long as you are in the correct directory (or use `-c`), the correct mappings are used:

```bash
# In case 042
cd CASE-2026-042
piiswap anonymize evidence/ -r -o evidence_anon/

# In case 043
cd CASE-2026-043
piiswap anonymize evidence/ -r -o evidence_anon/

# Or with an explicit case ID (from any location):
piiswap anonymize /path/to/evidence -r -o /path/to/output -c CASE-2026-042
```

---

## 8. Supported file formats

### Fully supported (read + write in original format)

| Format | Extensions | Installation |
|--------|-----------|-------------|
| Plain text | .txt, .log, .md, .csv, .tsv, .json, .xml, .html, .yaml, .yml, .conf, .cfg, .ini, .sql, .php, .sh, .bat, .ps1, .py, .js, .eml, .env, .properties | Basic |
| Word | .docx | `.[formats]` |
| Excel | .xlsx, .xls | `.[formats]` |
| SQLite | .db, .sqlite, .sqlite3 | Basic |

### Read-only (read + output as text)

| Format | Extensions | Output as | Installation |
|--------|-----------|-----------|-------------|
| PDF | .pdf | .txt | `.[formats]` |
| Windows Event Log | .evtx | .xml | `.[forensics]` |
| Network capture | .pcap, .pcapng, .cap | .txt | `.[forensics]` |

> Read-only formats: the anonymized output is written as text/XML because the original binary format cannot be reliably rewritten.

---

## 9. What is and is not anonymized?

### IS anonymized (PII)

| Type | Examples | Token format |
|------|----------|--------------|
| Email addresses | user@company.be | ANONEMAIL001 |
| Phone numbers | +32 471 12 34 56 | ANONPHONE001 |
| IBAN account numbers | BE68 5390 0754 7034 | ANONIBAN001 |
| Usernames | john.doe, jdoe | ANONUSER001 |
| First names | John, Marc | ANONFIRST001 |
| Last names | Smith, Johnson | ANONLAST001 |
| Addresses | Main Street 42 | ANONADDR001 |
| Passwords | SuperSecret123! | ANONPASS001 |
| API keys | DEMO_KEY_..., ghp_... | ANONKEY001 |
| File paths (with user) | C:\Users\john\... | ANONUSER001 |
| Hostnames | DESKTOP-JOHNPC | ANONHOST001 |
| Social handles | @john_doe, u/crypto_user, profile URLs | ANONHANDLE001 |
| Snapchat data | Usernames, emails, phones from production CSVs | (per PII type) |

### Is NOT anonymized (protected by allowlist)

| Type | Reason |
|------|--------|
| IP addresses | Forensic indicators (IOCs) |
| Hashes (MD5, SHA1, SHA256) | Evidence integrity |
| Timestamps | Timeline reconstruction |
| Protocols (HTTP, TCP, SSH) | Technical context |
| MITRE ATT&CK IDs | Classification references |

### Entity resolution

piiswap recognizes that related PII belongs to the same person:

```
jan.janssens@company.be  →  ANONEMAIL001  (PERSON001)
jan.janssens             →  ANONUSER001   (PERSON001)  ← same person!
Janssens                 →  ANONLAST001   (PERSON001)  ← same person!
```

This works automatically based on email - username - name patterns.

---

## 10. Tips and frequently asked questions

### Can I add additional files afterwards?

Yes. Simply run `anonymize` again with the new files:

```bash
# Add extra log files
piiswap anonymize extra_logs/ -r -o extra_logs_anon/
```

The existing mappings are reused. If `jan.janssens` was already ANONUSER001, it stays that way in the new files.

### Can I adjust the allowlist and re-anonymize?

Yes, but you need to reset the `processed_files` tracking. The simplest way is to delete the output directory and anonymize again:

```bash
rm -rf evidence_anon/
piiswap allowlist add "new-value" --type custom
piiswap anonymize evidence/ -r -o evidence_anon/
```

### What if I accidentally anonymize the wrong files?

No problem — the original files are NEVER modified. Delete the output directory and start over.

### Can I export the mapping database?

```bash
piiswap mappings -c MY-CASE
```

This displays all mappings as a table. You can pipe this to a file:

```bash
piiswap mappings -c MY-CASE > mappings_export.txt
```

### What about the encryption key?

The mapping database contains **all real PII** and is therefore the most sensitive file. Recommendations:

1. **Always use encryption** (`-p` or `PIISWAP_KEY`)
2. **Store the key separately** from the database (password manager, not in the same directory)
3. **If you lose the key**, you can no longer de-anonymize

### What if the scan detects too much or too little?

- **Too much**: Add false positives to the allowlist, or use `--exclude-types` to skip entire PII categories
- **Too little**: Check whether the file format is supported (see section 8), or try without `--strict`
- **Strict mode**: Use `--strict` to only detect full name pairs (first + last name), not standalone first names
- **Type filtering**: Use `--include-types` to only detect specific types, or `--exclude-types` to skip types

```bash
piiswap scan evidence/ -r --strict
piiswap scan evidence/ -r --exclude-types hostname,filepath_user
piiswap scan evidence/ -r --include-types email,phone,iban
```

### Can I de-anonymize only specific PII types?

Yes! Use `--only` to selectively restore certain types while keeping others masked:

```bash
# Restore names and emails, but keep passwords and IBANs masked
piiswap deanonymize report_anon.md -o report.md --only username,email,firstname,lastname
```

This is useful when sharing analysis results where some PII should remain hidden.

### Can I manually link two entities?

Yes, if the automatic entity resolution misses a connection:

```bash
piiswap link ANONUSER001 ANONEMAIL005
```

This merges ANONEMAIL005 into the entity of ANONUSER001.

### What if the same person appears in two cases?

That is by design: in case A, `jan.janssens` is ANONUSER001, in case B, `jan.janssens` might be ANONUSER003. The cases are fully separated. This is important for:

- **Privacy**: no cross-case tracking
- **Simplicity**: no shared state between investigations
- **Security**: leaking one case database does not compromise other cases

---

## Summary: quick reference

```bash
# Setup
piiswap new <CASE-ID> [-p password]              # Create case dir + init DB
piiswap init [CASE-ID] [-p password]              # Init DB in existing dir

# Analysis
piiswap scan <path> -r [--strict] [--template <t>] [--ioc-file <f>]
    [--include-types <t>] [--exclude-types <t>]
piiswap anonymize <path> -r -o <output> [--strict] [--dry-run]
    [--template <t>] [--ioc-file <f>]
    [--include-types <t>] [--exclude-types <t>]
    [--pii-columns <cols>] [--keep-columns <cols>]
piiswap deanonymize <path> -r -o <output>
    [--only <types>] [--pii-columns <cols>] [--keep-columns <cols>]
piiswap verify <original> <anonymized>

# Management
piiswap status [-c CASE-ID]
piiswap mappings [-c CASE-ID]
piiswap link <token1> <token2>
piiswap templates                                 # List provider templates

# Allowlist
piiswap allowlist add <value> [--type <t>] [--reason "reason"]
piiswap allowlist add-domain <domain> [--reason "reason"]
piiswap allowlist import-file <file> [--type <t>] [--column <n>]
piiswap allowlist list
piiswap allowlist remove <value>
```
