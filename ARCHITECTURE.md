# piiswap — Architecture

## 1. Pipeline Overview (Bidirectional)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ANONYMIZATION FLOW (→)                           │
│                                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │ Case     │   │ File     │   │ PII      │   │ Entity   │            │
│  │ Files    │──>│ Adapter  │──>│ Detector │──>│ Resolver │            │
│  │ (input)  │   │ Layer    │   │ Engine   │   │          │            │
│  └──────────┘   └──────────┘   └──────────┘   └────┬─────┘            │
│                                                      │                  │
│                                                      v                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │ Anon     │<──│ File     │<──│ Replacer │<──│ Token    │            │
│  │ Files    │   │ Writer   │   │ Engine   │   │ Generator│            │
│  │ (output) │   │          │   │          │   │          │            │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘            │
│                                                      │                  │
│                                                      v                  │
│                                               ┌──────────┐             │
│                                               │ Mapping  │             │
│                                               │ Store    │             │
│                                               │ (SQLite) │             │
│                                               │ encrypted│             │
│                                               └──────────┘             │
└─────────────────────────────────────────────────────────────────────────┘

                              │
                    Anon files to Cloud LLM
                              │
                              v

┌─────────────────────────────────────────────────────────────────────────┐
│                      DE-ANONYMIZATION FLOW (←)                          │
│                                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │ LLM      │   │ Text     │   │ Reverse  │   │ Mapping  │            │
│  │ Output   │──>│ Reader   │──>│ Replacer │<──│ Store    │            │
│  │          │   │          │   │ (tokens  │   │ (lookup) │            │
│  └──────────┘   └──────────┘   │  → PII)  │   └──────────┘            │
│                                 └────┬─────┘                            │
│                                      v                                  │
│                                ┌──────────┐                             │
│                                │ Final    │                             │
│                                │ Report   │                             │
│                                │ (real    │                             │
│                                │  names)  │                             │
│                                └──────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. Detector Engine — Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    PII DETECTOR ENGINE                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ LAYER 1: Allowlist Filter (NEVER anonymize)         │    │
│  │                                                     │    │
│  │  ✗ IPv4/IPv6 addresses                              │    │
│  │  ✗ File hashes (MD5, SHA1, SHA256)                  │    │
│  │  ✗ Timestamps (ISO, syslog, etc.)                   │    │
│  │  ✗ Protocol names (TCP, HTTP, SSH...)               │    │
│  │  ✗ Process names (svchost.exe, cmd.exe...)          │    │
│  │  ✗ MITRE ATT&CK IDs (T1234.001)                    │    │
│  │  ✗ Case-specific allowlist (C2 domains etc.)        │    │
│  │  ✗ Domain-aware: allowlisted domains protect emails │    │
│  │  ✗ IOC file import (--ioc-file)                     │    │
│  │  ✗ Bulk import (allowlist import-file)              │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │ filtered                         │
│                          v                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ TYPE FILTER (--include-types / --exclude-types)     │    │
│  │  Skip or select specific PII types before detection │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │ filtered                         │
│                          v                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ LAYER 2: Regex Detectors (high precision)           │    │
│  │                                                     │    │
│  │  → EmailDetector        (RFC 5322 pattern)          │    │
│  │  → PhoneDetector        (international formats)     │    │
│  │  → IBANDetector         (country prefix + checksum) │    │
│  │  → APIKeyDetector       (high entropy strings)      │    │
│  │  → CredentialDetector   (password=, pwd=, etc.)     │    │
│  │  → FilePathUserDetector (C:\Users\<NAME>\)          │    │
│  │  → HostnamePIIDetector  (LAPTOP-<NAME>)             │    │
│  │  → SocialDetector       (@user, u/user, URLs)       │    │
│  │  → FieldLabelDetector   (Name: Jan, Email: ...)     │    │
│  │  → SnapchatDetector     (production CSV parsing)    │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                  │
│                          v                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ LAYER 3: Wordlist Detectors (flashtext)             │    │
│  │                                                     │    │
│  │  → FullNameDetector     (firstname + lastname)      │    │
│  │  → LastNameDetector     (min 4 characters)          │    │
│  │  → FirstNameDetector    (context-dependent)         │    │
│  │  → StreetAddressDetector(Belgian + intl. streets)   │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                  │
│                          v                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ LAYER 4: NER/ML Detectors [OPTIONAL - Phase 3]     │    │
│  │                                                     │    │
│  │  → SpaCy NER plugin    (nl/en models, CPU)          │    │
│  │  → Local LLM plugin    (ollama/vLLM, GPU optional)  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## 3. Entity Resolution

```
        john.doe@company.com          C:\Users\john.doe\        LAPTOP-JOHN
               │                              │                       │
               v                              v                       v
        ┌──────────┐                   ┌──────────┐            ┌──────────┐
        │ Extract  │                   │ Extract  │            │ Extract  │
        │ local    │                   │ username │            │ name     │
        │ part     │                   │ from path│            │ from host│
        └────┬─────┘                   └────┬─────┘            └────┬─────┘
             │                              │                       │
             v                              v                       v
          john.doe                       john.doe                  JOHN
             │                              │                       │
             └──────────┬───────────────────┘                       │
                        │ exact match                    partial match
                        v                                       │
                 ┌──────────────┐                               │
                 │  PERSON-001  │<──────────────────────────────┘
                 │              │
                 │  mappings:   │
                 │  ├ ANONUSER001    ← john.doe (username)
                 │  ├ ANONEMAIL001   ← john.doe@company.com
                 │  ├ ANONFIRST001   ← John
                 │  ├ ANONLAST001    ← Doe
                 │  └ ANONHOST001    ← LAPTOP-JOHN
                 └──────────────┘
```

## 4. File Adapter Architecture

```
                    ┌──────────────────┐
                    │   FileAdapter    │ (abstract base)
                    │                  │
                    │  read()          │
                    │  write()         │
                    │  supports()      │
                    └────────┬─────────┘
                             │
     ┌──────────┬────────┬───┴────┬──────────┬──────────┬──────────┐
     v          v        v        v          v          v          v
┌────────┐ ┌────────┐ ┌─────┐ ┌──────┐ ┌────────┐ ┌────────┐ ┌────────┐
│Plain   │ │ Docx   │ │ PDF │ │SQLite│ │  EVTX  │ │  PCAP  │ │  XLSX  │
│Text    │ │Adapter │ │Adapt│ │Adapt │ │ Adapter│ │ Adapter│ │ Adapter│
│Adapter │ │        │ │     │ │      │ │        │ │        │ │        │
│.txt    │ │ .docx  │ │.pdf │ │.db   │ │ .evtx  │ │ .pcap  │ │ .xlsx  │
│.log    │ │        │ │→.txt│ │.sqlit│ │ →.xml  │ │ →.txt  │ │        │
│.md .csv│ │        │ │     │ │      │ │        │ │.pcapng │ │        │
│.json   │ │        │ │     │ │      │ │        │ │        │ │        │
│.xml etc│ │        │ │     │ │      │ │        │ │        │ │        │
└────────┘ └────────┘ └─────┘ └──────┘ └────────┘ └────────┘ └────────┘
```

## 5. Mapping Store (Encrypted SQLite)

```
┌─────────────────────────────────────────────────────────┐
│                    mapping.db                            │
│                (Fernet encrypted)                        │
│                                                         │
│  ┌───────────────────────────────────────────────┐      │
│  │ entities                                      │      │
│  │ ┌───────────┬─────────────┬────────────────┐  │      │
│  │ │ entity_id │ entity_type │ created_at     │  │      │
│  │ ├───────────┼─────────────┼────────────────┤  │      │
│  │ │ PERSON-001│ person      │ 2026-03-16T... │  │      │
│  │ │ PERSON-002│ person      │ 2026-03-16T... │  │      │
│  │ └───────────┴─────────────┴────────────────┘  │      │
│  └───────────────────────────────────────────────┘      │
│                                                         │
│  ┌───────────────────────────────────────────────┐      │
│  │ mappings                                      │      │
│  │ ┌──────────┬──────────┬─────────────┬───────┐ │      │
│  │ │entity_id │ pii_type │ raw_value   │ token │ │      │
│  │ ├──────────┼──────────┼─────────────┼───────┤ │      │
│  │ │PERSON-001│ username │ john.doe    │ANON...│ │      │
│  │ │PERSON-001│ email    │ john.doe@.. │ANON...│ │      │
│  │ │PERSON-001│ firstname│ John        │ANON...│ │      │
│  │ │PERSON-001│ lastname │ Doe         │ANON...│ │      │
│  │ └──────────┴──────────┴─────────────┴───────┘ │      │
│  └───────────────────────────────────────────────┘      │
│                                                         │
│  ┌───────────────────────────────────────────────┐      │
│  │ allowlist                                     │      │
│  │ ┌──────────────┬────────────┬────────────┐    │      │
│  │ │ value        │ value_type │ reason     │    │      │
│  │ ├──────────────┼────────────┼────────────┤    │      │
│  │ │ evil-c2.com  │ domain     │ C2 infra   │    │      │
│  │ │ DarkSide     │ alias      │ threat grp │    │      │
│  │ └──────────────┴────────────┴────────────┘    │      │
│  └───────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

## 6. Token Naming Convention

```
PII Type        Token Format           Example
─────────────────────────────────────────────────────
username        ANONUSER###            ANONUSER001
email           ANONEMAIL###           ANONEMAIL001
firstname       ANONFIRST###           ANONFIRST001
lastname        ANONLAST###            ANONLAST001
phone           ANONPHONE###           ANONPHONE001
iban            ANONIBAN###            ANONIBAN001
apikey          ANONKEY###             ANONKEY001
password        ANONPASS###            ANONPASS001
address         ANONADDR###            ANONADDR001
hostname        ANONHOST###            ANONHOST001
social_handle   ANONHANDLE###          ANONHANDLE001
name            ANONNAME###            ANONNAME001
filepath_user   (replaces user part)   C:\Users\ANONUSER001\

Note: tokens NEVER contain special characters (< > - & ' ")
→ safe in XML, SQL, JSON, YAML
```

## 7. CLI Workflow per Case

```
  Analyst                           piiswap                    Cloud LLM
    │                                  │                            │
    │  piiswap new CASE-042          │                            │
    │─────────────────────────────────>│                            │
    │  (case dir + mapping DB created) │                            │
    │                                  │                            │
    │  piiswap scan ./data/ -r       │                            │
    │─────────────────────────────────>│                            │
    │  (dry-run: shows detected PII)   │                            │
    │<─────────────────────────────────│                            │
    │                                  │                            │
    │  piiswap allowlist add         │                            │
    │    "evil-c2.com" "DarkSide"      │                            │
    │─────────────────────────────────>│                            │
    │                                  │                            │
    │  piiswap anonymize ./data/ -r  │                            │
    │─────────────────────────────────>│                            │
    │  (files anonymized)              │                            │
    │<─────────────────────────────────│                            │
    │                                  │                            │
    │  Anonymized files ────────────────────────────────────────>  │
    │                                  │                    (analysis)
    │                                  │                            │
    │  LLM report received  <────────────────────────────────────  │
    │                                  │                            │
    │  piiswap deanonymize           │                            │
    │    llm_report.md                 │                            │
    │─────────────────────────────────>│                            │
    │  (report with real names)        │                            │
    │<─────────────────────────────────│                            │
    │                                  │                            │
    │  piiswap verify                │                            │
    │    original.sql anonymized.sql   │                            │
    │─────────────────────────────────>│                            │
    │  (confirmed: no PII leaked)      │                            │
    │<─────────────────────────────────│                            │
```

## 8. Dependencies per Phase

```
Phase 1 (Core)          Phase 2 (Formats)        Phase 3 (ML)
──────────────          ──────────────────       ─────────────
flashtext               python-docx              spacy
pandas                  pdfplumber               (local LLM via
click                   ruamel.yaml               ollama/vLLM)
cryptography            openpyxl
                        python-evtx
                        scapy
```

## 9. Provider Templates + Column-Aware Processing

```
  piiswap anonymize data.csv --template telegram-user

  ┌─────────────────────────────────────────────────────┐
  │  Template "telegram-user"                            │
  │    pii_columns:  [Username, Name, Phone]             │
  │    keep_columns: [ID, IP, DTG, Type]                 │
  └──────────┬──────────────────────────────────────────┘
             │
             v
  ┌──────────────────────────────────────────────────────┐
  │  Column-Aware Processing (case-insensitive matching) │
  │                                                      │
  │  ┌────────────┬──────────┬─────────┬────────┬──────┐ │
  │  │  Username  │  Name    │  Phone  │   IP   │ DTG  │ │
  │  ├────────────┼──────────┼─────────┼────────┼──────┤ │
  │  │ ANONUSER01 │ ANONNAME │ ANONPH  │ kept   │ kept │ │
  │  │ ANONUSER02 │ ANONNAME │ ANONPH  │ kept   │ kept │ │
  │  └────────────┴──────────┴─────────┴────────┴──────┘ │
  │                                                      │
  │  Blind mode: if template marks column as PII,        │
  │  ALL values are anonymized — even if no detector      │
  │  recognizes them (GustavoGG77, funds4eva, Ot Boppin) │
  └──────────────────────────────────────────────────────┘

  Processing chain per cell:
    1. Check mapping store (already seen?)     → return token
    2. Run detectors (email, phone, etc.)      → register + return token
    3. Blind mode: column says PII             → register + return token

  Column name → PII type inference:
    "username", "login", "screen"  → username
    "email"                        → email
    "phone", "mobile", "gsm"      → phone
    "name", "naam"                 → name
    "address", "adres"             → address

Supported: CsvAdapter (.csv, .tsv), XlsxAdapter (.xlsx)
Matching: case-insensitive (Username == username == USERNAME)
```

## 10. Selective De-anonymization

```
  ┌────────────────────────┐
  │  Anonymized report     │
  │                        │
  │  ANONUSER001 logged in │     piiswap deanonymize
  │  from 192.168.1.50.    │     --only username,email
  │  Password: ANONPASS003 │──────────────────────────────┐
  │  Key: ANONKEY001       │                              │
  └────────────────────────┘                              v
                                           ┌──────────────────────┐
                                           │  Selective output    │
                                           │                      │
                                           │  john.doe logged in  │
                                           │  from 192.168.1.50.  │
                                           │  Password: ANONPASS003│ ← still masked
                                           │  Key: ANONKEY001     │ ← still masked
                                           └──────────────────────┘

Only the requested PII types are restored.
Other tokens remain in place (safe for sharing).
```
