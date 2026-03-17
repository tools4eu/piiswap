# Threat Analysis Report

## Executive Summary

Based on the provided evidence, **ANONEMAIL001** is the primary subject of this investigation. The account was compromised or used to conduct unauthorized activities, with logins from both the subject's home IP (84.193.22.41) and a suspicious Tor exit node (185.220.101.44, Moscow RU).

## Timeline

| Time (UTC) | Actor | Event | IP | Source |
|------------|-------|-------|-----|--------|
| 07:55 | ANONUSER001 | Snapchat login (iPhone) | 84.193.22.41 | Snapchat data |
| 08:00 | ANONEMAIL001 | ISP: connection to Microsoft 365 | 84.193.22.41 | ISP log |
| 08:15 | ANONEMAIL001 | Microsoft 365 sign-in (ANONHOST001) | 84.193.22.41 | Microsoft |
| 10:00 | ANONEMAIL001 | Microsoft 365 sign-in (unknown device) | 185.220.101.44 | Microsoft |
| 10:02 | ANONUSER001 | Snapchat login (Android Unknown) | 185.220.101.44 | Snapchat data |
| 10:10 | ANONEMAIL003 | Azure Portal login attempts (2 fail, 1 success) | 185.220.101.44 | Microsoft |
| 10:15 | ANONEMAIL001 | Email to ANONUSER003 about shipment | 185.220.101.44 | Email headers |
| 10:30 | ANONEMAIL001 | ISP: large data transfer to 45.33.32.156 | 84.193.22.41 | ISP log |

## Key Findings

### 1. Account Compromise or Dual-Use
ANONEMAIL001 logged into Microsoft 365 from 84.193.22.41 (Brussels, legitimate) at 08:15, then from 185.220.101.44 (Moscow, Tor exit) at 10:00. This is a **simultaneous session from two countries**, indicating either:
- Account compromise (stolen credentials)
- Intentional use of Tor for operational security

The Snapchat account ANONUSER001 shows the same pattern: legitimate iPhone login at 07:55, then "Android Unknown" from 185.220.101.44 at 10:02.

### 2. Admin Account Breach
ANONEMAIL003 (admin account) was accessed from 185.220.101.44 after two failed attempts. This suggests **brute-force followed by successful access** — likely using credentials harvested from the compromised session.

### 3. Cryptocurrency Activity
ANONEMAIL001 made a BTC withdrawal (0.734 BTC) from the crypto exchange from IP 185.220.101.44 — the same suspicious IP. The destination wallet is ANONKEY001.

The earlier withdrawal (0.5 BTC on Feb 28) was from the legitimate IP 84.193.22.41.

### 4. Communication with Suspect Contact
ANONUSER003 (ANONUSER003) is listed in ANONEMAIL001's Snapchat friends. An email was sent from ANONEMAIL001 to ANONUSER003 on Mar 1 at 10:15 discussing a "shipment" and providing a physical address (ANONADDR001) and phone number (ANONPHONE001).

### 5. Financial Exposure
- IBAN: ANONIBAN001 — linked to the crypto exchange KYC
- BTC wallet: ANONKEY001 — received 0.734 BTC withdrawal during suspicious session
- Total crypto exposure: approximately 1.234 BTC + 15.5 ETH on exchange

### 6. Social Media Footprint
The subject maintains accounts across multiple platforms:
- Instagram: ANONHANDLE001
- Twitter: ANONHANDLE002
- Snapchat: ANONUSER001
- Telegram: ANONHANDLE003
- LinkedIn: ANONHANDLE004
- Reddit: ANONHANDLE005

The Telegram account ANONHANDLE003 is a member of crypto and darknet channels, which aligns with the cryptocurrency activity and communication with ANONUSER003.

## IOCs

| Type | Value | Context |
|------|-------|---------|
| IP | 185.220.101.44 | Tor exit node, Moscow — used for unauthorized access |
| IP | 45.33.32.156 | Large data exfiltration target |
| IP | 84.193.22.41 | Subject home IP (Brussels) |
| Email | ANONUSER003 | Suspect contact (darkweb) |

## MITRE ATT&CK

- **T1078** — Valid Accounts (ANONEMAIL001 and ANONEMAIL003)
- **T1071.001** — Application Layer Protocol: Web (Microsoft 365 abuse)
- **T1567** — Exfiltration Over Web Service (crypto withdrawal)
- **T1090** — Proxy: Multi-hop (Tor usage from 185.220.101.44)

## Recommendations

1. **Immediately** disable ANONEMAIL001 and ANONEMAIL003
2. **Immediately** freeze crypto exchange account and flag ANONIBAN001
3. **Preserve** ISP logs for 84.193.22.41 and 91.182.33.55 (ANONEMAIL002)
4. **Investigate** ANONUSER003 as potential co-conspirator
5. **Monitor** ANONHANDLE003 (Telegram) for ongoing darknet activity
6. **Request** full chat logs between ANONUSER001 and ANONUSER003 from Snapchat
7. **Correlate** ANONPHONE001 with telecom records for Mar 1 timing
