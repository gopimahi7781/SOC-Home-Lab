# SOC Home Lab — Detection & Incident Response

A self-built Security Operations Center (SOC) lab for hands-on blue-team practice: log collection, SIEM detection engineering, alerting, EDR, IDS, and automated SOAR response. Real attacks are generated, detected, triaged, and documented as incident tickets — the full SOC analyst workflow, end to end.

---

## Lab Overview

An isolated virtual network running a SIEM, a monitored Windows endpoint, and an attacker host. Attacks are launched, detected in the SIEM, and investigated like production alerts.

| Role | System |
|------|--------|
| SIEM | Splunk Enterprise (Ubuntu Server) |
| Monitored endpoint | Windows 10 — Sysmon + Universal Forwarder |
| Attacker | Kali Linux |

---

## Tooling & Data Sources

| Capability | Tool | Notes |
|-----------|------|-------|
| SIEM | Splunk Enterprise | Indexes: `windows`, `linux`, `snort`, `edr` |
| Windows telemetry | Sysmon + Universal Forwarder | SwiftOnSecurity config |
| Linux telemetry | auth.log + syslog | SSH / system events |
| IDS | Snort | Custom rules: ICMP, Nmap scan, SSH brute-force |
| EDR | LimaCharlie | Sigma rules → detections → Splunk |
| SOAR | Tines | Webhook → AbuseIPDB reputation → email alert |

---

## Detection & Alerting

- Scheduled **Splunk alerts** (High severity) for SSH and RDP brute-force activity
- Custom **Snort rules** for network-based attacks (port scans, ICMP, brute-force)
- **LimaCharlie + Sigma** detections forwarded into Splunk for unified EDR visibility
- **SOC monitoring dashboard** — KPIs, attack timechart, top attacker IPs
- **Threat-intel lookups** — a known-bad IP list enriches alerts in Splunk, tagging matching source IPs with threat type and source

---

## SOAR Automation

Splunk alert → Tines webhook → **AbuseIPDB** IP reputation lookup → formatted **email summary** to the analyst inbox. Automates the enrichment step of triage so IP context is delivered without manual lookups.

---

## Attacks Simulated (MITRE ATT&CK)

| Technique | ID | Tool |
|-----------|-----|------|
| Network Service Discovery | T1046 | Nmap |
| Brute Force — SSH | T1110 | Hydra |
| Brute Force — RDP | T1110 | Hydra |
| Create Account | T1136.001 | `net user` |

---

## Investigations

Each incident is triaged and documented as a SOC ticket: **alert → investigation → evidence → analysis → verdict → recommendations.**

| # | Incident | Technique | Verdict |
|---|----------|-----------|---------|
| 01 | [RDP Brute-Force Attempt](incident-01-rdp-bruteforce.md) | T1110 | True Positive — No Compromise |
| 02 | [Nmap Port Scan Detected by IDS](incident-02-nmap-portscan.md) | T1046 | True Positive — Reconnaissance |
| 03 | [Phishing Email Analysis](incident-03-phishing-email.md) | T1566 | True Positive — Malicious Phishing |
| 04 | [Nmap SYN Scan (PCAP Analysis)](incident-04-nmap-syn-scan.md) | T1046 | True Positive — Reconnaissance |

*Additional investigations added as the lab grows.*

---

## Skills Demonstrated

- SIEM searching & detection engineering (Splunk SPL)
- Alert triage & True / False Positive classification
- Windows event log analysis (Event IDs 4624 / 4625)
- Network detection with an IDS (Snort)
- EDR detection with Sigma rules (LimaCharlie)
- SOAR enrichment automation (Tines)
- Threat-intel enrichment with Splunk lookups (known-bad IP matching)
- Phishing email analysis (header / SPF-DKIM-DMARC, link & attachment inspection)
- Packet capture & network traffic analysis (tcpdump capture, Wireshark — display filters, TCP flags, Conversations, scan detection)
- Incident documentation & MITRE ATT&CK mapping
