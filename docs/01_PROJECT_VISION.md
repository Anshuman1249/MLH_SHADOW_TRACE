# 🛡️ ShadowTrace — Project Vision

**Project:** ShadowTrace — Autonomous Dark-Web & Crypto Scam Intelligence Assistant  
**Event:** National Cybersecurity Hackathon @ NFSU (National Forensic Sciences University)  
**Organizers:** Major League Hacking (MLH) × Google Gemini  
**Version:** 1.0.0  
**Date:** November 2026  

---

## 1. Problem Statement

India reported **31,000+ cybercrime complaints per day** on the National Cybercrime Reporting Portal (NCRP) in 2025, with estimated annual losses exceeding ₹30,000 crore. The dominant attack chains follow a repeatable pattern:

1. **Social Engineering Entry** — Telegram job scams, fake utility bill APKs, loan app extortion
2. **Financial Layering** — Victim funds routed through UPI mule accounts, hawala networks, or prepaid wallets
3. **Crypto Exit** — Layered funds converted to USDT/TRX via P2P exchanges, washed through mixers (Tornado Cash, Sinbad), and cashed out on offshore CEXs

Law enforcement investigators (I4C, State Cyber Cells) currently perform each OSINT lookup **manually** — checking wallets on Etherscan, running WHOIS queries, tracing UPI handles across bank portals — in a process that takes **days per case**. By the time the financial trail is mapped, funds have already exited Indian jurisdiction.

---

## 2. Vision

> **ShadowTrace autonomously traces a single suspect entity (crypto wallet, UPI ID, Telegram handle, domain, phone number, or IP address) through the entire scam kill-chain in under 60 seconds, producing an interactive knowledge graph, forensic dossier, and FIR-ready police briefing.**

### Core Differentiators

| Capability | Manual Investigation | ShadowTrace |
|------------|--------------------|-------------|
| Entity resolution across chains | Hours/Days | < 30 seconds |
| Cross-domain correlation (UPI ↔ Crypto ↔ Telegram) | Requires 4+ separate tools | Single autonomous trace |
| Knowledge graph generation | Not performed | Real-time Vis.js interactive graph |
| FIR/I4C formatted report | Manual drafting | Auto-generated, exportable |
| Offline resilience | N/A — requires live access | Full deterministic fallback dataset |

---

## 3. Target Users

| Persona | Use Case |
|---|---|
| **Cyber Crime Investigators** (State Police / I4C) | Rapid triage of reported complaints, evidence chain construction |
| **Forensic Analysts** (NFSU, CFSL labs) | Technical artifact analysis, expert witness report generation |
| **Financial Intelligence Units** (FIU-IND, ED) | PMLA compliance, crypto trail documentation for prosecution |
| **Hackathon Judges** (MHA/NFSU panel) | Live demonstration of autonomous OSINT + AI-driven analysis |

---

## 4. Success Metrics (Hackathon Demo)

| Metric | Target |
|---|---|
| End-to-end trace time | < 60 seconds for pre-seeded cases |
| Graph entities rendered | ≥ 12 nodes, ≥ 15 edges per case |
| Report completeness | FIR sections, risk score, timeline, regulatory citations |
| Offline resilience | 100% functional with no network connectivity |
| UI polish | Dark forensic theme, zero UI errors during 3-min pitch |

---

## 5. Alignment with National Cybersecurity Goals

- **MHA I4C (Indian Cyber Crime Coordination Centre):** Direct alignment with the Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS) workflow
- **BNSS 2023 (Bharatiya Nagarik Suraksha Sanhita):** Report format compliant with Section 94 (formerly CrPC Section 91) production orders for digital evidence
- **PMLA 2002:** Crypto trail documentation suitable for Enforcement Directorate proceedings
- **RBI Digital Payment Security Controls (2024):** UPI mule detection aligns with PSP fraud monitoring guidelines

---

## 6. Hackathon Pitch Tagline

> *"From a single Telegram handle to a complete scam kill-chain — traced, graphed, and briefed in 60 seconds."*

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
