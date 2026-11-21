# ShadowTrace 🛡️
### Forensic Scam Intelligence & Financial Laundering Triage Platform

ShadowTrace is an autonomous cyber intelligence dashboard built for law enforcement investigators, cyber crime cells, and forensic analysts. It accelerates financial fraud triage by tracing suspect entities across multiple decentralized and digital payment rails in seconds.

---

## ⚡ Core Capabilities

- **Cross-Rail Entity Resolution:** Automatically identifies and normalizes suspect vectors:
  - **Crypto Wallets:** EVM (Ethereum, Polygon, BSC, Arbitrum, Base), TRON (TRC-20), and Bitcoin.
  - **Indian UPI VPAs:** Virtual Payment Addresses and `upi://pay` payment intent deep links.
  - **Telecom Subscribers:** Indian mobile numbers resolved to their Department of Telecommunications (DoT) Licensed Service Area (LSA) circle and assigned operator (Vodafone Idea, Bharti Airtel, Reliance Jio, BSNL).
  - **Telegram Threats:** Public channel & bot threat intel extraction (`t.me/s/...`).
  - **Network Vectors:** Web phishing hostnames, WHOIS registration, SSL certificates, and IP geolocation.

- **Multi-Hop On-Chain Graph:**
  - Live queries to Blockscout v2 APIs, TRON RPC nodes, and Blockchain.info.
  - Expands 2-3 hops through top counterparties by transaction value.
  - Flags known exchanges (cash-out nodal points) and mixer/anonymizer contracts (Tornado Cash, etc.) against OFAC SDN lists.

- **Explainable Rule-Based Threat Scoring:**
  - Deterministic evaluation based on mixer interactions, rapid pass-through / peel chains, high-velocity fan-outs, and known illicit tag matches.
  - Safely outputs `INSUFFICIENT DATA` when no on-chain records exist, preventing false-positive indictments.

- **Statutory Police Briefing & Evidentiary Dossier:**
  - Generates court-ready Section 94 BNSS 2023 production orders and Section 63 BSA 2023 evidence dossiers.
  - Strictly evidence-grounded: cites penal sections (BNS 318/319, IT Act 66C/66D, PMLA Sec 3) only when supported by verifiable forensic artifacts.
  - Exports to ReportLab PDF, structured JSON, and CSV.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- `git`

### 2. Installation
```bash
git clone https://github.com/Anshuman1249/MLH_SHADOW_TRACE.git
cd MLH_SHADOW_TRACE
pip install -r requirements.txt
```

### 3. Running the Dashboard
```bash
streamlit run app.py
```

The investigation console will launch in your browser at `http://localhost:8501`.

---

## 📂 Project Architecture

```
shadowtrace/
├── app.py                 # Streamlit forensic operations dashboard & visualizer
├── agent.py               # Autonomous triage engine & evidence synthesis
├── tools.py               # Live blockchain drivers, DoT telecom OSINT, & graph builder
├── entity_detector.py     # Universal classifier (Crypto, UPI, Phone, Telegram, Domain, IP)
├── cases.py               # Verified demo syndicate files & threat color palettes
├── case_store.py          # Investigation persistence & cross-case link detection
├── requirements.txt       # Production dependencies
├── CASE_STUDIES.md        # Operation walk-throughs & investigative scenarios
└── docs/                  # Technical specifications & architecture guides
```

---

## 📜 Statutory Compliance
Compliant with standard Indian law enforcement evidentiary procedures:
- **Section 94 BNSS 2023:** Summons to produce documents or records from nodal officers.
- **Section 63 BSA 2023:** Admissibility of electronic records with cryptographic SHA-256 hash trail.
- **Section 69 IT Act 2000:** Lawful interception and subscriber identity disclosure directives.
