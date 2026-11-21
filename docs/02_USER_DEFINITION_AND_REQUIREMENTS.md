# 📋 ShadowTrace — User Definition & Requirements

**Document ID:** ST-URD-002  
**Version:** 1.0.0  
**Status:** Approved for Development  

---

## 1. User Personas

### 1.1 Primary: Cyber Crime Investigator (State Cyber Cell / I4C)

| Attribute | Detail |
|---|---|
| **Role** | Sub-Inspector to Inspector rank, assigned cyber fraud cases |
| **Technical Level** | Moderate — comfortable with web apps, limited CLI experience |
| **Daily Workflow** | Receives NCRP complaint → manually checks bank/UPI/crypto records → drafts FIR |
| **Pain Points** | 50+ complaints/day backlog; each trace takes 2-4 hours; no cross-domain correlation tool |
| **Success Criteria** | Reduce per-case triage from hours to minutes; auto-generate FIR-ready reports |

### 1.2 Secondary: Forensic Analyst (NFSU / CFSL)

| Attribute | Detail |
|---|---|
| **Role** | Digital forensics examiner preparing expert witness testimony |
| **Technical Level** | High — understands blockchain, network forensics, malware analysis |
| **Daily Workflow** | Receives seized devices → extracts artifacts → correlates across data sources → writes expert report |
| **Pain Points** | Manual graph construction in Maltego/i2; no India-specific UPI/Telegram intelligence feeds |
| **Success Criteria** | Interactive evidence graph with exportable forensic dossier |

### 1.3 Tertiary: Hackathon Judge (MHA / NFSU Panel)

| Attribute | Detail |
|---|---|
| **Role** | Evaluates hackathon submissions for innovation, feasibility, and national impact |
| **Technical Level** | Variable — mix of policy experts and technical faculty |
| **Evaluation Criteria** | Working demo, real-world applicability, UI polish, presentation quality |
| **Success Criteria** | Impressive 3-minute live demo with zero crashes |

---

## 2. Functional Requirements

### 2.1 Core Features (Must-Have — P0)

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| FR-01 | **Entity Input** | User enters any suspect entity: crypto address, UPI VPA, Telegram handle, domain, IP, or phone number |
| FR-02 | **Autonomous Multi-Tool Trace** | System autonomously selects and executes relevant OSINT tools without user intervention |
| FR-03 | **Interactive Knowledge Graph** | Vis.js graph with draggable nodes, color-coded threat levels, labeled edges, physics simulation |
| FR-04 | **Forensic Dossier Generation** | Structured report with: Executive Summary, Evidence Timeline, Risk Score (0-100%), Entity Table, Regulatory Citations |
| FR-05 | **FIR/I4C Police Briefing** | Auto-formatted briefing compliant with I4C CFCFRMS reporting standards |
| FR-06 | **Pre-Seeded Case Studies** | 2 complete cases loadable from dropdown: Operation DhanChor, Operation Vidyut |
| FR-07 | **Report Export** | Downloadable in HTML, PDF, and Markdown formats |
| FR-08 | **Offline Resilience** | Full functionality using deterministic fallback data when network is unavailable |

### 2.2 OSINT Tool Requirements (P0)

| Tool | Input | Output |
|---|---|---|
| `lookup_crypto_wallet` | Crypto address + chain (ETH/BTC/TRON) | Balance, tx count, risk rating, flagged mixer/exchange hops, graph nodes/edges |
| `lookup_upi_osint` | UPI VPA (e.g., `name@bank`) | Bank PSP, velocity flags, mule risk score, merchant registry check, graph nodes/edges |
| `lookup_telegram_threat_intel` | Handle or channel name | Threat group associations, scam kit promotions, linked crypto addresses, graph nodes/edges |
| `lookup_domain_whois_dns` | Domain name | Registrar, creation date, nameservers, hosting IP, phishing risk score, graph nodes/edges |
| `lookup_ip_geolocation` | IPv4/IPv6 address | Country, city, ASN, ISP, hosting provider, known C2 flags, graph nodes/edges |
| `lookup_phone_osint` | Phone number (E.164) | Carrier, region, VoIP flag, spam reports, linked UPI/social accounts, graph nodes/edges |

### 2.3 Enhanced Features (Nice-to-Have — P1)

| ID | Requirement | Notes |
|---|---|---|
| FR-09 | **Thought Trace Panel** | Terminal-style real-time display of the intelligence engine's reasoning and tool calls |
| FR-10 | **Risk Heatmap** | Color-coded risk indicators across all discovered entities |
| FR-11 | **Case Session Persistence** | Ability to reload and continue a previous investigation session |
| FR-12 | **Evidence Chain Validation** | Automated check that every graph edge has a supporting evidence artifact |

---

## 3. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | **Response Time** | Complete trace in < 60 seconds (pre-seeded cases < 30s) |
| NFR-02 | **Browser Compatibility** | Chrome 100+, Firefox 100+, Edge 100+ |
| NFR-03 | **Accessibility** | High contrast dark theme, readable fonts ≥ 14px |
| NFR-04 | **Data Privacy** | No user data persisted beyond session; API keys stored in session state only |
| NFR-05 | **Deployment Simplicity** | Single `pip install` + `streamlit run` on Windows 11 with Python 3.10-3.12 |
| NFR-06 | **Zero C++ Dependencies** | All Python packages must be pure-Python or ship pre-built Windows wheels |
| NFR-07 | **Error Handling** | Graceful degradation — network failures trigger fallback, never crash |

---

## 4. Constraints

| Constraint | Detail |
|---|---|
| **Runtime** | Python 3.10 – 3.12 on Windows 11 (64-bit) |
| **No Build Tools** | No Visual C++ Build Tools; no `pygraphviz`, `uvloop`, or similar C-extensions |
| **API Dependencies** | Google Gemini API only; all other OSINT sources use public APIs or fallback data |
| **Hackathon Time** | Complete build within hackathon timeframe; prioritize demo stability over feature breadth |
| **Presentation** | 3-minute pitch to NFSU/MHA judges; UI must be self-explanatory and visually impressive |

---

## 5. User Stories

| ID | Story | Priority |
|---|---|---|
| US-01 | As an investigator, I want to paste a suspicious UPI ID and get an instant risk assessment so I can prioritize high-risk complaints | P0 |
| US-02 | As an investigator, I want to see how a crypto wallet connects to UPI mule accounts in a visual graph so I can explain the money trail to a magistrate | P0 |
| US-03 | As a forensic analyst, I want to export a complete evidence dossier in HTML format so I can attach it to my expert witness report | P0 |
| US-04 | As a hackathon judge, I want to see a pre-loaded case study execute flawlessly so I can evaluate the tool's capabilities | P0 |
| US-05 | As an investigator, I want the tool to work even without internet so I can use it in field offices with poor connectivity | P0 |
| US-06 | As a forensic analyst, I want to trace a Telegram channel to its linked crypto deposit addresses so I can identify the financial beneficiary of a scam ring | P0 |
| US-07 | As an investigator, I want a one-click FIR-formatted police briefing so I don't have to manually rewrite the findings | P1 |

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
