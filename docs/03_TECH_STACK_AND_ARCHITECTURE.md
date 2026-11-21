# 🏗️ ShadowTrace — Tech Stack & Architecture

**Document ID:** ST-ARCH-003  
**Version:** 1.0.0  

---

## 1. Technology Stack

### 1.1 Core Stack

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Language** | Python | 3.12.0 | Primary runtime |
| **Frontend** | Streamlit | ≥ 1.38.0 | Web application framework |
| **Graph Visualization** | Vis.js (via CDN) | 9.1.9 | Interactive network graph embedded via `streamlit.components.v1.html` |
| **Intelligence Engine** | Google Gemini API | gemini-2.0-flash | Function calling, structured reasoning, report synthesis |
| **Gemini SDK** | google-generativeai | ≥ 0.8.0 | Python client for Gemini API |

### 1.2 Supporting Libraries

| Package | Purpose | Windows-Safe |
|---|---|---|
| `streamlit` | UI framework | ✅ Pure wheels |
| `google-generativeai` | Gemini API client | ✅ Pure Python |
| `requests` | HTTP client for live OSINT APIs | ✅ Pure Python |
| `python-whois` | WHOIS lookup fallback | ✅ Pure Python |
| `phonenumbers` | Phone number parsing and validation | ✅ Pure Python |
| `jinja2` | HTML report templating | ✅ Pure Python |
| `markdown` | Markdown-to-HTML conversion for reports | ✅ Pure Python |
| `python-dateutil` | Date parsing for evidence timelines | ✅ Pure Python |

### 1.3 Explicitly Excluded (C++ Build Tool Dependencies)

| Package | Reason for Exclusion | Alternative |
|---|---|---|
| `pygraphviz` | Requires Graphviz C library + MSVC | Vis.js (browser-side) |
| `uvloop` | Unix-only, C-extension | asyncio default loop |
| `numpy/scipy` | Not needed; heavy C-extensions | Pure Python math |
| `pdfkit/weasyprint` | Requires wkhtmltopdf / GTK C libs | Jinja2 HTML → browser print-to-PDF |
| `python-magic` | Requires libmagic C library | Built-in `mimetypes` module |

---

## 2. System Architecture

### 2.1 High-Level Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        STREAMLIT UI (app.py)                     │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐  │
│  │ Sidebar   │  │ Entity Input │  │ Vis.js     │  │ Dossier   │  │
│  │ • API Key │  │ + Trace Btn  │  │ Graph      │  │ Panel     │  │
│  │ • Cases   │  │              │  │ (HTML Comp)│  │ + Export  │  │
│  └──────────┘  └──────┬───────┘  └─────▲──────┘  └─────▲─────┘  │
│                       │                │                │        │
└───────────────────────┼────────────────┼────────────────┼────────┘
                        │                │                │
                        ▼                │                │
┌───────────────────────────────────────────────────────────────────┐
│                   INTELLIGENCE ENGINE (agent.py)                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  Gemini 2.0 Flash — Function Calling Orchestration Loop     │  │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────────────────┐    │  │
│  │  │ Analyze   │  │ Select    │  │ Synthesize Findings  │    │  │
│  │  │ Entity    │→ │ Tools     │→ │ → Report + Graph     │    │  │
│  │  └───────────┘  └─────┬─────┘  └──────────────────────┘    │  │
│  └────────────────────────┼────────────────────────────────────┘  │
│                           │                                       │
└───────────────────────────┼───────────────────────────────────────┘
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                      OSINT TOOLS (tools.py)                       │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │ Crypto Wallet  │  │ UPI OSINT      │  │ Telegram Intel     │  │
│  │ (ETH/BTC/TRON) │  │ (VPA Analysis) │  │ (Channel/Handle)   │  │
│  ├────────────────┤  ├────────────────┤  ├────────────────────┤  │
│  │ Domain WHOIS   │  │ IP Geolocation │  │ Phone OSINT        │  │
│  │ (DNS + Risk)   │  │ (ASN + C2 Flag)│  │ (Carrier + Spam)   │  │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────────┘  │
│          │                   │                    │               │
│          ▼                   ▼                    ▼               │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  Live API Layer (requests) ←→ Fallback Mock Data (cases.py)│  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow Sequence

```
User Input (entity string)
    │
    ▼
app.py receives input → passes to agent.py
    │
    ▼
agent.py sends to Gemini with tool declarations
    │
    ▼
Gemini returns function_call(s) specifying which tool(s) to invoke
    │
    ▼
agent.py executes tool(s) from tools.py
    │
    ├── Live API available? → Hit real API → Parse response
    │
    └── Network down / no key? → Return fallback mock data
    │
    ▼
Tool returns structured JSON: { evidence: {...}, graph: { nodes: [...], edges: [...] } }
    │
    ▼
agent.py feeds results back to Gemini for synthesis
    │
    ▼
Gemini may request additional tool calls (autonomous loop)
    │
    ▼
Final synthesis: { briefing: "...", risk_score: 85, graph: {...}, timeline: [...] }
    │
    ▼
app.py renders: Vis.js graph + Dossier panel + Export buttons
```

---

## 3. Component Details

### 3.1 Streamlit UI (`app.py`)

| Component | Implementation |
|---|---|
| **Theme** | Dark forensic / cyberpunk via `st.set_page_config` + custom CSS injection |
| **Sidebar** | API key input (password field), case study dropdown, about section |
| **Main Area** | Entity input bar, "Autonomous Trace" button, tabbed output panels |
| **Graph Panel** | Vis.js rendered in `streamlit.components.v1.html()` with full interactivity |
| **Dossier Panel** | Formatted markdown with st.expander sections for each evidence category |
| **Export** | `st.download_button` for HTML/PDF/Markdown report files |
| **Thought Trace** | `st.status` + `st.code` blocks showing real-time tool execution log |

### 3.2 Intelligence Engine (`agent.py`)

| Feature | Implementation |
|---|---|
| **Model** | `gemini-2.0-flash` via `google-generativeai` |
| **System Persona** | Elite Cyber Forensic Investigator with Indian law enforcement context |
| **Tool Declarations** | 6 tools registered as Gemini function declarations with typed schemas |
| **Execution Loop** | Iterative: send → receive function_call → execute → feed result → repeat until text response |
| **Output Format** | Structured JSON with `briefing`, `risk_score`, `timeline`, `graph`, `recommendations` |
| **Error Handling** | API timeout → retry once → fallback to template-based synthesis |

### 3.3 OSINT Tools (`tools.py`)

Each tool follows a consistent pattern:

```python
def lookup_tool(input_param: str) -> dict:
    """
    1. Validate input format
    2. Attempt live API call (try/except with timeout)
    3. On failure → return deterministic fallback data
    4. Structure response as:
       {
           "status": "live" | "fallback",
           "evidence": { ... raw findings ... },
           "risk_score": 0-100,
           "graph": {
               "nodes": [ { "id": "...", "label": "...", "type": "...", "threat_level": "..." } ],
               "edges": [ { "source": "...", "target": "...", "relation": "...", "threat_level": "..." } ]
           }
       }
    """
```

### 3.4 Case Data (`cases.py`)

| Element | Content |
|---|---|
| **Case Definitions** | 2 complete cases with metadata, suspect entities, evidence chains |
| **Fallback Datasets** | Pre-computed tool outputs for every entity in both cases |
| **Graph Data** | Complete node/edge lists for Vis.js rendering |
| **Evidence Artifacts** | Realistic WHOIS records, blockchain transactions, UPI metadata |

---

## 4. API Dependencies

| API | Purpose | Required? | Fallback |
|---|---|---|---|
| Google Gemini API | AI reasoning + synthesis | Yes (for live AI) | Template-based report generation |
| Etherscan API | ETH wallet lookup | No | Mock blockchain data |
| Blockchain.info API | BTC wallet lookup | No | Mock blockchain data |
| Tronscan API | TRON wallet lookup | No | Mock blockchain data |
| ip-api.com | IP geolocation | No | Mock geolocation data |
| WHOIS (python-whois) | Domain registration data | No | Mock WHOIS records |

---

## 5. Security Considerations

| Concern | Mitigation |
|---|---|
| API key exposure | Stored in Streamlit session state only; never logged or persisted to disk |
| User input injection | All entity inputs validated against expected formats before processing |
| XSS in graph rendering | Vis.js labels sanitized; no raw HTML injection in graph component |
| Data privacy | No investigation data stored beyond the browser session |
| Dependency supply chain | All packages pinned to specific versions in `requirements.txt` |

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
