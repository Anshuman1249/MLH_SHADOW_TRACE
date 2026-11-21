# 📜 ShadowTrace — Project Rules & Development Standards

**Document ID:** ST-RULES-004  
**Version:** 1.0.0  

---

## 1. Zero-Placeholder Policy

> **ABSOLUTE RULE:** No file in this project may contain placeholder code, truncated blocks, or dummy data.

| Violation | Example | Required Action |
|---|---|---|
| TODO comments | `# TODO: implement later` | Write complete implementation or ask for clarification |
| Truncated code | `// ... rest of code ...` | Provide every line of the function |
| Dummy data | `"test1234"`, `"example.com"` | Use forensically realistic values (valid WHOIS format, real UPI VPA structure, actual blockchain address format) |
| Hardcoded fake keys | `"sk-fake-key-123"` | Use environment variable or UI input with clear instructions |
| Empty functions | `def analyze(): pass` | Full implementation or raise `NotImplementedError` with explanation |

---

## 2. Code Quality Standards

### 2.1 Python Style

| Rule | Standard |
|---|---|
| **Formatter** | PEP 8 compliant |
| **Line Length** | 100 characters max (soft), 120 characters (hard) |
| **Imports** | Grouped: stdlib → third-party → local; alphabetical within groups |
| **Type Hints** | Required on all function signatures |
| **Docstrings** | Required on all public functions; Google-style format |
| **Constants** | UPPER_SNAKE_CASE at module level |
| **Error Handling** | Specific exceptions; never bare `except:` |

### 2.2 Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Files | `snake_case.py` | `tools.py`, `agent.py`, `cases.py` |
| Functions | `snake_case` | `lookup_crypto_wallet()` |
| Classes | `PascalCase` | `ForensicReport` |
| Constants | `UPPER_SNAKE_CASE` | `GEMINI_MODEL_NAME` |
| Graph node IDs | `type:value` format | `wallet:0xABC...`, `upi:fraud@ybl` |

### 2.3 Function Return Standards

Every OSINT tool function must return a dict matching this schema:

```python
{
    "status": "live" | "fallback",          # Data source indicator
    "query": "original_input",              # Echo back the input
    "evidence": {                           # Raw intelligence findings
        "summary": "...",
        "details": { ... },
        "risk_indicators": [ ... ]
    },
    "risk_score": 0-100,                    # Computed threat score
    "graph": {
        "nodes": [
            {
                "id": "unique_id",
                "label": "Display Label",
                "type": "wallet|upi|telegram|domain|ip|phone|exchange|mixer|person",
                "threat_level": "critical|high|medium|low|info"
            }
        ],
        "edges": [
            {
                "source": "node_id_1",
                "target": "node_id_2",
                "relation": "Description of relationship",
                "threat_level": "critical|high|medium|low|info"
            }
        ]
    }
}
```

---

## 3. Resilience & Fallback Rules

### 3.1 Dual-Mode Architecture

Every external data source must implement the following pattern:

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│ Validate    │ ──→ │ Try Live API │ ──→ │ Parse Response │
│ Input       │     │ (timeout 5s) │     │                │
└─────────────┘     └──────┬───────┘     └────────────────┘
                           │ FAIL
                           ▼
                    ┌──────────────┐
                    │ Return       │
                    │ Fallback     │
                    │ Mock Data    │
                    └──────────────┘
```

### 3.2 Fallback Data Quality

| Requirement | Detail |
|---|---|
| **Structural Fidelity** | Mock responses must match the exact JSON schema of the real API |
| **Forensic Realism** | Addresses, timestamps, and amounts must be plausible (not `0x000...000`) |
| **Determinism** | Same input always returns same fallback output (no randomization) |
| **Coverage** | Every entity in both pre-seeded cases must have a pre-computed fallback |
| **Labeling** | Fallback responses must set `"status": "fallback"` so the UI can indicate data source |

---

## 4. UI/UX Rules

### 4.1 Theme Requirements

| Element | Specification |
|---|---|
| **Background** | Dark (#0a0a0a to #1a1a2e gradient) |
| **Primary Accent** | Neon cyan (#00f5d4) |
| **Alert/Danger** | Red (#ff0054) |
| **Warning** | Amber (#f0a500) |
| **Text** | Light gray (#e0e0e0) on dark background |
| **Font** | Monospace for data/code, sans-serif for headings |
| **Branding** | "ShadowTrace" — no mention of AI, LLM, or Gemini in the UI |

### 4.2 UI Branding Rules

| ✅ Allowed in UI | ❌ Not Allowed in UI |
|---|---|
| "ShadowTrace Intelligence Engine" | "AI Agent" |
| "Autonomous Analysis" | "LLM" or "Large Language Model" |
| "Intelligence Module" | "Gemini" or "Google AI" |
| "Threat Analysis Engine" | "Machine Learning Model" |
| "Forensic Intelligence System" | "Neural Network" |

### 4.3 Graph Visualization Rules

| Rule | Detail |
|---|---|
| **Node Colors** | Critical: red, High: orange, Medium: yellow, Low: green, Info: cyan |
| **Node Shapes** | Wallet: diamond, UPI: dot, Telegram: triangle, Domain: square, IP: hexagon, Phone: star |
| **Edge Labels** | Always show relationship type |
| **Physics** | Enabled with moderate repulsion for readable layouts |
| **Interaction** | Drag, zoom, hover tooltips, click to highlight connected nodes |

---

## 5. Git & Version Control Rules

| Rule | Detail |
|---|---|
| **Branch Strategy** | `main` branch only (hackathon scope) |
| **Commit Messages** | `[component] action: description` (e.g., `[tools] add: crypto wallet lookup`) |
| **No Secrets in Git** | API keys via UI input or environment variables only |
| **`.gitignore`** | `__pycache__/`, `*.pyc`, `.env`, `.streamlit/secrets.toml` |

---

## 6. Hackathon Presentation Rules

| Rule | Detail |
|---|---|
| **Demo Duration** | Exactly 3 minutes — rehearse to this target |
| **Failure Protocol** | If live API fails during demo, fallback data activates silently — do not mention it |
| **Screen Setup** | Full-screen browser, font size adequate for projector (minimum 16px) |
| **Case Study Order** | Demo Case #409 (Operation DhanChor) first — it has the most visual graph |
| **Q&A Prep** | Anticipate questions about data sources, privacy, and scalability |

---

## 7. Documentation Standards

| Rule | Detail |
|---|---|
| **File Naming** | `NN_DOCUMENT_TITLE.md` (numbered, uppercase with underscores) |
| **Headers** | Maximum 4 levels (`####`) |
| **Tables** | Use markdown tables for structured comparisons |
| **Diagrams** | ASCII art or Mermaid.js for architecture diagrams |
| **Cross-References** | Link to other docs by relative path |

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
