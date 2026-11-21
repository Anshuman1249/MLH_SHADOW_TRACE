# 🔨 ShadowTrace — Development Guide

**Document ID:** ST-DEV-007  
**Version:** 1.0.0  

---

## 1. Development Workflow

### 1.1 File Modification Order

Always develop and test in this order to minimize breakage:

```
cases.py → tools.py → agent.py → app.py
   (1)        (2)        (3)       (4)
```

**Rationale:**
- `cases.py` has zero imports from other project files — it's the data foundation
- `tools.py` imports only from `cases.py` (for fallback data)
- `agent.py` imports from `tools.py` (tool functions) and `cases.py` (case definitions)
- `app.py` imports from all three — it's the top-level integration

### 1.2 Hot Reload Development

Streamlit supports hot reload. During development:

```powershell
streamlit run app.py
```

Edit any `.py` file → save → Streamlit auto-detects the change → click "Rerun" in the browser (or enable "Always rerun" in Streamlit settings).

---

## 2. Module Contracts

### 2.1 `cases.py` — Data Layer Contract

**Exports:**

| Name | Type | Description |
|---|---|---|
| `CASES` | `dict[str, dict]` | Map of case_id → case definition (metadata, entities, evidence) |
| `FALLBACK_DATA` | `dict[str, dict]` | Map of `"tool_name:input"` → pre-computed tool output |
| `get_case(case_id: str)` | `function → dict` | Returns a specific case definition |
| `get_fallback(tool_name: str, query: str)` | `function → dict or None` | Returns fallback data for a specific tool+query combo |
| `GRAPH_STYLES` | `dict` | Node type → color/shape mapping for Vis.js |

**Rules:**
- No external imports beyond Python stdlib
- All data is deterministic — no random generation
- Every entity appearing in a case must have a corresponding fallback entry

### 2.2 `tools.py` — OSINT Layer Contract

**Exports:**

| Name | Signature | Description |
|---|---|---|
| `lookup_crypto_wallet` | `(address: str, chain: str) → dict` | Blockchain intelligence |
| `lookup_upi_osint` | `(upi_id: str) → dict` | UPI VPA analysis |
| `lookup_telegram_threat_intel` | `(handle_or_channel: str) → dict` | Telegram threat intel |
| `lookup_domain_whois_dns` | `(domain: str) → dict` | Domain WHOIS + DNS |
| `lookup_ip_geolocation` | `(ip_address: str) → dict` | IP geolocation + threat flags |
| `lookup_phone_osint` | `(phone_number: str) → dict` | Phone number intelligence |
| `TOOL_REGISTRY` | `dict[str, callable]` | Map of tool names → functions for the agent |

**Rules:**
- Every function must try live API first, then fallback
- Every function must return the standard schema (see 04_PROJECT_RULES.md §2.3)
- Timeout for live API calls: 5 seconds max
- Never raise exceptions to the caller — always return a valid response dict

### 2.3 `agent.py` — Intelligence Engine Contract

**Exports:**

| Name | Signature | Description |
|---|---|---|
| `run_trace` | `(entity: str, api_key: str, callback: callable) → dict` | Main entry point for autonomous investigation |
| `TOOL_DECLARATIONS` | `list[dict]` | Gemini function declaration schemas |

**`run_trace` return schema:**

```python
{
    "success": True/False,
    "entity": "original input",
    "briefing": "FIR-formatted police briefing text",
    "risk_score": 0-100,
    "risk_label": "CRITICAL|HIGH|MEDIUM|LOW",
    "timeline": [
        {"timestamp": "ISO-8601", "event": "description", "source": "tool_name"}
    ],
    "graph": {
        "nodes": [...],
        "edges": [...]
    },
    "tool_calls": [
        {"tool": "name", "input": "query", "status": "success|fallback"}
    ],
    "recommendations": ["action item 1", "action item 2"],
    "raw_evidence": { ... }
}
```

**`callback` function:** Called by the agent during execution to report progress:

```python
def callback(event_type: str, data: dict):
    """
    event_type: "thinking" | "tool_call" | "tool_result" | "synthesis" | "error"
    data: { "message": "...", ... }
    """
```

### 2.4 `app.py` — UI Layer Contract

**Imports from:**
- `cases.py`: `CASES`, `get_case`, `GRAPH_STYLES`
- `tools.py`: (not directly — accessed via agent)
- `agent.py`: `run_trace`

**Streamlit Session State Keys:**

| Key | Type | Description |
|---|---|---|
| `api_key` | `str` | Gemini API key |
| `trace_result` | `dict or None` | Latest trace result from agent |
| `trace_log` | `list[str]` | Terminal-style execution log |
| `selected_case` | `str or None` | Currently selected case study ID |

---

## 3. Adding a New OSINT Tool

To add a new tool (e.g., `lookup_social_media`):

### Step 1: Add Fallback Data to `cases.py`

```python
# In FALLBACK_DATA dict
"lookup_social_media:@suspect_handle": {
    "status": "fallback",
    "query": "@suspect_handle",
    "evidence": { ... },
    "risk_score": 65,
    "graph": { "nodes": [...], "edges": [...] }
}
```

### Step 2: Implement the Tool in `tools.py`

```python
def lookup_social_media(handle: str) -> dict:
    """Analyze social media handle for threat indicators."""
    # 1. Validate input
    # 2. Try live API
    # 3. Fallback to cases.get_fallback()
    # 4. Return standard schema
```

### Step 3: Register with the Agent in `agent.py`

Add the function declaration to `TOOL_DECLARATIONS` and add the function to the tool dispatch map.

### Step 4: Test

```powershell
python -c "from tools import lookup_social_media; import json; print(json.dumps(lookup_social_media('@suspect'), indent=2))"
```

---

## 4. Vis.js Graph Integration

The graph is rendered as a self-contained HTML page embedded via `streamlit.components.v1.html()`.

### Data Flow

```
agent.py returns graph JSON
    │
    ▼
app.py serializes to JavaScript
    │
    ▼
HTML template with Vis.js CDN
    │
    ▼
streamlit.components.v1.html(html_string, height=600)
    │
    ▼
Interactive graph in iframe
```

### Graph HTML Template Structure

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style> /* dark theme styles */ </style>
</head>
<body>
    <div id="graph" style="width:100%; height:580px;"></div>
    <script>
        var nodes = new vis.DataSet(/* injected from Python */);
        var edges = new vis.DataSet(/* injected from Python */);
        var network = new vis.Network(container, {nodes, edges}, options);
    </script>
</body>
</html>
```

---

## 5. Report Export Implementation

### HTML Report
- Uses Jinja2 template with inline CSS (no external stylesheets)
- Self-contained single HTML file
- Dark theme matching the app
- Includes base64-encoded graph screenshot placeholder

### Markdown Report
- Clean markdown with tables and headers
- Compatible with GitHub rendering
- Includes text-based entity table (no graph)

### PDF Export
- Generated via the HTML report + browser's native "Print to PDF"
- `app.py` provides a "Print Report" button that opens the HTML in a new tab
- No `wkhtmltopdf` or `weasyprint` dependency needed

---

## 6. Error Handling Patterns

### Tool-Level Error Handling

```python
def lookup_tool(input_param: str) -> dict:
    try:
        # Validate input
        if not is_valid(input_param):
            return _error_response(input_param, "Invalid input format")

        # Try live API
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return _parse_live_response(response.json())

    except requests.exceptions.Timeout:
        return _get_fallback_or_error(input_param, "API timeout")

    except requests.exceptions.ConnectionError:
        return _get_fallback_or_error(input_param, "No network")

    except Exception as e:
        return _get_fallback_or_error(input_param, str(e))
```

### Agent-Level Error Handling

```python
def run_trace(entity: str, api_key: str, callback) -> dict:
    try:
        # Normal Gemini function-calling loop
        ...
    except google.api_core.exceptions.ResourceExhausted:
        callback("error", {"message": "API quota exceeded — using template synthesis"})
        return _template_synthesis(entity, collected_evidence)
    except Exception as e:
        callback("error", {"message": f"Engine error: {e}"})
        return _fallback_trace(entity)
```

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
