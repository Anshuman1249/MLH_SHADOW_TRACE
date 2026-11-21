# 🧪 ShadowTrace — Testing Guide

**Document ID:** ST-TEST-008  
**Version:** 1.0.0  

---

## 1. Testing Strategy

### 1.1 Testing Pyramid

```
        ┌───────────┐
        │  Demo     │  ← Full 3-minute pitch simulation
        │  Test     │
        ├───────────┤
        │Integration│  ← End-to-end trace with both cases
        │  Tests    │
        ├───────────┤
        │  Module   │  ← Each component in isolation
        │  Tests    │
        ├───────────┤
        │  Unit     │  ← Individual functions
        │  Tests    │
        └───────────┘
```

### 1.2 Testing Modes

| Mode | Network | API Keys | Purpose |
|---|---|---|---|
| **Online** | Available | Provided | Verify live API integration |
| **Offline** | Disconnected | Not required | Verify fallback resilience (critical for demo) |
| **Hybrid** | Available | Partial | Verify graceful degradation per-tool |

---

## 2. Unit Tests

### 2.1 `cases.py` Tests

```powershell
# Verify all cases load correctly
python -c "from cases import CASES; print(f'Cases loaded: {list(CASES.keys())}')"

# Verify fallback data coverage
python -c "from cases import FALLBACK_DATA; print(f'Fallback entries: {len(FALLBACK_DATA)}')"

# Verify graph styles defined
python -c "from cases import GRAPH_STYLES; print(f'Graph styles: {list(GRAPH_STYLES.keys())}')"

# Verify specific case structure
python -c "from cases import get_case; import json; c = get_case('case_409'); print(json.dumps(list(c.keys()), indent=2))"
```

### 2.2 `tools.py` Tests

Test each tool individually with both live and fallback modes:

```powershell
# Test crypto wallet lookup (will use fallback if no network)
python -c "from tools import lookup_crypto_wallet; import json; r = lookup_crypto_wallet('TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1', 'TRON'); print(json.dumps(r, indent=2))"

# Test UPI OSINT lookup
python -c "from tools import lookup_upi_osint; import json; r = lookup_upi_osint('rajeshk.mule03@ybl'); print(json.dumps(r, indent=2))"

# Test Telegram threat intel
python -c "from tools import lookup_telegram_threat_intel; import json; r = lookup_telegram_threat_intel('@earnmoneyfast_bot'); print(json.dumps(r, indent=2))"

# Test domain WHOIS
python -c "from tools import lookup_domain_whois_dns; import json; r = lookup_domain_whois_dns('bijli-pay-india.com'); print(json.dumps(r, indent=2))"

# Test IP geolocation
python -c "from tools import lookup_ip_geolocation; import json; r = lookup_ip_geolocation('103.74.19.104'); print(json.dumps(r, indent=2))"

# Test phone OSINT
python -c "from tools import lookup_phone_osint; import json; r = lookup_phone_osint('+918234567890'); print(json.dumps(r, indent=2))"
```

### 2.3 Validation Checks

For each tool output, verify:

```powershell
# Schema validation script
python -c "
from tools import lookup_crypto_wallet
r = lookup_crypto_wallet('TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1', 'TRON')
assert 'status' in r, 'Missing status field'
assert r['status'] in ('live', 'fallback'), f'Invalid status: {r[\"status\"]}'
assert 'evidence' in r, 'Missing evidence field'
assert 'risk_score' in r, 'Missing risk_score field'
assert 0 <= r['risk_score'] <= 100, f'Risk score out of range: {r[\"risk_score\"]}'
assert 'graph' in r, 'Missing graph field'
assert 'nodes' in r['graph'], 'Missing graph nodes'
assert 'edges' in r['graph'], 'Missing graph edges'
assert len(r['graph']['nodes']) > 0, 'Empty graph nodes'
print('All schema checks PASSED')
"
```

---

## 3. Module Tests

### 3.1 Agent Module Test

```powershell
# Test agent with a pre-seeded case entity (requires API key)
python -c "
import os
from agent import run_trace
def log(event_type, data):
    print(f'[{event_type}] {data.get(\"message\", \"\")}')

# Uses GEMINI_API_KEY env var or will fail gracefully
api_key = os.environ.get('GEMINI_API_KEY', '')
if api_key:
    result = run_trace('TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1', api_key, log)
    print(f'Success: {result[\"success\"]}')
    print(f'Risk Score: {result[\"risk_score\"]}')
    print(f'Graph Nodes: {len(result[\"graph\"][\"nodes\"])}')
    print(f'Graph Edges: {len(result[\"graph\"][\"edges\"])}')
else:
    print('No API key — skipping live agent test')
"
```

### 3.2 Report Export Test

```powershell
# Test HTML report generation
python -c "
from app import generate_html_report
# (requires a trace_result dict — test with mock data)
print('Report generation function exists and is callable')
"
```

---

## 4. Integration Tests

### 4.1 Full Trace — Case #409 (Operation DhanChor)

```powershell
# End-to-end test with Case #409
python -c "
from cases import get_case
from agent import run_trace
import os, json

case = get_case('case_409')
entity = case['primary_entity']
api_key = os.environ.get('GEMINI_API_KEY', '')

log_entries = []
def log(event_type, data):
    log_entries.append(f'[{event_type}] {data}')

result = run_trace(entity, api_key, log)

# Validation
assert result['success'], 'Trace failed'
assert result['risk_score'] >= 50, f'Risk score too low for known fraud case: {result[\"risk_score\"]}'
assert len(result['graph']['nodes']) >= 5, f'Too few graph nodes: {len(result[\"graph\"][\"nodes\"])}'
assert len(result['graph']['edges']) >= 4, f'Too few graph edges: {len(result[\"graph\"][\"edges\"])}'
assert len(result['briefing']) > 100, 'Briefing too short'
assert len(result['timeline']) >= 3, f'Too few timeline entries: {len(result[\"timeline\"])}'

print('Case #409 Integration Test: ALL CHECKS PASSED')
print(f'  Nodes: {len(result[\"graph\"][\"nodes\"])}')
print(f'  Edges: {len(result[\"graph\"][\"edges\"])}')
print(f'  Risk Score: {result[\"risk_score\"]}')
print(f'  Tool Calls: {len(result[\"tool_calls\"])}')
"
```

### 4.2 Full Trace — Case #102 (Operation Vidyut)

```powershell
# Same structure as above with case_102 entity
python -c "
from cases import get_case
from agent import run_trace
import os

case = get_case('case_102')
entity = case['primary_entity']
api_key = os.environ.get('GEMINI_API_KEY', '')

result = run_trace(entity, api_key, lambda t, d: None)

assert result['success'], 'Trace failed'
assert result['risk_score'] >= 50, 'Risk score too low for known fraud case'
assert len(result['graph']['nodes']) >= 5, 'Too few graph nodes'

print('Case #102 Integration Test: ALL CHECKS PASSED')
"
```

---

## 5. Offline Resilience Test

This is the most critical test for the hackathon demo.

### 5.1 Network Disconnection Test

```powershell
# Step 1: Disconnect from network (disable Wi-Fi / unplug Ethernet)
# Step 2: Run the full trace
python -c "
from agent import run_trace
result = run_trace('TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1', '', lambda t, d: print(f'[{t}] {d}'))
assert result['success'], 'Offline trace should still succeed with fallback data'
print('OFFLINE TEST PASSED')
"
# Step 3: Reconnect network
```

### 5.2 Partial Network Test

Verify each tool degrades individually:

```powershell
# Set an invalid API key to force Gemini fallback
python -c "
from agent import run_trace
result = run_trace('rajeshk.mule03@ybl', 'invalid-key', lambda t, d: None)
assert result['success'], 'Should succeed even with invalid API key'
print('INVALID KEY FALLBACK TEST PASSED')
"
```

---

## 6. UI/UX Tests

### 6.1 Manual Checklist

| # | Test | Expected Result | ✅/❌ |
|---|---|---|---|
| 1 | Launch app with `streamlit run app.py` | Dark themed UI loads without errors | |
| 2 | Enter API key in sidebar | Key stored, no visible echo | |
| 3 | Select "Operation DhanChor" from dropdown | Entity field auto-populates | |
| 4 | Click "Autonomous Trace" | Thought trace panel shows real-time progress | |
| 5 | Graph renders after trace completes | ≥ 12 nodes, interactive drag/zoom | |
| 6 | Hover over graph nodes | Tooltip shows entity details | |
| 7 | Dossier panel shows formatted report | Executive summary, timeline, risk score | |
| 8 | Click "Export HTML" | HTML file downloads | |
| 9 | Click "Export Markdown" | MD file downloads | |
| 10 | Click "Export PDF" | Printable HTML opens in new tab | |
| 11 | Repeat steps 3-10 with "Operation Vidyut" | Same quality, different data | |
| 12 | Enter custom entity (e.g., random crypto address) | Tool executes, results display | |
| 13 | Test with no API key | Graceful error message, suggest entering key | |
| 14 | Test with no network | Fallback data used, all features work | |

### 6.2 Projector Readability Test

| Element | Minimum Size | Check |
|---|---|---|
| Body text | 14px | Readable from 3 meters |
| Headings | 20px+ | Clearly visible |
| Graph labels | 12px+ | Readable when zoomed to fit |
| Button text | 14px | Clearly clickable |
| Risk score | 24px+ | Prominent display |

---

## 7. Performance Benchmarks

| Metric | Target | Measurement |
|---|---|---|
| Cold start (Streamlit launch) | < 10 seconds | `Measure-Command { streamlit run app.py }` |
| Pre-seeded case trace (online) | < 60 seconds | Stopwatch from button click to graph render |
| Pre-seeded case trace (offline) | < 30 seconds | Stopwatch from button click to graph render |
| Graph render time | < 2 seconds | From data load to interactive graph |
| Report export | < 1 second | From button click to download prompt |

---

## 8. Pre-Demo Checklist

Run through this checklist 30 minutes before the pitch:

- [ ] Virtual environment activated
- [ ] `streamlit run app.py` launches without errors
- [ ] API key entered and working
- [ ] Case #409 trace completes successfully
- [ ] Case #102 trace completes successfully
- [ ] Graph is interactive (drag a node to verify)
- [ ] Export buttons produce downloadable files
- [ ] Font size adequate for projector
- [ ] Browser in full-screen mode (F11)
- [ ] Backup plan: disconnect network, verify offline mode works

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
