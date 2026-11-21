# 📊 ShadowTrace — Task Breakdown & Development Phases

**Document ID:** ST-TASKS-005  
**Version:** 1.0.0  

---

## 1. Development Phases Overview

```
Phase 1: Foundation        Phase 2: Intelligence       Phase 3: Interface        Phase 4: Polish
(Setup + Data)             (Tools + Engine)             (UI + Graph)              (Test + Demo)
  │                          │                            │                         │
  ├─ requirements.txt        ├─ tools.py (6 tools)        ├─ app.py (Streamlit)     ├─ Integration test
  ├─ cases.py (2 cases)      ├─ agent.py (Gemini)         ├─ Vis.js graph           ├─ Offline test
  ├─ Project docs            ├─ Fallback data wiring      ├─ Report export          ├─ Demo rehearsal
  └─ Directory structure     └─ Tool testing              ├─ Dark theme CSS         └─ Pitch script
                                                          └─ Thought trace panel
```

---

## 2. Detailed Task List

### Phase 1: Foundation (Setup + Data Layer)

| Task ID | Task | File(s) | Status | Dependencies |
|---|---|---|---|---|
| T-1.1 | Create project directory structure | `docs/`, root files | ⬜ Pending | None |
| T-1.2 | Write `requirements.txt` with Windows-safe packages | `requirements.txt` | ⬜ Pending | None |
| T-1.3 | Create all documentation files | `docs/*.md` | 🟢 In Progress | None |
| T-1.4 | Build Case #409 "Operation DhanChor" data | `cases.py` | ⬜ Pending | None |
| T-1.5 | Build Case #102 "Operation Vidyut" data | `cases.py` | ⬜ Pending | None |
| T-1.6 | Define fallback mock datasets for all case entities | `cases.py` | ⬜ Pending | T-1.4, T-1.5 |
| T-1.7 | Define graph schema (node types, edge types, colors) | `cases.py` | ⬜ Pending | None |
| T-1.8 | Write CASE_STUDIES.md with pitch script | `CASE_STUDIES.md` | ⬜ Pending | T-1.4, T-1.5 |
| T-1.9 | Set up Python virtual environment | Local setup | ⬜ Pending | T-1.2 |

### Phase 2: Intelligence Layer (OSINT Tools + AI Engine)

| Task ID | Task | File(s) | Status | Dependencies |
|---|---|---|---|---|
| T-2.1 | Implement `lookup_crypto_wallet()` | `tools.py` | ⬜ Pending | T-1.6 |
| T-2.2 | Implement `lookup_upi_osint()` | `tools.py` | ⬜ Pending | T-1.6 |
| T-2.3 | Implement `lookup_telegram_threat_intel()` | `tools.py` | ⬜ Pending | T-1.6 |
| T-2.4 | Implement `lookup_domain_whois_dns()` | `tools.py` | ⬜ Pending | T-1.6 |
| T-2.5 | Implement `lookup_ip_geolocation()` | `tools.py` | ⬜ Pending | T-1.6 |
| T-2.6 | Implement `lookup_phone_osint()` | `tools.py` | ⬜ Pending | T-1.6 |
| T-2.7 | Test each tool individually (live + fallback) | `tools.py` | ⬜ Pending | T-2.1 to T-2.6 |
| T-2.8 | Configure Gemini with forensic investigator persona | `agent.py` | ⬜ Pending | T-1.2 |
| T-2.9 | Register 6 tools as Gemini function declarations | `agent.py` | ⬜ Pending | T-2.7 |
| T-2.10 | Build autonomous execution loop | `agent.py` | ⬜ Pending | T-2.9 |
| T-2.11 | Implement report synthesis (briefing + risk score + graph) | `agent.py` | ⬜ Pending | T-2.10 |
| T-2.12 | Add error handling and fallback synthesis | `agent.py` | ⬜ Pending | T-2.11 |
| T-2.13 | Test agent with both pre-seeded cases | `agent.py` | ⬜ Pending | T-2.12 |

### Phase 3: Interface Layer (Streamlit UI + Graph)

| Task ID | Task | File(s) | Status | Dependencies |
|---|---|---|---|---|
| T-3.1 | Create Streamlit app scaffold with page config | `app.py` | ⬜ Pending | T-1.2 |
| T-3.2 | Implement dark forensic theme CSS | `app.py` | ⬜ Pending | T-3.1 |
| T-3.3 | Build sidebar (API key, case dropdown, about) | `app.py` | ⬜ Pending | T-3.1 |
| T-3.4 | Build entity input bar and trace button | `app.py` | ⬜ Pending | T-3.3 |
| T-3.5 | Build Vis.js graph component (HTML embed) | `app.py` | ⬜ Pending | T-3.1 |
| T-3.6 | Build thought trace panel (terminal-style) | `app.py` | ⬜ Pending | T-3.4 |
| T-3.7 | Build forensic dossier panel | `app.py` | ⬜ Pending | T-2.11 |
| T-3.8 | Implement HTML report export | `app.py` | ⬜ Pending | T-3.7 |
| T-3.9 | Implement Markdown report export | `app.py` | ⬜ Pending | T-3.7 |
| T-3.10 | Implement PDF export (browser print-to-PDF) | `app.py` | ⬜ Pending | T-3.8 |
| T-3.11 | Wire agent.py to Streamlit UI | `app.py` | ⬜ Pending | T-2.13, T-3.6 |
| T-3.12 | Pre-load case studies into dropdown | `app.py` | ⬜ Pending | T-1.8 |

### Phase 4: Polish & Demo Preparation

| Task ID | Task | File(s) | Status | Dependencies |
|---|---|---|---|---|
| T-4.1 | Full integration test (both cases, live API) | All | ⬜ Pending | T-3.11 |
| T-4.2 | Offline resilience test (disconnect network, run both cases) | All | ⬜ Pending | T-4.1 |
| T-4.3 | UI polish pass (spacing, colors, font sizes for projector) | `app.py` | ⬜ Pending | T-4.1 |
| T-4.4 | Performance optimization (< 60s trace time) | `agent.py`, `tools.py` | ⬜ Pending | T-4.1 |
| T-4.5 | Rehearse 3-minute pitch with stopwatch | Presentation | ⬜ Pending | T-4.3 |
| T-4.6 | Final documentation review | `docs/*.md` | ⬜ Pending | T-4.3 |
| T-4.7 | Create `.gitignore` and clean repository | Root | ⬜ Pending | T-4.6 |

---

## 3. Dependency Graph

```
T-1.1 ──→ T-1.2 ──→ T-1.9
  │          │
  ▼          ▼
T-1.3    T-1.4 + T-1.5
              │
              ▼
           T-1.6 ──→ T-1.7
              │
              ├──→ T-2.1 through T-2.6 (parallel)
              │         │
              │         ▼
              │      T-2.7 ──→ T-2.9 ──→ T-2.10 ──→ T-2.11 ──→ T-2.12 ──→ T-2.13
              │                                          │
              ▼                                          ▼
           T-1.8                    T-3.1 ──→ T-3.2 through T-3.6 (parallel)
                                                 │
                                                 ▼
                                    T-3.7 ──→ T-3.8/T-3.9/T-3.10 ──→ T-3.11 ──→ T-3.12
                                                                          │
                                                                          ▼
                                                               T-4.1 through T-4.7 (sequential)
```

---

## 4. Effort Estimates

| Phase | Tasks | Estimated Time |
|---|---|---|
| Phase 1: Foundation | 9 tasks | ~1.5 hours |
| Phase 2: Intelligence | 13 tasks | ~3 hours |
| Phase 3: Interface | 12 tasks | ~2.5 hours |
| Phase 4: Polish | 7 tasks | ~1.5 hours |
| **Total** | **41 tasks** | **~8.5 hours** |

---

## 5. Critical Path

The critical path (longest dependency chain determining minimum completion time):

```
T-1.2 → T-1.4 → T-1.6 → T-2.1 → T-2.7 → T-2.9 → T-2.10 → T-2.11 → T-2.13 → T-3.11 → T-4.1 → T-4.5
```

**Mitigation:** Parallelize Phase 2 tool implementations (T-2.1 through T-2.6) and Phase 3 UI components (T-3.2 through T-3.6).

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
