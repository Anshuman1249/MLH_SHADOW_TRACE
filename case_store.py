"""
ShadowTrace — Saved Cases Storage Helper
Allows saving, naming, and loading custom investigation cases to saved_cases.json.
Provides cross-referencing across saved investigation files.
"""

import json
import os
from datetime import datetime, timezone

SAVED_CASES_FILE = os.path.join(os.path.dirname(__file__), "saved_cases.json")


def load_saved_cases() -> dict:
    """Load user-saved cases from disk. Returns dict of case_id -> case_dict."""
    if not os.path.exists(SAVED_CASES_FILE):
        return {}
    try:
        with open(SAVED_CASES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_case_to_file(case_name: str, primary_entity: str, trace_result: dict) -> str:
    """Save an active investigation with custom name into saved_cases.json."""
    cases = load_saved_cases()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    case_id = f"custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    graph = trace_result.get("graph", {})
    all_entities = {}
    for n in graph.get("nodes", []):
        ntype = n.get("type", "unknown")
        all_entities.setdefault(ntype, []).append(n.get("id"))

    new_case = {
        "id": case_id,
        "codename": case_name.strip() or f"Case #{len(cases) + 500}",
        "status": "Archived Case File",
        "created_at": now_str,
        "classification": trace_result.get("case_type", "Cyber Investigation"),
        "summary": trace_result.get("briefing", "")[:350] + "...",
        "primary_entity": primary_entity,
        "risk_score": trace_result.get("risk_score"),
        "risk_label": trace_result.get("risk_label", "INSUFFICIENT DATA"),
        "all_entities": all_entities,
        "timeline": trace_result.get("timeline", []),
        "graph": graph,
        "recommendations": trace_result.get("recommendations", []),
        "briefing": trace_result.get("briefing", ""),
    }

    cases[case_id] = new_case
    with open(SAVED_CASES_FILE, "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2)

    return case_id


def delete_saved_case(case_id: str) -> bool:
    """Delete a saved case by ID."""
    cases = load_saved_cases()
    if case_id in cases:
        del cases[case_id]
        with open(SAVED_CASES_FILE, "w", encoding="utf-8") as f:
            json.dump(cases, f, indent=2)
        return True
    return False


def find_connected_cases(entity: str) -> list:
    """Check if an entity or wallet appears in any previously saved case archive."""
    entity_clean = entity.strip().lower()
    matches = []
    cases = load_saved_cases()
    for cid, c in cases.items():
        if entity_clean == c.get("primary_entity", "").lower():
            matches.append((cid, c.get("codename", cid), "Primary Target Match"))
            continue
        # Search nodes
        for n in c.get("graph", {}).get("nodes", []):
            nid = n.get("id", "").lower()
            if entity_clean in nid or nid in entity_clean:
                matches.append((cid, c.get("codename", cid), f"Connected Node ({n.get('type')})"))
                break
    return matches
