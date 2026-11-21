"""
ShadowTrace — Intelligence Engine
Orchestrates live OSINT lookups, multi-hop expansion, and Gemini report synthesis.
Gemini acts as the report writer only — grounded strictly in verified findings.
"""

import os
import json
import re
import requests
from datetime import datetime, timezone
from typing import Callable, Optional

from cases import CASES, get_case, get_case_for_entity, get_all_case_tools
from tools import TOOL_REGISTRY
from entity_detector import detect_and_normalize_entity

PRIMARY_GEMINI_MODEL = "gemini-flash-lite-latest"


def _risk_label(score: Optional[int]) -> str:
    if score is None:
        return "INSUFFICIENT DATA"
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def run_trace(entity_input: str, api_key: str, callback: Callable) -> dict:
    """Run an autonomous investigation trace on any suspect entity."""
    raw_input = entity_input.strip()
    category, normalized_val, human_label = detect_and_normalize_entity(raw_input)
    
    callback("thinking", {"message": f"Classified Input: [{category.upper()}] -> Normalized: {normalized_val}"})

    # Check pre-seeded case
    case = get_case_for_entity(raw_input) or get_case_for_entity(normalized_val)
    if case:
        callback("thinking", {"message": f"Matching verified syndicate file: {case['codename']} ({case['id']})"})
        calls = get_all_case_tools(case)
    else:
        # Determine execution based on entity category
        dispatch_map = {
            "evm_wallet": [("lookup_crypto_wallet", {"address": normalized_val, "chain": "ETH"})],
            "tron_wallet": [("lookup_crypto_wallet", {"address": normalized_val, "chain": "TRON"})],
            "btc_wallet": [("lookup_crypto_wallet", {"address": normalized_val, "chain": "BTC"})],
            "upi": [("lookup_upi_osint", {"upi_id": normalized_val})],
            "telegram": [("lookup_telegram_threat_intel", {"handle_or_channel": normalized_val})],
            "phone": [("lookup_phone_osint", {"phone_number": normalized_val})],
            "domain": [("lookup_domain_whois_dns", {"domain": normalized_val})],
            "ip": [("lookup_ip_geolocation", {"ip_address_str": normalized_val})],
        }
        calls = list(dispatch_map.get(category, [("lookup_domain_whois_dns", {"domain": normalized_val})]))

    all_evidence = []
    all_nodes = []
    all_edges = []
    tool_calls_log = []

    # Logger callback wrapper
    def _tool_log(msg: str):
        callback("thinking", {"message": f"📡 {msg}"})

    for tool_name, args in calls:
        callback("tool_call", {"message": f"Executing {tool_name}({json.dumps(args)})"})
        try:
            # Inject log_fn if accepted
            if tool_name in TOOL_REGISTRY:
                result = TOOL_REGISTRY[tool_name](**args, log_fn=_tool_log)
            else:
                result = {"status": "error", "error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            result = {"status": "error", "error": str(e), "graph": {"nodes": [], "edges": []}}

        all_evidence.append(result)
        if isinstance(result, dict):
            all_nodes.extend(result.get("graph", {}).get("nodes", []))
            all_edges.extend(result.get("graph", {}).get("edges", []))
            status = result.get("status", "unknown")
        else:
            status = "error"

        tool_calls_log.append({"tool": tool_name, "input": json.dumps(args), "status": status})
        callback("tool_result", {"message": f"{tool_name} -> {status}", "tool": tool_name, "status": status})

    # If case exists, include its verified multi-hop graph
    if case:
        case_graph = case.get("graph", {})
        all_nodes = case_graph.get("nodes", []) + all_nodes
        all_edges = case_graph.get("edges", []) + all_edges

    unique_nodes = _deduplicate_nodes(all_nodes)
    unique_edges = _deduplicate_edges(all_edges)

    # Determine risk score based on rule-based calculation
    risk_scores = [e.get("risk_score") for e in all_evidence if isinstance(e, dict) and e.get("risk_score") is not None]
    
    # If all tools reported insufficient data or empty
    if not risk_scores:
        risk_score = None
        risk_lbl = "INSUFFICIENT DATA"
    else:
        risk_score = max(risk_scores)
        risk_lbl = _risk_label(risk_score)

    callback("synthesis", {"message": "Drafting Evidence-Grounded Forensic Dossier..."})

    # Try Gemini report writer with strict grounding prompt
    briefing = _synthesize_report_with_gemini(
        entity=normalized_val,
        category=category,
        evidence=all_evidence,
        case=case,
        risk_score=risk_score,
        risk_lbl=risk_lbl,
        api_key=api_key,
        log_fn=_tool_log,
    )

    timeline = _merge_timelines(all_evidence, case)
    recommendations = _build_evidence_based_recommendations(category, risk_score, all_evidence, case)

    return {
        "success": True,
        "entity": normalized_val,
        "original_input": raw_input,
        "category": category,
        "human_label": human_label,
        "briefing": briefing,
        "risk_score": risk_score,
        "risk_label": risk_lbl,
        "case_type": case.get("classification", _classify_case_type(category, risk_score)) if case else _classify_case_type(category, risk_score),
        "timeline": timeline,
        "graph": {"nodes": unique_nodes, "edges": unique_edges},
        "tool_calls": tool_calls_log,
        "recommendations": recommendations,
        "raw_evidence": all_evidence,
    }


def _synthesize_report_with_gemini(entity: str, category: str, evidence: list, case: Optional[dict],
                                    risk_score: Optional[int], risk_lbl: str, api_key: str, log_fn: Callable) -> str:
    """Pass verified findings to Gemini. Grounded strictly in JSON evidence without hallucinating statutes."""
    # Build facts payload
    clean_findings = []
    for e in evidence:
        if isinstance(e, dict) and "evidence" in e:
            clean_findings.append({
                "source": e.get("evidence", {}).get("details", {}).get("source", "Telemetry"),
                "summary": e.get("evidence", {}).get("summary"),
                "indicators": e.get("evidence", {}).get("risk_indicators", []),
            })

    # If empty findings, write strict no-adverse text
    if not clean_findings or risk_lbl == "INSUFFICIENT DATA":
        return (
            f"### 📋 INVESTIGATION SUMMARY\n\n"
            f"**Subject:** `{entity}` | **Status:** `NO ADVERSE FINDINGS`\n\n"
            f"No adverse findings from the public sources and blockchain nodes queried. "
            f"The subject vector currently exhibits no confirmed transaction history, scam alerts, or mixer interaction on record. "
            f"No statutory penal charges are warranted based on the presently available evidentiary records."
        )

    # Prompt Gemini if API key is provided
    if api_key and len(api_key.strip()) > 10:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{PRIMARY_GEMINI_MODEL}:generateContent"
            headers = {"Content-Type": "application/json", "X-goog-api-key": api_key}
            system_instruction = (
                "You are an expert Cyber Forensic Investigator writing an official briefing for Indian Cyber Crime Police (I4C). "
                "STRICT GROUNDING INSTRUCTIONS:\n"
                "1. Use ONLY the facts provided in the JSON payload. NEVER invent addresses, amounts, or links.\n"
                "2. If findings are empty, state 'No adverse findings from the sources queried'.\n"
                "3. Cite statutory legal provisions (IT Act 66C/66D, BNS 318, PMLA 3) ONLY when specific findings support them "
                "(e.g., mixer interaction supports PMLA; fake UPI mule supports IT Act 66D). If no evidence of fraud exists, cite NO penal charges.\n"
                "4. Use cautious language: 'pattern consistent with', 'observed on-chain interaction'."
            )
            prompt = (
                f"{system_instruction}\n\n"
                f"TARGET ENTITY: {entity} (Category: {category})\n"
                f"RISK INDEX: {risk_score}/100 ({risk_lbl})\n"
                f"FACTUAL FINDINGS:\n{json.dumps(clean_findings, indent=2)}\n\n"
                f"Write a formal, structured police report with markdown sections: "
                f"### 1. Executive Forensic Summary, ### 2. Intercepted Asset Flow, ### 3. Evidence Matrix, ### 4. Applicable Statutory Provisions (only if supported)."
            )
            r = requests.post(url, headers=headers, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=10)
            if r.status_code == 200:
                text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
                return text.strip()
        except Exception as ex:
            log_fn(f"Gemini API writer note: {ex}. Using deterministic forensic synthesis.")

    # Fallback to deterministic evidence-grounded briefing
    return _build_deterministic_briefing(entity, category, clean_findings, case, risk_score, risk_lbl)


def _build_deterministic_briefing(entity: str, category: str, clean_findings: list, case: Optional[dict],
                                  risk_score: Optional[int], risk_lbl: str) -> str:
    now_str = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M UTC")
    ref_id = f"I4C-CFCFRMS/2026/{(abs(hash(entity)) % 8999) + 1000}"

    lines = [
        f"### 🏛️ FIRST INFORMATION FORENSIC BRIEFING",
        f"**Case File Reference:** `{ref_id}` | **Date:** `{now_str}`",
        f"**Subject Vector:** `{entity}` | **Threat Assessment:** `{risk_score or 'N/A'}/100 ({risk_lbl})`",
        "",
        "---",
        "",
        "#### 1. Executive Summary & Observed Evidence",
    ]

    for f in clean_findings:
        lines.append(f"- **{f.get('source', 'Telemetry')}:** {f.get('summary', '')}")

    lines.extend([
        "",
        "#### 2. Key Forensic Triggers",
    ])
    for f in clean_findings:
        for ind in f.get("indicators", []):
            lines.append(f"- {ind}")

    # Cautious legal charges ONLY if evidence supports it
    has_mixer = any("mixer" in str(f).lower() or "privacy" in str(f).lower() for f in clean_findings)
    has_mule = any("mule" in str(f).lower() or "upi" in str(f).lower() for f in clean_findings)
    has_phish = any("phishing" in str(f).lower() or "malicious" in str(f).lower() for f in clean_findings)

    applicable_charges = []
    if has_mule:
        applicable_charges.append("**IT Act 2000, Sec 66D:** Cheating by personation using digital mule account infrastructure.")
    if has_phish:
        applicable_charges.append("**IT Act 2000, Sec 66C & BNS 2023 Sec 318:** Identity theft & fraudulent inducement via phishing conduit.")
    if has_mixer:
        applicable_charges.append("**PMLA 2002, Sec 3 & 4:** Concealment and layering of proceeds of crime via anonymization mixer.")

    if applicable_charges:
        lines.extend([
            "",
            "#### 3. Statutory Indictment (Evidence-Supported)",
        ])
        for chg in applicable_charges:
            lines.append(f"- {chg}")
    else:
        lines.extend([
            "",
            "#### 3. Statutory Indictment",
            "*(No penal charges recommended at this stage. Observed telemetry reveals no confirmed fraud or laundering activities.)*",
        ])

    return "\n".join(lines)


def _classify_case_type(category: str, risk_score: Optional[int]) -> str:
    if risk_score is None:
        return "Unconfirmed / Insufficient Telemetry"
    mapping = {
        "evm_wallet": "Ethereum / EVM Multi-Chain Triage",
        "tron_wallet": "TRON TRC-20 Laundering Triage",
        "btc_wallet": "Bitcoin On-Chain Flow Analysis",
        "upi": "Indian UPI Mule Collection Ring",
        "telegram": "Telegram Cyber Syndicate Intelligence",
        "domain": "Web Phishing Infrastructure Triage",
        "ip": "Command & Control (C2) Server Profiling",
        "phone": "Telecom Subscriber OSINT Investigation",
    }
    return mapping.get(category, "Cyber Crime Financial Investigation")


def _build_evidence_based_recommendations(category: str, risk_score: Optional[int], evidence: list, case: Optional[dict]) -> list:
    if risk_score is None:
        return [
            "Log entity in monitor registry; insufficient historical on-chain activity to justify court summons.",
            "Schedule passive re-check in 72 hours for potential delayed transaction broadcast.",
        ]

    recs = []
    if risk_score >= 70:
        recs.append("Issue immediate Section 94 BNSS 2023 Order to concerned Bank PSP / Exchange Nodal Officer for asset freeze.")
        recs.append("Transmit transaction hashes to I4C Cyber Crime Portal (1930 Helpline) for national lien registration.")
    elif risk_score >= 40:
        recs.append("Request account KYC documentation and subscriber access logs under Section 94 BNSS 2023.")

    if category in ["evm_wallet", "tron_wallet", "btc_wallet"]:
        recs.append("Issue preservation summons to counterparty cryptocurrency exchanges for KYC records.")
    elif category == "upi":
        recs.append("Request NPCI settlement audit trail and linked beneficiary bank account records.")
    elif category == "telegram":
        recs.append("Submit channel takedown notice via LEA portal (telegram.org/tos/law) and extract subscriber metadata.")

    return recs


def _merge_timelines(evidence: list, case: Optional[dict] = None) -> list:
    timeline = []
    if case:
        timeline.extend(case.get("timeline", []))

    for e in evidence:
        if not isinstance(e, dict):
            continue
        details = e.get("evidence", {}).get("details", {})
        ts = details.get("first_seen", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        timeline.append({
            "timestamp": ts,
            "event": f"Active forensic telemetry verified on {e.get('query', 'identifier')}",
            "source": details.get("source", "Live OSINT Engine"),
        })

    timeline.sort(key=lambda x: str(x.get("timestamp", "")))
    return timeline


def _deduplicate_nodes(nodes: list) -> list:
    seen = set()
    unique = []
    for n in nodes:
        nid = n.get("id", "")
        if nid and nid not in seen:
            seen.add(nid)
            unique.append(n)
    return unique


def _deduplicate_edges(edges: list) -> list:
    seen = set()
    unique = []
    for e in edges:
        key = (e.get("source", ""), e.get("target", ""), e.get("relation", ""))
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique
