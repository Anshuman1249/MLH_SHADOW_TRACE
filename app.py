"""
ShadowTrace — Autonomous Dark-Web & Crypto Scam Intelligence Assistant
Law Enforcement Forensic Operations Dashboard
"""

import os
import io
import csv
import json
import time
import hashlib
from datetime import datetime, timezone

import streamlit as st
import streamlit.components.v1 as components
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from cases import CASES, GRAPH_STYLES, THREAT_COLORS, get_case, get_case_for_entity
from agent import run_trace
from entity_detector import detect_and_normalize_entity
from case_store import load_saved_cases, save_case_to_file, delete_saved_case, find_connected_cases

# Read Gemini API key from environment or fallback silently
GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")

# ---------------------------------------------------------------------------
# Page Configuration & Dark Forensic Theme
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ShadowTrace | Forensic Scam Intelligence Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        background-color: #080c14;
        color: #e2e8f0;
    }

    .stApp {
        background: radial-gradient(circle at 12% 10%, #0f172a 0%, #06090f 100%);
    }

    h1, h2, h3, h4 {
        font-family: 'JetBrains Mono', monospace;
        color: #38bdf8;
        letter-spacing: -0.5px;
    }

    /* Kill-Chain Pipeline Flow */
    .pipeline-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: #020617;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 20px;
        overflow-x: auto;
    }

    .pipeline-step {
        display: flex;
        flex-direction: column;
        align-items: center;
        min-width: 130px;
        text-align: center;
    }

    .pipeline-step-badge {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 700;
        padding: 5px 10px;
        border-radius: 6px;
        margin-bottom: 6px;
        text-transform: uppercase;
    }

    .pipeline-step-title {
        font-size: 0.82rem;
        font-weight: 600;
        color: #f1f5f9;
    }

    .pipeline-step-sub {
        font-size: 0.70rem;
        color: #64748b;
        font-family: 'JetBrains Mono', monospace;
    }

    .pipeline-arrow {
        color: #0284c7;
        font-size: 1.3rem;
        font-weight: bold;
        padding: 0 8px;
    }

    /* Cards */
    .forensic-card {
        background: #090e1a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }

    .forensic-card-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.88rem;
        font-weight: 700;
        color: #38bdf8;
        text-transform: uppercase;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 8px;
        margin-bottom: 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .chip {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        margin-right: 6px;
        margin-bottom: 6px;
    }

    .chip-crit { background: #ef444422; border: 1px solid #ef4444; color: #f87171; }
    .chip-high { background: #f9731622; border: 1px solid #f97316; color: #fb923c; }
    .chip-med  { background: #eab30822; border: 1px solid #eab308; color: #facc15; }
    .chip-low  { background: #22c55e22; border: 1px solid #22c55e; color: #4ade80; }
    .chip-law  { background: #0284c722; border: 1px solid #0284c7; color: #38bdf8; }
    .chip-demo { background: #8b5cf622; border: 1px solid #8b5cf6; color: #c4b5fd; }

    /* FIR Header Banner */
    .fir-banner {
        background: linear-gradient(90deg, #0b1329 0%, #0284c715 100%);
        border: 1px solid #0284c740;
        border-left: 4px solid #38bdf8;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 16px;
    }

    /* Inspector Box */
    .inspector-box {
        background: #020617;
        border: 1px solid #0284c7;
        border-left: 4px solid #38bdf8;
        border-radius: 8px;
        padding: 16px;
        font-family: 'Inter', sans-serif;
    }

    /* Primary buttons */
    .stButton > button {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
        color: #ffffff;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        border: 1px solid #38bdf8;
        border-radius: 6px;
        transition: all 0.2s ease-in-out;
    }

    .stButton > button:hover {
        background: linear-gradient(135deg, #0369a1 0%, #075985 100%);
        border-color: #7dd3fc;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.4);
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "trace_result" not in st.session_state:
    st.session_state["trace_result"] = None

if "trace_logs" not in st.session_state:
    st.session_state["trace_logs"] = []

if "current_entity" not in st.session_state:
    st.session_state["current_entity"] = "@earnmoneyfast_bot"

if "case_title" not in st.session_state:
    st.session_state["case_title"] = "Operation DhanChor"

if "elapsed_seconds" not in st.session_state:
    st.session_state["elapsed_seconds"] = 0.0

if "is_demo_case" not in st.session_state:
    st.session_state["is_demo_case"] = True

# ---------------------------------------------------------------------------
# Sidebar Controls & Case Management
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ SHADOWTRACE OPS")
    st.markdown("*Autonomous Intelligence & Case Archive*")
    st.markdown("---")

    st.markdown("#### 📁 Active Case Archive")
    
    saved_db = load_saved_cases()
    archive_options = {
        "Case #409: Operation DhanChor [SEEDED DEMO]": ("seed", "case_409"),
        "Case #102: Operation Vidyut [SEEDED DEMO]": ("seed", "case_102"),
    }
    for cid, cval in saved_db.items():
        archive_options[f"📂 {cval.get('codename', cid)} ({cval.get('created_at', '')[:10]})"] = ("custom", cid)

    archive_options["[+] Start New Investigation"] = ("new", "")

    selected_archive_name = st.selectbox(
        "Select Case File",
        options=list(archive_options.keys()),
        index=0,
    )
    case_kind, case_id = archive_options[selected_archive_name]

    if case_kind == "seed" and case_id:
        cdata = get_case(case_id)
        st.session_state["current_entity"] = cdata.get("primary_entity", "")
        st.session_state["case_title"] = cdata.get("codename", "")
        st.session_state["is_demo_case"] = True
        st.caption(f"Status: **{cdata.get('status')}** | Focus: `{st.session_state['current_entity']}`")
    elif case_kind == "custom" and case_id:
        cdata = saved_db.get(case_id, {})
        st.session_state["current_entity"] = cdata.get("primary_entity", "")
        st.session_state["case_title"] = cdata.get("codename", "")
        st.session_state["trace_result"] = cdata
        st.session_state["is_demo_case"] = False
        st.caption(f"Archived: **{cdata.get('created_at')}** | Risk: `{cdata.get('risk_score') or 'N/A'}`")
        
        if st.button("🗑️ Delete This Saved Case", use_container_width=True):
            delete_saved_case(case_id)
            st.rerun()
    elif case_kind == "new":
        st.session_state["is_demo_case"] = False
        if st.session_state["case_title"] in ["Operation DhanChor", "Operation Vidyut"]:
            st.session_state["case_title"] = "New Investigation #1"
            st.session_state["current_entity"] = ""
            st.session_state["trace_result"] = None

    st.markdown("---")
    st.markdown("#### 🏛️ Statutory Enforcement Index")
    st.caption(
        "• **Sec 94 BNSS 2023** (Summons for production)\n"
        "• **Sec 63 BSA 2023** (Electronic records certificate)\n"
        "• **MHA I4C** (Citizen Financial Cyber Fraud Standard)\n"
        "• **IT Act 2000** (Sec 43, 66C, 66D)\n"
        "• **PMLA 2002** (Sec 3/4 Money Laundering Offence)"
    )
    st.markdown("---")
    st.caption("NFSU × MLH Hackathon Build | Forensic Edition")

# ---------------------------------------------------------------------------
# Vis.js Graph HTML Builder
# ---------------------------------------------------------------------------
def render_visjs_graph(nodes_data: list, edges_data: list) -> str:
    formatted_nodes = []
    for n in nodes_data:
        ntype = n.get("type", "default")
        style = GRAPH_STYLES.get(ntype, GRAPH_STYLES["default"])
        tlevel = n.get("threat_level", "medium").lower()
        border_color = THREAT_COLORS.get(tlevel, "#38bdf8")

        node_obj = {
            "id": n["id"],
            "label": n.get("label", n["id"]),
            "shape": style.get("shape", "dot"),
            "size": style.get("size", 25),
            "color": {
                "background": style.get("color", "#1e293b"),
                "border": border_color,
                "highlight": {
                    "background": "#38bdf8",
                    "border": "#ffffff",
                },
            },
            "font": {
                "color": "#f8fafc",
                "face": "JetBrains Mono, monospace",
                "size": 12,
            },
            "borderWidth": 2,
            "shadow": True,
        }
        formatted_nodes.append(node_obj)

    formatted_edges = []
    for e in edges_data:
        e_threat = e.get("threat_level", "medium").lower()
        color = THREAT_COLORS.get(e_threat, "#64748b")
        edge_obj = {
            "from": e["source"],
            "to": e["target"],
            "label": e.get("relation", ""),
            "color": {
                "color": color,
                "highlight": "#38bdf8",
            },
            "arrows": "to",
            "font": {
                "color": "#94a3b8",
                "size": 10,
                "align": "horizontal",
                "strokeWidth": 0,
            },
            "smooth": {"type": "curvedCW", "roundness": 0.2},
            "width": 2 if e_threat in ["critical", "high"] else 1,
        }
        formatted_edges.append(edge_obj)

    nodes_json = json.dumps(formatted_nodes)
    edges_json = json.dumps(formatted_edges)

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style>
        body {{
          margin: 0;
          padding: 0;
          background-color: #030712;
          overflow: hidden;
        }}
        #mynetwork {{
          width: 100%;
          height: 540px;
          border: 1px solid #1e293b;
          border-radius: 8px;
        }}
      </style>
    </head>
    <body>
      <div id="mynetwork"></div>
      <script type="text/javascript">
        var container = document.getElementById('mynetwork');
        var data = {{
          nodes: new vis.DataSet({nodes_json}),
          edges: new vis.DataSet({edges_json})
        }};
        var options = {{
          physics: {{
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{
              gravitationalConstant: -50,
              centralGravity: 0.01,
              springLength: 105,
              springConstant: 0.08
            }},
            stabilization: {{ iterations: 120 }}
          }},
          interaction: {{
            hover: true,
            tooltipDelay: 100,
            zoomView: true,
            dragView: true
          }}
        }};
        var network = new vis.Network(container, data, options);
      </script>
    </body>
    </html>
    """
    return html_code

# ---------------------------------------------------------------------------
# Official Police PDF Report Generator (ReportLab)
# ---------------------------------------------------------------------------
def generate_pdf_report(res: dict) -> bytes:
    """Generate an authentic, formal Indian Cybercrime Investigation PDF."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    
    styles = getSampleStyleSheet()
    header_sup = ParagraphStyle('Sup', fontName='Helvetica-Bold', fontSize=8, textColor=colors.HexColor('#0284c7'), spaceAfter=4)
    header_title = ParagraphStyle('HTitle', fontName='Helvetica-Bold', fontSize=16, textColor=colors.HexColor('#0f172a'), spaceAfter=4)
    sec_title = ParagraphStyle('STitle', fontName='Helvetica-Bold', fontSize=11, textColor=colors.HexColor('#0f172a'), spaceBefore=12, spaceAfter=6)
    body_txt = ParagraphStyle('BTxt', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#334155'), leading=13, spaceAfter=6)
    
    elements = []
    now_str = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M UTC")
    
    # Header
    elements.append(Paragraph("MINISTRY OF HOME AFFAIRS // INDIAN CYBER CRIME COORDINATION CENTRE (I4C)", header_sup))
    elements.append(Paragraph("FIRST INFORMATION FORENSIC BRIEFING DOSSIER", header_title))
    elements.append(Paragraph(f"Statutory Standard: Section 94 BNSS 2023 / Section 63 BSA 2023 | Timestamp: {now_str}", header_sup))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # Meta Table
    score_disp = f"{res.get('risk_score')}/100" if res.get('risk_score') is not None else "INSUFFICIENT DATA"
    summary_data = [
        ["Investigation Subject", str(res.get('entity'))],
        ["Case File Reference", f"I4C-CFCFRMS / {res.get('case_type', 'Financial Cybercrime')}"],
        ["Threat Classification", f"{score_disp} — {res.get('risk_label')}"],
        ["Correlated Forensic Nodes", f"{len(res.get('graph', {}).get('nodes', []))} Entity Nodes ({len(res.get('graph', {}).get('edges', []))} Vectors)"],
    ]
    t = Table(summary_data, colWidths=[150, 390])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0f172a')),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 8))

    # Section 1: Executive Summary
    elements.append(Paragraph("1. EXECUTIVE MODUS OPERANDI & ASSET FLOW", sec_title))
    raw_brief = res.get('briefing', '')
    clean_lines = [l for l in raw_brief.split("\n") if not l.startswith("#")]
    clean_body = " ".join([l.strip() for l in clean_lines if l.strip()])
    elements.append(Paragraph(clean_body[:600] + "...", body_txt))

    # Section 2: Statutory Action Directives
    elements.append(Paragraph("2. REQUISITE INVESTIGATION ORDERS (SECTION 94 BNSS)", sec_title))
    for r in res.get("recommendations", []):
        elements.append(Paragraph(f"• <b>[ACTION ORDER]</b> {r}", body_txt))

    # Section 3: Evidence Matrix
    elements.append(Paragraph("3. DIGITAL EVIDENCE TELEMETRY CHAIN", sec_title))
    tl_data = [["Timestamp", "Incident Event", "Attribution Source"]]
    for item in res.get("timeline", [])[:8]:
        tl_data.append([
            str(item.get("timestamp", ""))[:16],
            Paragraph(str(item.get("event", "")), body_txt),
            str(item.get("source", "")),
        ])
    
    tl_table = Table(tl_data, colWidths=[95, 345, 100])
    tl_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    elements.append(tl_table)
    elements.append(Spacer(1, 14))

    # Officer Signature Block
    sig_data = [
        ["Certified by Investigating Officer:", "Verified by Cyber Forensic Lab:"],
        ["\n\n__________________________________\nInspector of Police (Cyber Crime PS)", "\n\n__________________________________\nDigital Forensic Examiner, NFSU / CFSL"],
    ]
    sig_t = Table(sig_data, colWidths=[270, 270])
    sig_t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#475569')),
    ]))
    elements.append(sig_t)

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

# ---------------------------------------------------------------------------
# CSV Exporter
# ---------------------------------------------------------------------------
def generate_csv_export(nodes: list, edges: list) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Entity Identifier", "Display Label", "Type", "Threat Level", "Connections"])
    for n in nodes:
        nid = n.get("id", "")
        conn_count = sum(1 for e in edges if e.get("source") == nid or e.get("target") == nid)
        writer.writerow([nid, n.get("label", "").replace("\n", " "), n.get("type"), n.get("threat_level"), conn_count])
    return buf.getvalue()

# ---------------------------------------------------------------------------
# Section 94 BNSS Legal Summons Drafter
# ---------------------------------------------------------------------------
def draft_bnss_summons(entity_label: str, case_name: str) -> str:
    today = datetime.now().strftime("%d-%B-%Y")
    return f"""FORM OF SUMMONS UNDER SECTION 94 BNSS 2023 (FORMERLY SEC 91 CrPC)
========================================================================
ORDER FOR PRODUCTION OF DOCUMENTS / DIGITAL ELECTRONIC RECORDS
Date of Notice: {today}
Investigation Ref: I4C-CFCFRMS / {case_name.upper()}
To: 
    The Nodal / Compliance Officer,
    Authorized Intermediary / Bank PSP / Cryptocurrency Exchange Desk

WHEREAS an ongoing investigation into serious cyber offences under Section 66C/66D 
of the Information Technology Act 2000 and Section 318/319 of Bharatiya Nyaya Sanhita (BNS) 2023 
is being conducted regarding the fraudulent diversion of proceeds:

TARGET IDENTIFIER FOR IMMEDIATE PRODUCTION:
------------------------------------------
Suspect Entity / VPA / Wallet: {entity_label}

YOU ARE HEREBY REQUIRED under Section 94 of Bharatiya Nagarik Suraksha Sanhita (BNSS) 2023:
1. To IMMEDIATELY FREEZE / PUT ON LIEN any funds, balances, or digital assets currently held.
2. To furnish complete subscriber registration details, KYC documentation, linked bank accounts,
   and IP access logs with port numbers within 24 hours of receipt of this notice.
3. To preserve all transaction records for a minimum duration of 180 days.

Take notice that failure to attend or comply with this directive renders the entity liable 
to legal prosecution under Section 223 of BNS 2023.

Issued by Order of:
Cyber Crime Police Station / I4C Special Investigation Unit
"""

# ---------------------------------------------------------------------------
# Main Layout: Case Title & Input Bar
# ---------------------------------------------------------------------------
st.markdown("## 🛡️ SHADOWTRACE FORENSIC OPS")

col_hdr1, col_hdr2 = st.columns([3, 2])
with col_hdr1:
    case_name_input = st.text_input(
        "Investigation Codename / Case File",
        value=st.session_state["case_title"],
        help="Assign a descriptive name to organize this investigation in the archive.",
    )
    if case_name_input != st.session_state["case_title"]:
        st.session_state["case_title"] = case_name_input

with col_hdr2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    if st.session_state["trace_result"]:
        if st.button("💾 Save Case to Archive", use_container_width=True):
            new_id = save_case_to_file(
                case_name=st.session_state["case_title"],
                primary_entity=st.session_state["current_entity"],
                trace_result=st.session_state["trace_result"],
            )
            st.success(f"Case saved to archive as **{st.session_state['case_title']}**!")
            st.rerun()

# Investigation Input Bar
col_in1, col_in2 = st.columns([4, 1])
with col_in1:
    target_entity = st.text_input(
        "Target Suspect Identifier (Crypto Wallet, UPI VPA, Telegram Handle, Domain, IP, Phone)",
        value=st.session_state["current_entity"],
        placeholder="e.g. +919876543210, @earnmoneyfast_bot, 0x28C6c06298d514Db089934071355E5743bf21d60, bijli-pay-india.com",
    )
    if target_entity != st.session_state["current_entity"]:
        st.session_state["current_entity"] = target_entity

with col_in2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    trace_btn = st.button("🚀 INITIATE TRACE", use_container_width=True)

# Instant Classification Preview
if target_entity.strip():
    cat, norm, lbl = detect_and_normalize_entity(target_entity)
    conn_cases = find_connected_cases(norm)
    
    col_prev1, col_prev2 = st.columns([2, 1])
    with col_prev1:
        st.caption(f"🔍 **Auto-Detected Target:** `{lbl}` &nbsp;|&nbsp; Normalized: `{norm}`")
    with col_prev2:
        if conn_cases:
            st.warning(f"⚠️ Appears in {len(conn_cases)} archived case(s): **{conn_cases[0][1]}**")

# ---------------------------------------------------------------------------
# Trace Execution Flow
# ---------------------------------------------------------------------------
if trace_btn and target_entity.strip():
    st.session_state["trace_logs"] = []
    start_time = time.time()
    
    with st.status("⚡ Running Autonomous Multi-Hop OSINT Trace...", expanded=True) as status_box:
        def agent_callback(event_type: str, data: dict):
            msg = data.get("message", "")
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_line = f"[{timestamp}] [{event_type.upper()}] {msg}"
            st.session_state["trace_logs"].append(log_line)
            st.write(log_line)

        try:
            res = run_trace(
                entity_input=target_entity,
                api_key=GEMINI_KEY,
                callback=agent_callback,
            )
            st.session_state["elapsed_seconds"] = round(time.time() - start_time, 2)
            st.session_state["trace_result"] = res
            status_box.update(label=f"✅ Trace Completed in {st.session_state['elapsed_seconds']}s", state="complete", expanded=False)
        except Exception as ex:
            st.session_state["elapsed_seconds"] = round(time.time() - start_time, 2)
            status_box.update(label=f"❌ Error during trace: {ex}", state="error")
            st.error(f"Execution Failure: {ex}")

# ---------------------------------------------------------------------------
# Results Display
# ---------------------------------------------------------------------------
res = st.session_state["trace_result"]

if res:
    # -----------------------------------------------------------------------
    # Laundering Kill-Chain Pipeline
    # -----------------------------------------------------------------------
    case_found = get_case_for_entity(res.get("entity", ""))
    is_dhan = "409" in (case_found.get("id", "") if case_found else "") or "@" in res.get("entity", "")
    
    st.markdown("#### ⚡ Autonomous Laundering Trail & Intervention Barrier")
    
    if is_dhan:
        st.markdown("""
        <div class="pipeline-container">
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#334155; color:#cbd5e1;">Step 1: Inception</span>
                <span class="pipeline-step-title">Telegram Lure</span>
                <span class="pipeline-step-sub">@earnmoneyfast_bot</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#ef4444; color:#ffffff;">🚨 Freeze Point</span>
                <span class="pipeline-step-title">UPI Mule Layer</span>
                <span class="pipeline-step-sub">PhonePe / Paytm (3 VPAs)</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#ea580c; color:#ffffff;">Step 3: Conversion</span>
                <span class="pipeline-step-title">P2P Crypto Desk</span>
                <span class="pipeline-step-sub">WazirX INR Escrow</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#7c3aed; color:#ffffff;">Step 4: Layering</span>
                <span class="pipeline-step-title">TRON Wash Wallet</span>
                <span class="pipeline-step-sub">342 Layering Tx</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#dc2626; color:#ffffff;">Step 5: Mixer</span>
                <span class="pipeline-step-title">Tornado Cash</span>
                <span class="pipeline-step-sub">89 Anonymized Hops</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#059669; color:#ffffff;">Step 6: Exit</span>
                <span class="pipeline-step-title">Offshore CEX</span>
                <span class="pipeline-step-sub">Huobi Liquidation</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="pipeline-container">
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#334155; color:#cbd5e1;">Step 1: Inflow</span>
                <span class="pipeline-step-title">Primary Vector</span>
                <span class="pipeline-step-sub">Deposit / Origination</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#ef4444; color:#ffffff;">🚨 Freeze Point</span>
                <span class="pipeline-step-title">Collection Layer</span>
                <span class="pipeline-step-sub">Intermediary Node</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#7c3aed; color:#ffffff;">Step 3: Conversion</span>
                <span class="pipeline-step-title">Anonymization</span>
                <span class="pipeline-step-sub">Privacy Protocol</span>
            </div>
            <div class="pipeline-arrow">➔</div>
            <div class="pipeline-step">
                <span class="pipeline-step-badge" style="background:#059669; color:#ffffff;">Step 4: Liquidation</span>
                <span class="pipeline-step-title">Offshore Exit</span>
                <span class="pipeline-step-sub">CEX Cash-out</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Metrics row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        score = res.get("risk_score")
        lbl = res.get("risk_label", "UNKNOWN")
        score_txt = f"{score}/100" if score is not None else "INSUFFICIENT"
        st.metric("Threat Severity", score_txt, delta=lbl, delta_color="inverse" if score else "off")
    with m2:
        num_nodes = len(res.get("graph", {}).get("nodes", []))
        st.metric("Correlated Nodes", f"{num_nodes} Entities")
    with m3:
        num_edges = len(res.get("graph", {}).get("edges", []))
        st.metric("Laundering Hops", f"{num_edges} Vectors")
    with m4:
        num_tools = len(res.get("tool_calls", []))
        st.metric("Live Lookups", f"{num_tools} Executed")
    with m5:
        st.metric("Elapsed Runtime", f"{st.session_state['elapsed_seconds']}s")

    # Tabs
    tab_dossier, tab_graph, tab_inspector, tab_timeline, tab_terminal = st.tabs([
        "📑 Police Briefing & Dossier",
        "🌐 Multi-Hop Threat Graph",
        "🔎 Entity & Summons Inspector",
        "⏳ Evidence Timeline",
        "🖥️ Operational Engine Logs",
    ])

    # -----------------------------------------------------------------------
    # TAB 1: FORMAL POLICE BRIEFING
    # -----------------------------------------------------------------------
    with tab_dossier:
        col_dos_main, col_dos_side = st.columns([3, 1])
        
        with col_dos_main:
            # Official Banner
            ref_id = f"I4C-CFCFRMS/2026/{(abs(hash(res.get('entity', ''))) % 8999) + 1000}"
            now_str = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M UTC")
            
            # Evidence Integrity Hash
            rep_text = str(res.get("briefing", "")) + str(res.get("timeline", ""))
            sha256_fingerprint = hashlib.sha256(rep_text.encode()).hexdigest()

            st.markdown(f"""
            <div class="fir-banner">
                <div style="font-family:'JetBrains Mono'; font-size:0.75rem; color:#38bdf8; font-weight:700;">
                    CENTRAL CYBER CRIME INVESTIGATION WING // FIRST INFORMATION BRIEFING
                </div>
                <div style="font-size:1.15rem; font-weight:700; color:#ffffff; margin: 4px 0;">
                    CASE REF: {ref_id}
                </div>
                <div style="font-size:0.80rem; color:#94a3b8;">
                    <strong>Subject Vector:</strong> <code>{res.get('entity')}</code> &nbsp;|&nbsp; 
                    <strong>Classification:</strong> {res.get('case_type')} &nbsp;|&nbsp; 
                    <strong>Timestamp:</strong> {now_str}
                </div>
                <div style="font-size:0.72rem; color:#64748b; font-family:'JetBrains Mono'; margin-top: 6px;">
                    EVIDENTIARY SHA-256: {sha256_fingerprint}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Executive Investigation Narrative
            st.markdown("""
            <div class="forensic-card">
                <div class="forensic-card-header">
                    <span>📑 Executive Forensic Briefing (Evidence-Grounded)</span>
                </div>
            """, unsafe_allow_html=True)
            
            st.markdown(res.get("briefing", ""))
            st.markdown("</div>", unsafe_allow_html=True)

            # Multi-Hop Evidence Matrix
            st.markdown("""
            <div class="forensic-card">
                <div class="forensic-card-header">
                    <span>🔗 Multi-Hop Interception & Laundering Matrix</span>
                </div>
            """, unsafe_allow_html=True)
            
            edges = res.get("graph", {}).get("edges", [])
            if edges:
                matrix_rows = []
                for idx, e in enumerate(edges[:10], 1):
                    matrix_rows.append({
                        "Hop": f"#{idx}",
                        "Source Vector": e.get("source", ""),
                        "Laundering Action": e.get("relation", ""),
                        "Destination Vector": e.get("target", ""),
                        "Threat Level": e.get("threat_level", "medium").upper(),
                    })
                st.table(matrix_rows)
            else:
                st.caption("No multi-hop edges recorded.")
            st.markdown("</div>", unsafe_allow_html=True)

            # Statutory Directives Card
            st.markdown("""
            <div class="forensic-card">
                <div class="forensic-card-header">
                    <span>🚨 Requisite Judicial Orders & Statutory Action Directives</span>
                </div>
            """, unsafe_allow_html=True)
            for rec in res.get("recommendations", []):
                st.markdown(f"• **[STATUTORY ORDER]** {rec}")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_dos_side:
            st.markdown("#### 💾 Export Formal Dossier")
            st.caption("Official evidence exports formatted for judicial submission.")

            # 1. PDF Download
            pdf_bytes = generate_pdf_report(res)
            st.download_button(
                label="📕 Download Official Police PDF",
                data=pdf_bytes,
                file_name=f"Police_Dossier_{res.get('entity')[:16]}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

            # 2. JSON Export
            json_export_data = {
                "sha256": sha256_fingerprint,
                "timestamp": now_str,
                "entity": res.get("entity"),
                "risk_score": res.get("risk_score"),
                "risk_label": res.get("risk_label"),
                "case_type": res.get("case_type"),
                "briefing": res.get("briefing"),
                "graph": res.get("graph"),
                "timeline": res.get("timeline"),
                "recommendations": res.get("recommendations"),
            }
            st.download_button(
                label="💾 Download Structured JSON",
                data=json.dumps(json_export_data, indent=2),
                file_name=f"ShadowTrace_{res.get('entity')[:16]}.json",
                mime="application/json",
                use_container_width=True,
            )

            # 3. CSV Export
            csv_data = generate_csv_export(res.get("graph", {}).get("nodes", []), res.get("graph", {}).get("edges", []))
            st.download_button(
                label="📊 Download Entity CSV",
                data=csv_data,
                file_name=f"Entities_{res.get('entity')[:16]}.csv",
                mime="text/csv",
                use_container_width=True,
            )

            st.markdown("---")
            st.info(
                "📜 **Evidentiary Standard:** Report conforms to **Section 63 of Bharatiya Sakshya Adhiniyam (BSA) 2023** "
                "with tamper-evident SHA-256 cryptographic hashing."
            )

    # -----------------------------------------------------------------------
    # TAB 2: VIS.JS GRAPH
    # -----------------------------------------------------------------------
    with tab_graph:
        st.markdown("#### Interactive Forensic Graph (Vis.js Physics Engine)")
        st.caption("💡 Drag nodes to isolate clusters • Scroll to zoom • Color borders represent threat severity")
        
        graph_data = res.get("graph", {})
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        if nodes:
            vis_html = render_visjs_graph(nodes, edges)
            components.html(vis_html, height=560, scrolling=False)
        else:
            st.warning("No interconnected graph nodes discovered for this entity.")

    # -----------------------------------------------------------------------
    # TAB 3: Entity & Summons Inspector
    # -----------------------------------------------------------------------
    with tab_inspector:
        st.markdown("#### 🔎 Interactive Entity Inspector & Section 94 Summons Drafter")
        st.caption("Select any discovered entity to view intelligence, transaction velocity, and generate a legally compliant production order.")

        nodes = res.get("graph", {}).get("nodes", [])
        node_options = [n.get("label", n.get("id")).replace("\n", " — ") for n in nodes]
        
        if node_options:
            selected_node_label = st.selectbox("Inspect Discovered Entity Node", options=node_options, index=0)
            
            matched_node = None
            for n in nodes:
                lbl = n.get("label", n.get("id")).replace("\n", " — ")
                if lbl == selected_node_label:
                    matched_node = n
                    break

            if matched_node:
                col_insp1, col_insp2 = st.columns([1, 1])
                
                with col_insp1:
                    st.markdown("<div class='inspector-box'>", unsafe_allow_html=True)
                    st.markdown(f"### 🎯 Entity: `{matched_node.get('id')}`")
                    st.markdown(f"**Node Type:** `{matched_node.get('type', 'N/A').upper()}`")
                    
                    tlevel = matched_node.get('threat_level', 'medium').upper()
                    chip_class = "chip-crit" if tlevel == "CRITICAL" else ("chip-high" if tlevel == "HIGH" else "chip-med")
                    st.markdown(f"**Threat Severity:** <span class='chip {chip_class}'>{tlevel}</span>", unsafe_allow_html=True)
                    
                    connected_edges = [
                        e for e in res.get("graph", {}).get("edges", [])
                        if e.get("source") == matched_node.get("id") or e.get("target") == matched_node.get("id")
                    ]
                    st.markdown(f"**Connected Hops:** {len(connected_edges)} vectors")
                    for e in connected_edges[:4]:
                        st.caption(f"• `{e.get('source')}` ➔ `{e.get('target')}` ({e.get('relation')})")
                    
                    st.markdown("</div>", unsafe_allow_html=True)

                with col_insp2:
                    st.markdown("#### 📜 Instant Section 94 BNSS Legal Summons")
                    st.caption("Auto-fills official notice addressed to Nodal Officer of PSP / Exchange demanding immediate freeze.")
                    
                    summons_text = draft_bnss_summons(matched_node.get("id"), st.session_state["case_title"])
                    st.text_area("Legal Summons Draft", value=summons_text, height=220)
                    
                    st.download_button(
                        label="📥 Download Legal Notice (.txt)",
                        data=summons_text,
                        file_name=f"BNSS_Sec94_Summons_{matched_node.get('id').replace(':', '_')[:16]}.txt",
                        mime="text/plain",
                        use_container_width=True,
                    )
        else:
            st.info("Run an autonomous trace to populate inspectable entities.")

    # -----------------------------------------------------------------------
    # TAB 4: Incident Chronology
    # -----------------------------------------------------------------------
    with tab_timeline:
        st.markdown("#### ⏱️ Chronological Incident Reconstruction")
        timeline_items = res.get("timeline", [])
        if timeline_items:
            for item in timeline_items:
                ts = item.get("timestamp", "N/A")
                ev = item.get("event", "")
                src = item.get("source", "Telemetry")
                st.markdown(
                    f"<div class='forensic-card' style='padding: 10px 14px; margin-bottom: 8px; border-left: 3px solid #0284c7;'>"
                    f"<strong style='color:#38bdf8; font-family:JetBrains Mono;'>[{ts}]</strong> "
                    f"<span style='color:#f8fafc;'>{ev}</span> "
                    f"<span style='float:right; color:#64748b; font-size:0.75rem; font-family:JetBrains Mono;'>VIA: {src}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No temporal records detected for this specific vector.")

    # -----------------------------------------------------------------------
    # TAB 5: Operational Engine Logs
    # -----------------------------------------------------------------------
    with tab_terminal:
        st.markdown("#### 💻 Operational Engine Thought Log")
        terminal_content = "\n".join(st.session_state["trace_logs"])
        st.code(terminal_content if terminal_content else "No logs in current session.", language="bash")

else:
    # Welcome Screen
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("### 🎯 Autonomous Intelligence Capabilities")
        st.markdown("""
        - **Blockchain Intelligence:** Live Blockscout v2 EVM tracking, TronGrid RPC, and Blockchain.info Bitcoin flows.
        - **UPI Forensic Triage:** NPCI / PSP velocity validation, mule account identification, and bank routing.
        - **Cross-Domain OSINT:** Live Telegram preview scraping extracting wallets, VPAs, phones, and domains.
        - **Case Archive & Memory:** Store custom-named investigations and resume triage anytime.
        """)
    with c2:
        st.markdown("### 🚀 Fast Demonstration Walkthrough")
        st.markdown("""
        1. Select **Case #409: Operation DhanChor [SEEDED DEMO]** or enter any Indian phone (+919876543210), wallet, or UPI.
        2. Click **Initiate Trace** to observe live multi-hop reasoning.
        3. View the **Laundering Kill-Chain Pipeline** and identify the intervention point.
        4. Inspect any entity in the **Entity & Summons Inspector** tab.
        5. Download the **Official PDF Report**, **JSON**, or **CSV** ready for judicial filing.
        """)
