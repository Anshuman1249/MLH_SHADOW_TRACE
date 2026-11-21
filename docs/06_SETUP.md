# ⚙️ ShadowTrace — Setup Guide

**Document ID:** ST-SETUP-006  
**Version:** 1.0.0  
**Target OS:** Windows 11 (64-bit)  
**Python Version:** 3.10 – 3.12  

---

## 1. Prerequisites

### 1.1 Required Software

| Software | Version | Check Command | Download |
|---|---|---|---|
| Python | 3.10 – 3.12 | `python --version` | [python.org](https://www.python.org/downloads/) |
| pip | ≥ 23.0 | `pip --version` | Included with Python |
| Git | ≥ 2.40 | `git --version` | [git-scm.com](https://git-scm.com/) |
| Browser | Chrome/Edge/Firefox (latest) | — | For Streamlit UI |

### 1.2 Required Accounts & Keys

| Service | Purpose | Required? | How to Get |
|---|---|---|---|
| Google Gemini API | Intelligence engine | Yes (for live AI) | [aistudio.google.com](https://aistudio.google.com/apikey) |
| Etherscan API | Live ETH wallet data | Optional | [etherscan.io/apis](https://etherscan.io/apis) |

> **Note:** ShadowTrace works fully offline using built-in fallback data. API keys enhance the experience with live data but are not required for the demo.

---

## 2. Installation Steps

### Step 1: Clone or Navigate to the Project

```powershell
cd "c:\Users\anshu\OneDrive\Documents\Anshuman\MLH_hackathon"
```

### Step 2: Create a Virtual Environment

```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

> **If you get an Execution Policy error**, run this first:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Step 4: Upgrade pip

```powershell
python -m pip install --upgrade pip
```

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Verify Installation

```powershell
python -c "import streamlit; import google.generativeai; print('All dependencies OK')"
```

---

## 3. Configuration

### 3.1 Gemini API Key

The API key can be provided in two ways:

**Option A: Via the Streamlit UI (Recommended for Demo)**
1. Launch the app
2. Enter your API key in the sidebar input field
3. The key is stored in session state only — never written to disk

**Option B: Via Environment Variable (Development)**
```powershell
$env:GEMINI_API_KEY = "your-api-key-here"
```

### 3.2 Optional: Etherscan API Key

For live Ethereum wallet data (not required — fallback data is built in):

```powershell
$env:ETHERSCAN_API_KEY = "your-etherscan-key-here"
```

---

## 4. Running the Application

### Standard Launch

```powershell
streamlit run app.py
```

The app will open automatically in your default browser at `http://localhost:8501`.

### Launch with Custom Port

```powershell
streamlit run app.py --server.port 8080
```

### Launch in Headless Mode (No Auto-Open Browser)

```powershell
streamlit run app.py --server.headless true
```

---

## 5. Project Directory Structure

```
MLH_hackathon/
├── docs/                              # Project documentation
│   ├── 01_PROJECT_VISION.md
│   ├── 02_USER_DEFINITION_AND_REQUIREMENTS.md
│   ├── 03_TECH_STACK_AND_ARCHITECTURE.md
│   ├── 04_PROJECT_RULES.md
│   ├── 05_TASK_BREAKDOWN.md
│   ├── 06_SETUP.md
│   ├── 07_DEVELOPMENT.md
│   ├── 08_TESTING.md
│   └── 09_SECURITY_REVIEW.md
├── app.py                             # Streamlit UI application
├── agent.py                           # Gemini intelligence engine
├── tools.py                           # 6 OSINT tool implementations
├── cases.py                           # Pre-seeded case data + fallback datasets
├── CASE_STUDIES.md                     # Case study breakdowns + pitch script
├── requirements.txt                   # Python dependencies
├── .gitignore                         # Git exclusions
└── .venv/                             # Virtual environment (not committed)
```

---

## 6. Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | Virtual environment not activated | Run `.\.venv\Scripts\Activate.ps1` |
| `pip install` fails with "Microsoft Visual C++ required" | A package needs C++ build tools | Check `requirements.txt` — this should not happen with our curated packages |
| Streamlit shows blank page | Browser cache | Hard refresh (Ctrl+Shift+R) or try incognito |
| `google.generativeai` import error | Package not installed | Run `pip install google-generativeai` |
| Graph not rendering | CDN blocked on venue network | Vis.js is loaded via CDN; in offline fallback, the graph still renders with inline data |
| PowerShell blocks `.ps1` script | Execution policy | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |

### Verifying Python Version

```powershell
python --version
# Expected: Python 3.10.x, 3.11.x, or 3.12.x
```

### Verifying All Dependencies

```powershell
pip list | Select-String "streamlit|google-generativeai|requests|python-whois|phonenumbers|jinja2|markdown"
```

---

## 7. Quick Start (Copy-Paste Ready)

```powershell
# Full setup in one go (run from project root)
cd "c:\Users\anshu\OneDrive\Documents\Anshuman\MLH_hackathon"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

---

*Document Owner: ShadowTrace Team | NFSU MLH Hackathon 2026*
