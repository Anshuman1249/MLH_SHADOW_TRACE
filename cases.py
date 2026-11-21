"""
ShadowTrace — Case Data & Deterministic Fallback Datasets
Complete forensic case definitions for Operation DhanChor and Operation Vidyut.
Every entity in both cases has a pre-computed fallback so the demo never crashes offline.
"""

from datetime import datetime

# ---------------------------------------------------------------------------
# Graph style mapping for Vis.js node rendering
# ---------------------------------------------------------------------------
GRAPH_STYLES = {
    "wallet":    {"color": "#e040fb", "shape": "diamond",     "size": 30},
    "upi":       {"color": "#ff5252", "shape": "dot",         "size": 28},
    "telegram":  {"color": "#448aff", "shape": "triangle",    "size": 30},
    "domain":    {"color": "#ff6e40", "shape": "square",      "size": 26},
    "ip":        {"color": "#ffab40", "shape": "hexagon",     "size": 24},
    "phone":     {"color": "#69f0ae", "shape": "star",        "size": 26},
    "exchange":  {"color": "#ffd740", "shape": "dot",         "size": 32},
    "mixer":     {"color": "#ff1744", "shape": "diamond",     "size": 34},
    "person":    {"color": "#40c4ff", "shape": "icon",        "size": 28},
    "bank":      {"color": "#b388ff", "shape": "square",      "size": 24},
    "apk":       {"color": "#ff3d00", "shape": "triangle",    "size": 26},
    "c2_panel":  {"color": "#d50000", "shape": "square",      "size": 28},
    "victim":    {"color": "#78909c", "shape": "dot",         "size": 20},
    "default":   {"color": "#90a4ae", "shape": "dot",         "size": 22},
}

THREAT_COLORS = {
    "critical": "#ff1744",
    "high":     "#ff6d00",
    "medium":   "#ffd600",
    "low":      "#00e676",
    "info":     "#448aff",
}

# ---------------------------------------------------------------------------
# CASE #409 — Operation DhanChor
# Fake Telegram Part-Time Job Scam → UPI Mule Accounts → P2P Crypto → TRON Wash
# ---------------------------------------------------------------------------
CASE_409 = {
    "id": "case_409",
    "codename": "Operation DhanChor",
    "status": "Active Investigation",
    "classification": "Part-Time Job Scam → UPI Mule Network → P2P Crypto Laundering",
    "summary": (
        "A Telegram-based part-time job scam network recruited victims through "
        "the channel @earnmoneyfast_bot, promising ₹5,000–₹15,000/day for 'product "
        "review tasks'. Victims deposited 'activation fees' ranging from ₹1,500 to "
        "₹25,000 into UPI mule accounts controlled by the syndicate. Collected funds "
        "were routed through 3 primary UPI mule identities to WazirX P2P desk, "
        "converted to USDT (TRC-20), layered through a TRON wash wallet, mixed via "
        "Tornado Cash, and cashed out on Huobi. Estimated 850+ victims, total "
        "proceeds ≈ ₹6.2 crore ($740K USD)."
    ),
    "primary_entity": "@earnmoneyfast_bot",
    "all_entities": {
        "telegram": ["@earnmoneyfast_bot"],
        "upi": ["rajeshk.mule03@ybl", "priya.sharma88@paytm", "vikram.ops@axl"],
        "crypto_tron": [
            "TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr",
            "TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1",
        ],
        "domain": ["earn-daily-income.in"],
        "phone": ["+918234567890"],
        "ip": ["45.154.98.221"],
    },
    "timeline": [
        {"timestamp": "2025-06-10T00:00:00Z", "event": "Domain earn-daily-income.in registered via NameSilo", "source": "WHOIS"},
        {"timestamp": "2025-06-12T00:00:00Z", "event": "Domain pointed to 45.154.98.221 (DigitalOcean SG)", "source": "DNS"},
        {"timestamp": "2025-07-01T00:00:00Z", "event": "Telegram channel @earnmoneyfast_bot created", "source": "Telegram OSINT"},
        {"timestamp": "2025-07-05T00:00:00Z", "event": "First victim complaint to NCRP — ₹5,000 lost to rajeshk.mule03@ybl", "source": "I4C NCRP"},
        {"timestamp": "2025-08-14T03:22:11Z", "event": "TRON wash wallet TJFoS6...bU1 first transaction", "source": "Tronscan"},
        {"timestamp": "2025-09-20T00:00:00Z", "event": "UPI mule priya.sharma88@paytm flagged by Paytm fraud team", "source": "PSP Alert"},
        {"timestamp": "2025-11-03T00:00:00Z", "event": "TRON wallet interacts with Tornado Cash router (89 tx)", "source": "Tronscan"},
        {"timestamp": "2026-01-15T00:00:00Z", "event": "I4C freeze order on vikram.ops@axl — ₹18.4 lakh frozen", "source": "I4C Order"},
        {"timestamp": "2026-03-28T00:00:00Z", "event": "Huobi cash-out detected — 67 tx totalling $312K", "source": "Chain Analysis"},
        {"timestamp": "2026-10-01T00:00:00Z", "event": "Total victim count crosses 850, cumulative loss ₹6.2 crore", "source": "NCRP Aggregation"},
    ],
    "graph": {
        "nodes": [
            {"id": "telegram:@earnmoneyfast_bot", "label": "Telegram\n@earnmoneyfast_bot", "type": "telegram", "threat_level": "critical"},
            {"id": "phone:+918234567890", "label": "Phone\n+91-82345-67890", "type": "phone", "threat_level": "high"},
            {"id": "domain:earn-daily-income.in", "label": "Domain\nearn-daily-income.in", "type": "domain", "threat_level": "high"},
            {"id": "ip:45.154.98.221", "label": "IP\n45.154.98.221\n(DigitalOcean SG)", "type": "ip", "threat_level": "medium"},
            {"id": "person:RajeshKumar", "label": "Mule 1\nRajesh Kumar", "type": "person", "threat_level": "high"},
            {"id": "upi:rajeshk.mule03@ybl", "label": "UPI Mule\nrajeshk.mule03@ybl", "type": "upi", "threat_level": "critical"},
            {"id": "person:PriyaSharma", "label": "Mule 2\nPriya Sharma", "type": "person", "threat_level": "high"},
            {"id": "upi:priya.sharma88@paytm", "label": "UPI Mule\npriya.sharma88@paytm", "type": "upi", "threat_level": "critical"},
            {"id": "person:VikramSingh", "label": "Operator\nVikram Singh", "type": "person", "threat_level": "critical"},
            {"id": "upi:vikram.ops@axl", "label": "UPI Mule\nvikram.ops@axl", "type": "upi", "threat_level": "critical"},
            {"id": "exchange:WazirX", "label": "WazirX\nP2P Desk", "type": "exchange", "threat_level": "high"},
            {"id": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "label": "TRON Collection\nTN7Ffh...Fhr", "type": "wallet", "threat_level": "critical"},
            {"id": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "label": "TRON Wash\nTJFoS6...bU1", "type": "wallet", "threat_level": "critical"},
            {"id": "mixer:TornadoCash", "label": "Tornado Cash\nMixer", "type": "mixer", "threat_level": "critical"},
            {"id": "exchange:Huobi", "label": "Huobi\nExchange", "type": "exchange", "threat_level": "high"},
            {"id": "victim:pool_409", "label": "850+ Victims\n₹6.2 Cr Loss", "type": "victim", "threat_level": "info"},
        ],
        "edges": [
            {"source": "telegram:@earnmoneyfast_bot", "target": "domain:earn-daily-income.in", "relation": "Promotes landing page", "threat_level": "high"},
            {"source": "telegram:@earnmoneyfast_bot", "target": "phone:+918234567890", "relation": "Contact number in bio", "threat_level": "medium"},
            {"source": "domain:earn-daily-income.in", "target": "ip:45.154.98.221", "relation": "Hosted on", "threat_level": "medium"},
            {"source": "phone:+918234567890", "target": "person:VikramSingh", "relation": "Registered to", "threat_level": "high"},
            {"source": "telegram:@earnmoneyfast_bot", "target": "upi:rajeshk.mule03@ybl", "relation": "Payment collection", "threat_level": "critical"},
            {"source": "telegram:@earnmoneyfast_bot", "target": "upi:priya.sharma88@paytm", "relation": "Payment collection", "threat_level": "critical"},
            {"source": "telegram:@earnmoneyfast_bot", "target": "upi:vikram.ops@axl", "relation": "Payment collection", "threat_level": "critical"},
            {"source": "upi:rajeshk.mule03@ybl", "target": "person:RajeshKumar", "relation": "KYC name match", "threat_level": "high"},
            {"source": "upi:priya.sharma88@paytm", "target": "person:PriyaSharma", "relation": "KYC name match", "threat_level": "high"},
            {"source": "upi:vikram.ops@axl", "target": "person:VikramSingh", "relation": "KYC name match", "threat_level": "critical"},
            {"source": "upi:rajeshk.mule03@ybl", "target": "exchange:WazirX", "relation": "INR deposit via IMPS", "threat_level": "high"},
            {"source": "upi:priya.sharma88@paytm", "target": "exchange:WazirX", "relation": "INR deposit via NEFT", "threat_level": "high"},
            {"source": "upi:vikram.ops@axl", "target": "exchange:WazirX", "relation": "INR deposit via RTGS", "threat_level": "high"},
            {"source": "exchange:WazirX", "target": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "relation": "USDT purchased (P2P)", "threat_level": "critical"},
            {"source": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "target": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "relation": "Funds layered (342 tx)", "threat_level": "critical"},
            {"source": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "target": "mixer:TornadoCash", "relation": "Mixed (89 tx)", "threat_level": "critical"},
            {"source": "mixer:TornadoCash", "target": "exchange:Huobi", "relation": "Post-mix cash-out", "threat_level": "critical"},
            {"source": "victim:pool_409", "target": "upi:rajeshk.mule03@ybl", "relation": "Victim payments", "threat_level": "info"},
            {"source": "victim:pool_409", "target": "upi:priya.sharma88@paytm", "relation": "Victim payments", "threat_level": "info"},
        ],
    },
    "regulatory": {
        "applicable_sections": [
            "IT Act 2000, Sec 66C — Identity Theft (UPI mule accounts)",
            "IT Act 2000, Sec 66D — Cheating by Personation (Telegram scam)",
            "BNS 2023, Sec 318 — Cheating (formerly IPC 420)",
            "BNS 2023, Sec 319 — Cheating by Personation",
            "BNS 2023, Sec 336 — Forgery (fake job documents)",
            "PMLA 2002, Sec 3 — Money Laundering (crypto layering)",
            "PMLA 2002, Sec 4 — Punishment for Money Laundering",
        ],
        "jurisdiction": "Multi-state; primary FIR recommended at complainant's local PS with I4C coordination",
        "evidence_preservation": "BNSS 2023 Sec 94 production order for WazirX KYC records and Telegram channel data",
    },
}


# ---------------------------------------------------------------------------
# CASE #102 — Operation Vidyut
# Fake Electricity Bill APK → SMS-Stealing C2 → Bank OTP Interception → Crypto Mixer
# ---------------------------------------------------------------------------
CASE_102 = {
    "id": "case_102",
    "codename": "Operation Vidyut",
    "status": "Active Investigation",
    "classification": "Fake Utility APK Extortion → OTP Interception → Crypto Mixer Laundering",
    "summary": (
        "An SMS-based phishing campaign sent messages claiming 'electricity bill overdue — "
        "pay immediately or disconnection in 24 hours' with a link to bijli-pay-india.com. "
        "The site served a malicious APK (bijli_pay_v2.3.apk) disguised as an electricity "
        "payment app. The APK contained an SMS-stealing trojan that forwarded all incoming "
        "SMS (including bank OTPs) to a C2 server at 103.74.19.104. The operators used "
        "intercepted OTPs to authorize UPI and net-banking transactions, draining victim "
        "accounts into quickpay.merchant@oksbi. Stolen funds were converted to ETH, mixed "
        "through Sinbad.io, converted to BTC, and cashed out on Binance. Estimated 1,200+ "
        "victims, total proceeds ≈ ₹8.7 crore ($1.04M USD)."
    ),
    "primary_entity": "bijli-pay-india.com",
    "all_entities": {
        "domain": ["bijli-pay-india.com"],
        "ip": ["103.74.19.104"],
        "telegram": ["@bijli_helpdesk"],
        "phone": ["+917891234560"],
        "upi": ["quickpay.merchant@oksbi"],
        "crypto_eth": ["0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68"],
        "crypto_btc": ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"],
    },
    "timeline": [
        {"timestamp": "2025-04-02T00:00:00Z", "event": "Domain bijli-pay-india.com registered via NameCheap (privacy ON)", "source": "WHOIS"},
        {"timestamp": "2025-04-05T00:00:00Z", "event": "Domain pointed to 103.74.19.104 (Hostinger VPS, Mumbai)", "source": "DNS"},
        {"timestamp": "2025-04-10T00:00:00Z", "event": "APK bijli_pay_v2.3.apk uploaded to phishing page", "source": "URL Scan"},
        {"timestamp": "2025-04-12T00:00:00Z", "event": "SMS campaign launched from +917891234560 (bulk SIM)", "source": "Telecom Intel"},
        {"timestamp": "2025-04-14T00:00:00Z", "event": "First victim OTP intercepted — ₹49,500 drained from HDFC savings", "source": "Bank Alert"},
        {"timestamp": "2025-05-20T00:00:00Z", "event": "Telegram @bijli_helpdesk set up for 'customer support' misdirection", "source": "Telegram OSINT"},
        {"timestamp": "2025-06-15T00:00:00Z", "event": "UPI quickpay.merchant@oksbi crosses ₹2 crore inflow", "source": "PSP Monitoring"},
        {"timestamp": "2025-08-01T00:00:00Z", "event": "ETH wallet 0x742d...bD68 begins receiving from Indian exchanges", "source": "Etherscan"},
        {"timestamp": "2025-10-10T00:00:00Z", "event": "Sinbad.io mixer transactions detected — 142 deposits", "source": "Chain Analysis"},
        {"timestamp": "2026-02-18T00:00:00Z", "event": "BTC cash-out on Binance — 23.4 BTC ($1.6M at time)", "source": "Binance Intel"},
        {"timestamp": "2026-06-01T00:00:00Z", "event": "CERT-In takedown order on bijli-pay-india.com", "source": "CERT-In"},
        {"timestamp": "2026-09-15T00:00:00Z", "event": "Total victim count 1,200+, cumulative loss ₹8.7 crore", "source": "NCRP Aggregation"},
    ],
    "graph": {
        "nodes": [
            {"id": "domain:bijli-pay-india.com", "label": "Phishing Site\nbijli-pay-india.com", "type": "domain", "threat_level": "critical"},
            {"id": "ip:103.74.19.104", "label": "C2 Server\n103.74.19.104\n(Hostinger Mumbai)", "type": "ip", "threat_level": "critical"},
            {"id": "phone:+917891234560", "label": "SMS Campaign\n+91-78912-34560", "type": "phone", "threat_level": "high"},
            {"id": "apk:bijli_pay_v2.3", "label": "Malicious APK\nbijli_pay_v2.3.apk", "type": "apk", "threat_level": "critical"},
            {"id": "c2:admin_panel", "label": "C2 Panel\n/admin/dashboard", "type": "c2_panel", "threat_level": "critical"},
            {"id": "telegram:@bijli_helpdesk", "label": "Fake Support\n@bijli_helpdesk", "type": "telegram", "threat_level": "high"},
            {"id": "person:AmitVerma", "label": "Operator\nAmit Verma", "type": "person", "threat_level": "critical"},
            {"id": "upi:quickpay.merchant@oksbi", "label": "Collection UPI\nquickpay.merchant@oksbi", "type": "upi", "threat_level": "critical"},
            {"id": "bank:SBI_XX4521", "label": "SBI Account\nXX4521", "type": "bank", "threat_level": "high"},
            {"id": "wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "label": "ETH Wallet\n0x742d...bD68", "type": "wallet", "threat_level": "critical"},
            {"id": "mixer:Sinbad", "label": "Sinbad.io\nMixer", "type": "mixer", "threat_level": "critical"},
            {"id": "wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "label": "BTC Wallet\nbc1qxy2...wlh", "type": "wallet", "threat_level": "critical"},
            {"id": "exchange:Binance", "label": "Binance\nExchange", "type": "exchange", "threat_level": "high"},
            {"id": "victim:pool_102", "label": "1,200+ Victims\n₹8.7 Cr Loss", "type": "victim", "threat_level": "info"},
            {"id": "registrar:NameCheap", "label": "Registrar\nNameCheap", "type": "domain", "threat_level": "medium"},
        ],
        "edges": [
            {"source": "phone:+917891234560", "target": "domain:bijli-pay-india.com", "relation": "SMS links to", "threat_level": "high"},
            {"source": "domain:bijli-pay-india.com", "target": "ip:103.74.19.104", "relation": "Hosted on", "threat_level": "high"},
            {"source": "domain:bijli-pay-india.com", "target": "apk:bijli_pay_v2.3", "relation": "Distributes malware", "threat_level": "critical"},
            {"source": "domain:bijli-pay-india.com", "target": "registrar:NameCheap", "relation": "Registered via", "threat_level": "medium"},
            {"source": "apk:bijli_pay_v2.3", "target": "ip:103.74.19.104", "relation": "C2 callback", "threat_level": "critical"},
            {"source": "ip:103.74.19.104", "target": "c2:admin_panel", "relation": "Hosts admin panel", "threat_level": "critical"},
            {"source": "c2:admin_panel", "target": "person:AmitVerma", "relation": "Operated by", "threat_level": "critical"},
            {"source": "telegram:@bijli_helpdesk", "target": "domain:bijli-pay-india.com", "relation": "Promotes", "threat_level": "high"},
            {"source": "telegram:@bijli_helpdesk", "target": "person:AmitVerma", "relation": "Administered by", "threat_level": "high"},
            {"source": "person:AmitVerma", "target": "upi:quickpay.merchant@oksbi", "relation": "Controls", "threat_level": "critical"},
            {"source": "upi:quickpay.merchant@oksbi", "target": "bank:SBI_XX4521", "relation": "Linked bank account", "threat_level": "high"},
            {"source": "bank:SBI_XX4521", "target": "wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "relation": "Funds converted to ETH", "threat_level": "critical"},
            {"source": "wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "target": "mixer:Sinbad", "relation": "Mixed (142 deposits)", "threat_level": "critical"},
            {"source": "mixer:Sinbad", "target": "wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "relation": "BTC output", "threat_level": "critical"},
            {"source": "wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "target": "exchange:Binance", "relation": "Cash-out (23.4 BTC)", "threat_level": "critical"},
            {"source": "victim:pool_102", "target": "domain:bijli-pay-india.com", "relation": "Lured to phishing", "threat_level": "info"},
            {"source": "victim:pool_102", "target": "upi:quickpay.merchant@oksbi", "relation": "Funds drained to", "threat_level": "info"},
        ],
    },
    "regulatory": {
        "applicable_sections": [
            "IT Act 2000, Sec 43 — Unauthorized Access (APK installs without informed consent)",
            "IT Act 2000, Sec 66 — Computer Related Offences (SMS interception)",
            "IT Act 2000, Sec 66C — Identity Theft (OTP interception)",
            "IT Act 2000, Sec 66D — Cheating by Personation (fake electricity portal)",
            "BNS 2023, Sec 318 — Cheating",
            "BNS 2023, Sec 308 — Extortion",
            "BNS 2023, Sec 336(3) — Forgery of electronic record",
            "PMLA 2002, Sec 3 — Money Laundering",
            "Telegraph Act 1885, Sec 25 — Interception of Messages",
        ],
        "jurisdiction": "Multi-state; CERT-In co-ordination with state Cyber PS; ED referral for PMLA",
        "evidence_preservation": "BNSS 2023 Sec 94 for Hostinger server image, Binance KYC, Telecom CDR for +917891234560",
    },
}


# ---------------------------------------------------------------------------
# Master case registry
# ---------------------------------------------------------------------------
CASES = {
    "case_409": CASE_409,
    "case_102": CASE_102,
}

# ---------------------------------------------------------------------------
# FALLBACK_DATA — deterministic mock responses for every tool × entity combination
# Key format: "tool_name:primary_input"
# ---------------------------------------------------------------------------
FALLBACK_DATA = {
    # ======================================================================
    # CASE 409 fallback data
    # ======================================================================
    "lookup_telegram_threat_intel:@earnmoneyfast_bot": {
        "status": "fallback",
        "query": "@earnmoneyfast_bot",
        "evidence": {
            "summary": "High-risk Telegram channel operating a part-time job scam recruiting Indian victims. Linked to UPI mule network and TRON crypto laundering.",
            "details": {
                "handle": "@earnmoneyfast_bot",
                "channel_name": "Earn Money Fast — Daily Income ₹5K-15K",
                "created": "2025-07-01",
                "subscriber_count": 14823,
                "posting_frequency": "8-12 posts/day",
                "language": "Hindi / Hinglish",
                "bot_commands": ["/start", "/join", "/deposit", "/withdraw", "/support"],
                "linked_domains": ["earn-daily-income.in"],
                "linked_crypto": ["TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr"],
                "linked_upi": ["rajeshk.mule03@ybl", "priya.sharma88@paytm", "vikram.ops@axl"],
                "scam_kit_type": "Task-based deposit scam (fake product reviews)",
                "associated_groups": ["CyberSindicate-IN-07", "Dragon Pay Network"],
                "admin_phone": "+918234567890",
            },
            "risk_indicators": [
                "SCAM_KIT: Matches known 'task-deposit' scam template used by CyberSindicate-IN-07",
                "HIGH_VOLUME: 14,823 subscribers with active deposit solicitation",
                "MULTI_UPI: 3 different UPI VPAs rotated as payment targets",
                "CRYPTO_LINK: Direct link to TRON wallet for 'withdrawal processing'",
                "SOCIAL_ENGINEERING: Uses urgency tactics — 'limited slots', 'VIP upgrade expiring'",
            ],
        },
        "risk_score": 95,
        "graph": {
            "nodes": [
                {"id": "telegram:@earnmoneyfast_bot", "label": "Telegram\n@earnmoneyfast_bot", "type": "telegram", "threat_level": "critical"},
                {"id": "domain:earn-daily-income.in", "label": "Domain\nearn-daily-income.in", "type": "domain", "threat_level": "high"},
                {"id": "upi:rajeshk.mule03@ybl", "label": "UPI Mule\nrajeshk.mule03@ybl", "type": "upi", "threat_level": "critical"},
                {"id": "upi:priya.sharma88@paytm", "label": "UPI Mule\npriya.sharma88@paytm", "type": "upi", "threat_level": "critical"},
                {"id": "upi:vikram.ops@axl", "label": "UPI Mule\nvikram.ops@axl", "type": "upi", "threat_level": "critical"},
                {"id": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "label": "TRON Collection\nTN7Ffh...Fhr", "type": "wallet", "threat_level": "critical"},
                {"id": "phone:+918234567890", "label": "Admin Phone\n+91-82345-67890", "type": "phone", "threat_level": "high"},
            ],
            "edges": [
                {"source": "telegram:@earnmoneyfast_bot", "target": "domain:earn-daily-income.in", "relation": "Promotes landing page", "threat_level": "high"},
                {"source": "telegram:@earnmoneyfast_bot", "target": "upi:rajeshk.mule03@ybl", "relation": "Payment collection", "threat_level": "critical"},
                {"source": "telegram:@earnmoneyfast_bot", "target": "upi:priya.sharma88@paytm", "relation": "Payment collection", "threat_level": "critical"},
                {"source": "telegram:@earnmoneyfast_bot", "target": "upi:vikram.ops@axl", "relation": "Payment collection", "threat_level": "critical"},
                {"source": "telegram:@earnmoneyfast_bot", "target": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "relation": "Crypto deposit address", "threat_level": "critical"},
                {"source": "telegram:@earnmoneyfast_bot", "target": "phone:+918234567890", "relation": "Admin contact", "threat_level": "high"},
            ],
        },
    },

    "lookup_upi_osint:rajeshk.mule03@ybl": {
        "status": "fallback",
        "query": "rajeshk.mule03@ybl",
        "evidence": {
            "summary": "Confirmed UPI mule account on PhonePe (YBL/Yes Bank). High-velocity inbound transactions consistent with scam fund collection.",
            "details": {
                "vpa": "rajeshk.mule03@ybl",
                "vpa_valid": True,
                "psp": "PhonePe (Yes Bank Ltd)",
                "bank_ifsc_prefix": "YESB",
                "account_holder_hint": "Rajesh K",
                "account_age_days": 210,
                "transaction_velocity": {
                    "daily_avg_inbound": 47,
                    "daily_avg_outbound": 3,
                    "peak_day_inbound": 182,
                    "avg_inbound_amount": 4850,
                },
                "mule_flags": [
                    "VELOCITY_ANOMALY: 47 inbound tx/day vs 3 outbound — classic mule pattern",
                    "AMOUNT_CLUSTERING: 83% of inbound between ₹1,500 and ₹25,000 (activation fee range)",
                    "NEW_ACCOUNT: Created 210 days ago, immediately high-volume",
                    "MULTI_SOURCE: Inbound from 400+ unique senders",
                ],
                "linked_complaints": 34,
                "i4c_freeze_status": "Not frozen (pending)",
                "total_inbound_volume": "₹1,42,38,000 (~₹1.42 Cr)",
            },
            "risk_indicators": [
                "High-velocity inbound (47 tx/day) with minimal outbound (3 tx/day)",
                "Amount clustering in ₹1,500-₹25,000 range matches scam deposit pattern",
                "34 linked complaints on NCRP portal",
                "Account age 210 days with immediate high-volume activity",
            ],
        },
        "risk_score": 89,
        "graph": {
            "nodes": [
                {"id": "upi:rajeshk.mule03@ybl", "label": "UPI Mule\nrajeshk.mule03@ybl", "type": "upi", "threat_level": "critical"},
                {"id": "person:RajeshKumar", "label": "Account Holder\nRajesh Kumar", "type": "person", "threat_level": "high"},
                {"id": "exchange:WazirX", "label": "WazirX\nP2P Desk", "type": "exchange", "threat_level": "high"},
            ],
            "edges": [
                {"source": "upi:rajeshk.mule03@ybl", "target": "person:RajeshKumar", "relation": "KYC registered to", "threat_level": "high"},
                {"source": "upi:rajeshk.mule03@ybl", "target": "exchange:WazirX", "relation": "Funds transferred via IMPS", "threat_level": "high"},
            ],
        },
    },

    "lookup_upi_osint:priya.sharma88@paytm": {
        "status": "fallback",
        "query": "priya.sharma88@paytm",
        "evidence": {
            "summary": "Confirmed UPI mule account on Paytm. Flagged by Paytm fraud detection team. High-velocity collection linked to job scam network.",
            "details": {
                "vpa": "priya.sharma88@paytm",
                "vpa_valid": True,
                "psp": "Paytm Payments Bank Ltd",
                "bank_ifsc_prefix": "PYTM",
                "account_holder_hint": "Priya S",
                "account_age_days": 185,
                "transaction_velocity": {
                    "daily_avg_inbound": 38,
                    "daily_avg_outbound": 2,
                    "peak_day_inbound": 156,
                    "avg_inbound_amount": 5200,
                },
                "mule_flags": [
                    "PSP_FLAGGED: Paytm fraud team flagged on 2025-09-20",
                    "VELOCITY_ANOMALY: 38 inbound tx/day",
                    "AMOUNT_CLUSTERING: 79% of inbound between ₹2,000 and ₹20,000",
                ],
                "linked_complaints": 28,
                "i4c_freeze_status": "Frozen (since 2025-10-05)",
                "total_inbound_volume": "₹1,08,72,000 (~₹1.09 Cr)",
            },
            "risk_indicators": [
                "PSP-flagged mule account (Paytm internal fraud alert)",
                "38 inbound tx/day, only 2 outbound — fund collection pattern",
                "28 linked NCRP complaints",
                "Account frozen by I4C since 2025-10-05",
            ],
        },
        "risk_score": 91,
        "graph": {
            "nodes": [
                {"id": "upi:priya.sharma88@paytm", "label": "UPI Mule\npriya.sharma88@paytm", "type": "upi", "threat_level": "critical"},
                {"id": "person:PriyaSharma", "label": "Account Holder\nPriya Sharma", "type": "person", "threat_level": "high"},
                {"id": "exchange:WazirX", "label": "WazirX\nP2P Desk", "type": "exchange", "threat_level": "high"},
            ],
            "edges": [
                {"source": "upi:priya.sharma88@paytm", "target": "person:PriyaSharma", "relation": "KYC registered to", "threat_level": "high"},
                {"source": "upi:priya.sharma88@paytm", "target": "exchange:WazirX", "relation": "Funds transferred via NEFT", "threat_level": "high"},
            ],
        },
    },

    "lookup_upi_osint:vikram.ops@axl": {
        "status": "fallback",
        "query": "vikram.ops@axl",
        "evidence": {
            "summary": "Primary operator UPI on Axis Bank. Highest volume mule in the DhanChor network. Partial I4C freeze — ₹18.4 lakh recovered.",
            "details": {
                "vpa": "vikram.ops@axl",
                "vpa_valid": True,
                "psp": "Axis Bank (AXL handle)",
                "bank_ifsc_prefix": "UTIB",
                "account_holder_hint": "Vikram S",
                "account_age_days": 240,
                "transaction_velocity": {
                    "daily_avg_inbound": 62,
                    "daily_avg_outbound": 5,
                    "peak_day_inbound": 231,
                    "avg_inbound_amount": 6100,
                },
                "mule_flags": [
                    "HIGHEST_VOLUME: Primary collection mule — ₹2.71 Cr total inbound",
                    "OPERATOR_LINK: Phone +918234567890 linked to this KYC",
                    "RTGS_OUTBOUND: Large RTGS transfers to exchange accounts",
                ],
                "linked_complaints": 51,
                "i4c_freeze_status": "Partial freeze — ₹18,40,000 recovered",
                "total_inbound_volume": "₹2,71,46,000 (~₹2.71 Cr)",
            },
            "risk_indicators": [
                "Highest-volume mule: 62 inbound tx/day, ₹2.71 Cr total",
                "51 linked NCRP complaints — most of any mule in network",
                "Linked to operator phone +918234567890",
                "RTGS outbound to exchange suggests direct crypto conversion",
            ],
        },
        "risk_score": 94,
        "graph": {
            "nodes": [
                {"id": "upi:vikram.ops@axl", "label": "UPI Mule\nvikram.ops@axl", "type": "upi", "threat_level": "critical"},
                {"id": "person:VikramSingh", "label": "Operator\nVikram Singh", "type": "person", "threat_level": "critical"},
                {"id": "phone:+918234567890", "label": "Phone\n+91-82345-67890", "type": "phone", "threat_level": "high"},
                {"id": "exchange:WazirX", "label": "WazirX\nP2P Desk", "type": "exchange", "threat_level": "high"},
            ],
            "edges": [
                {"source": "upi:vikram.ops@axl", "target": "person:VikramSingh", "relation": "KYC registered to", "threat_level": "critical"},
                {"source": "person:VikramSingh", "target": "phone:+918234567890", "relation": "Phone registered to", "threat_level": "high"},
                {"source": "upi:vikram.ops@axl", "target": "exchange:WazirX", "relation": "Funds via RTGS", "threat_level": "high"},
            ],
        },
    },

    "lookup_crypto_wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr": {
        "status": "fallback",
        "query": "TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr",
        "chain": "TRON",
        "evidence": {
            "summary": "TRON collection wallet receiving USDT-TRC20 from WazirX P2P purchases. Primary aggregation point before wash wallet layering.",
            "details": {
                "address": "TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr",
                "chain": "TRON",
                "balance": {"TRX": 3240.10, "USDT-TRC20": 128450.00},
                "total_transactions": 1583,
                "first_seen": "2025-07-20T11:04:33Z",
                "last_seen": "2026-11-18T22:17:45Z",
                "inbound_volume_usdt": 5842000,
                "outbound_volume_usdt": 5713550,
                "top_counterparties": [
                    {"address": "TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "tx_count": 342, "volume_usdt": 4230000, "label": "Wash Wallet"},
                    {"address": "TDqVegmPEb4Mce8LfNRguX2KFM2sUqpVgP", "tx_count": 218, "volume_usdt": 1612000, "label": "WazirX Hot Wallet"},
                ],
                "risk_flags": [
                    "COLLECTION_PATTERN: Aggregates from exchange then forwards to wash wallet",
                    "SINGLE_DESTINATION: 73% of outbound goes to one wallet (wash)",
                ],
            },
            "risk_indicators": [
                "Collection wallet aggregating $5.84M USDT from exchange",
                "73% of outbound to single wash wallet — classic layering setup",
                "Connected to WazirX P2P for INR-to-USDT conversion",
            ],
        },
        "risk_score": 88,
        "graph": {
            "nodes": [
                {"id": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "label": "TRON Collection\nTN7Ffh...Fhr", "type": "wallet", "threat_level": "critical"},
                {"id": "exchange:WazirX", "label": "WazirX\nP2P Desk", "type": "exchange", "threat_level": "high"},
                {"id": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "label": "TRON Wash\nTJFoS6...bU1", "type": "wallet", "threat_level": "critical"},
            ],
            "edges": [
                {"source": "exchange:WazirX", "target": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "relation": "USDT purchased (P2P)", "threat_level": "high"},
                {"source": "wallet:TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "target": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "relation": "Layered (342 tx, $4.23M)", "threat_level": "critical"},
            ],
        },
    },

    "lookup_crypto_wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1": {
        "status": "fallback",
        "query": "TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1",
        "chain": "TRON",
        "evidence": {
            "summary": "TRON wash wallet. High-velocity layering with Tornado Cash mixer interaction and Huobi exchange cash-out.",
            "details": {
                "address": "TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1",
                "chain": "TRON",
                "balance": {"TRX": 12450.82, "USDT-TRC20": 847293.50},
                "total_transactions": 2847,
                "first_seen": "2025-08-14T03:22:11Z",
                "last_seen": "2026-11-19T14:33:07Z",
                "transaction_velocity": "178 tx/week",
                "top_counterparties": [
                    {"address": "TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr", "tx_count": 342, "volume_usdt": 4230000, "label": "Collection Wallet"},
                    {"address": "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb", "tx_count": 89, "volume_usdt": 2140000, "label": "Tornado Cash Router"},
                    {"address": "TKzxdSv2FZKQrEqkKVgp5DcwEXBXkUGnJh", "tx_count": 67, "volume_usdt": 1870000, "label": "Huobi Hot Wallet"},
                ],
                "risk_flags": [
                    "MIXER_INTERACTION: 89 tx with Tornado Cash",
                    "EXCHANGE_CASHOUT: 67 tx to Huobi ($1.87M)",
                    "LAYERING: Split-and-merge pattern across 12 intermediate wallets",
                    "HIGH_VELOCITY: 178 tx/week sustained",
                ],
            },
            "risk_indicators": [
                "Tornado Cash interaction — 89 transactions ($2.14M USDT)",
                "Huobi cash-out — 67 transactions ($1.87M USDT)",
                "178 tx/week velocity with layering pattern",
                "USDT-TRC20 balance $847K suggests active operations",
            ],
        },
        "risk_score": 96,
        "graph": {
            "nodes": [
                {"id": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "label": "TRON Wash\nTJFoS6...bU1", "type": "wallet", "threat_level": "critical"},
                {"id": "mixer:TornadoCash", "label": "Tornado Cash\nMixer", "type": "mixer", "threat_level": "critical"},
                {"id": "exchange:Huobi", "label": "Huobi\nExchange", "type": "exchange", "threat_level": "high"},
            ],
            "edges": [
                {"source": "wallet:TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1", "target": "mixer:TornadoCash", "relation": "Mixed through (89 tx, $2.14M)", "threat_level": "critical"},
                {"source": "mixer:TornadoCash", "target": "exchange:Huobi", "relation": "Post-mix cash-out (67 tx)", "threat_level": "critical"},
            ],
        },
    },

    "lookup_domain_whois_dns:earn-daily-income.in": {
        "status": "fallback",
        "query": "earn-daily-income.in",
        "evidence": {
            "summary": "Recently registered .in domain used as landing page for Telegram job scam. Privacy-protected WHOIS. Hosted on DigitalOcean Singapore.",
            "details": {
                "domain": "earn-daily-income.in",
                "registrar": "NameSilo LLC",
                "created": "2025-06-10",
                "expires": "2026-06-10",
                "updated": "2025-06-10",
                "registrant": "REDACTED FOR PRIVACY (NameSilo Privacy)",
                "nameservers": ["ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"],
                "hosting_ip": "45.154.98.221",
                "hosting_provider": "DigitalOcean — Singapore DC",
                "ssl_issuer": "Let's Encrypt",
                "ssl_valid_to": "2026-03-10",
                "content_type": "Single-page task registration form with UPI payment integration",
                "similar_domains": ["earn-fast-money.in", "daily-income-tasks.in", "earn-online-india.in"],
                "phishing_indicators": [
                    "NEWLY_REGISTERED: Domain age < 18 months",
                    "PRIVACY_WHOIS: Registrant hidden behind privacy service",
                    "DISPOSABLE_HOSTING: DigitalOcean droplet (easy to spin up/down)",
                    "KEYWORD_DOMAIN: 'earn-daily-income' is a classic scam keyword pattern",
                ],
            },
            "risk_indicators": [
                "Domain age < 18 months with privacy-protected WHOIS",
                "Hosted on disposable DigitalOcean droplet",
                "Scam keyword pattern in domain name",
                "Similar domains registered (cluster indicator)",
            ],
        },
        "risk_score": 82,
        "graph": {
            "nodes": [
                {"id": "domain:earn-daily-income.in", "label": "Domain\nearn-daily-income.in", "type": "domain", "threat_level": "high"},
                {"id": "ip:45.154.98.221", "label": "Hosting IP\n45.154.98.221\n(DO Singapore)", "type": "ip", "threat_level": "medium"},
            ],
            "edges": [
                {"source": "domain:earn-daily-income.in", "target": "ip:45.154.98.221", "relation": "Hosted on (A record)", "threat_level": "medium"},
            ],
        },
    },

    "lookup_ip_geolocation:45.154.98.221": {
        "status": "fallback",
        "query": "45.154.98.221",
        "evidence": {
            "summary": "DigitalOcean VPS in Singapore. Hosts the earn-daily-income.in scam landing page. No direct C2 indicators but used as disposable infrastructure.",
            "details": {
                "ip": "45.154.98.221",
                "country": "Singapore",
                "country_code": "SG",
                "city": "Singapore",
                "region": "Central Singapore",
                "lat": 1.3521,
                "lon": 103.8198,
                "asn": "AS14061",
                "isp": "DigitalOcean LLC",
                "org": "DigitalOcean LLC",
                "hosting": True,
                "vpn_proxy": False,
                "tor_exit": False,
                "known_c2": False,
                "abuse_reports": 3,
                "reverse_dns": "45.154.98.221.static.cloud-ips.com",
                "open_ports": [80, 443],
                "hosted_domains": ["earn-daily-income.in"],
            },
            "risk_indicators": [
                "Cloud hosting (DigitalOcean) — commonly used as disposable scam infrastructure",
                "Singapore jurisdiction — outside Indian LEA direct reach",
                "3 prior abuse reports on this IP",
            ],
        },
        "risk_score": 55,
        "graph": {
            "nodes": [
                {"id": "ip:45.154.98.221", "label": "IP\n45.154.98.221\n(DigitalOcean SG)", "type": "ip", "threat_level": "medium"},
            ],
            "edges": [],
        },
    },

    "lookup_phone_osint:+918234567890": {
        "status": "fallback",
        "query": "+918234567890",
        "evidence": {
            "summary": "Jio prepaid SIM registered in Uttar Pradesh. Linked to Telegram channel admin and mule account KYC. 12 spam/fraud reports on Truecaller.",
            "details": {
                "number": "+918234567890",
                "valid": True,
                "country": "India",
                "country_code": "IN",
                "carrier": "Reliance Jio",
                "line_type": "Mobile (Prepaid)",
                "region": "Uttar Pradesh — Lucknow circle",
                "is_voip": False,
                "spam_reports": 12,
                "truecaller_name": "Vikram Job Support",
                "linked_upi": ["vikram.ops@axl"],
                "linked_accounts": ["Telegram: @earnmoneyfast_bot (admin)"],
                "first_seen_spam": "2025-07-10",
                "reported_categories": ["Job Scam", "Financial Fraud", "UPI Fraud"],
            },
            "risk_indicators": [
                "12 spam/fraud reports across platforms",
                "Truecaller tag: 'Vikram Job Support' — matches mule identity",
                "Linked to Telegram scam channel as admin",
                "Prepaid SIM — harder to trace post-churn",
            ],
        },
        "risk_score": 78,
        "graph": {
            "nodes": [
                {"id": "phone:+918234567890", "label": "Phone\n+91-82345-67890", "type": "phone", "threat_level": "high"},
                {"id": "person:VikramSingh", "label": "Operator\nVikram Singh", "type": "person", "threat_level": "critical"},
            ],
            "edges": [
                {"source": "phone:+918234567890", "target": "person:VikramSingh", "relation": "Registered to / Truecaller match", "threat_level": "high"},
            ],
        },
    },

    # ======================================================================
    # CASE 102 fallback data
    # ======================================================================
    "lookup_domain_whois_dns:bijli-pay-india.com": {
        "status": "fallback",
        "query": "bijli-pay-india.com",
        "evidence": {
            "summary": "Phishing domain impersonating Indian electricity bill payment portal. Distributes SMS-stealing APK. NameCheap registration with WHOIS privacy.",
            "details": {
                "domain": "bijli-pay-india.com",
                "registrar": "NameCheap Inc.",
                "created": "2025-04-02",
                "expires": "2026-04-02",
                "updated": "2025-04-02",
                "registrant": "WhoisGuard Protected — WhoisGuard Inc.",
                "registrant_country": "Panama (privacy service)",
                "nameservers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
                "hosting_ip": "103.74.19.104",
                "hosting_provider": "Hostinger — Mumbai, India",
                "ssl_issuer": "Let's Encrypt",
                "ssl_valid_to": "2026-01-15",
                "content_type": "Fake electricity bill payment portal with APK download",
                "phishing_indicators": [
                    "BRAND_IMPERSONATION: 'bijli-pay-india' mimics state electricity board portals",
                    "APK_DISTRIBUTION: Page serves bijli_pay_v2.3.apk on Android user-agent",
                    "NEWLY_REGISTERED: Domain age < 20 months",
                    "PRIVACY_WHOIS: Panama-based privacy service",
                    "CERT-IN_LISTED: Domain on CERT-In phishing takedown list since 2026-06-01",
                ],
            },
            "risk_indicators": [
                "Phishing domain impersonating electricity payment service",
                "Distributes malicious APK (bijli_pay_v2.3.apk)",
                "WHOIS privacy via Panama — common in phishing campaigns",
                "Listed on CERT-In takedown list",
            ],
        },
        "risk_score": 97,
        "graph": {
            "nodes": [
                {"id": "domain:bijli-pay-india.com", "label": "Phishing Site\nbijli-pay-india.com", "type": "domain", "threat_level": "critical"},
                {"id": "ip:103.74.19.104", "label": "C2 Server\n103.74.19.104", "type": "ip", "threat_level": "critical"},
                {"id": "apk:bijli_pay_v2.3", "label": "Malicious APK\nbijli_pay_v2.3.apk", "type": "apk", "threat_level": "critical"},
                {"id": "registrar:NameCheap", "label": "Registrar\nNameCheap", "type": "domain", "threat_level": "medium"},
            ],
            "edges": [
                {"source": "domain:bijli-pay-india.com", "target": "ip:103.74.19.104", "relation": "Hosted on", "threat_level": "critical"},
                {"source": "domain:bijli-pay-india.com", "target": "apk:bijli_pay_v2.3", "relation": "Distributes malware", "threat_level": "critical"},
                {"source": "domain:bijli-pay-india.com", "target": "registrar:NameCheap", "relation": "Registered via", "threat_level": "medium"},
            ],
        },
    },

    "lookup_ip_geolocation:103.74.19.104": {
        "status": "fallback",
        "query": "103.74.19.104",
        "evidence": {
            "summary": "Hostinger VPS in Mumbai hosting the C2 server and phishing panel for Operation Vidyut. Admin panel detected at /admin/dashboard.",
            "details": {
                "ip": "103.74.19.104",
                "country": "India",
                "country_code": "IN",
                "city": "Mumbai",
                "region": "Maharashtra",
                "lat": 19.076,
                "lon": 72.8777,
                "asn": "AS47583",
                "isp": "Hostinger International Ltd",
                "org": "Hostinger",
                "hosting": True,
                "vpn_proxy": False,
                "tor_exit": False,
                "known_c2": True,
                "abuse_reports": 47,
                "reverse_dns": "srv42.hostinger.in",
                "open_ports": [22, 80, 443, 8443],
                "hosted_domains": ["bijli-pay-india.com"],
                "c2_indicators": [
                    "PORT_8443: Non-standard HTTPS port — common for C2 panels",
                    "ADMIN_PANEL: /admin/dashboard returns 401 (password-protected panel)",
                    "EXFIL_ENDPOINT: /api/sms/inbox accepts POST — SMS exfiltration receiver",
                    "HIGH_ABUSE: 47 abuse reports on this IP",
                ],
            },
            "risk_indicators": [
                "Confirmed C2 server: SMS exfiltration endpoint detected",
                "Admin panel at /admin/dashboard (port 8443)",
                "47 abuse reports — heavily flagged infrastructure",
                "Indian hosting (Mumbai) — within LEA jurisdiction",
            ],
        },
        "risk_score": 94,
        "graph": {
            "nodes": [
                {"id": "ip:103.74.19.104", "label": "C2 Server\n103.74.19.104\n(Hostinger Mumbai)", "type": "ip", "threat_level": "critical"},
                {"id": "c2:admin_panel", "label": "C2 Panel\n/admin/dashboard", "type": "c2_panel", "threat_level": "critical"},
            ],
            "edges": [
                {"source": "ip:103.74.19.104", "target": "c2:admin_panel", "relation": "Hosts admin panel (port 8443)", "threat_level": "critical"},
            ],
        },
    },

    "lookup_telegram_threat_intel:@bijli_helpdesk": {
        "status": "fallback",
        "query": "@bijli_helpdesk",
        "evidence": {
            "summary": "Fake customer support Telegram channel for bijli-pay-india.com phishing site. Misdirects victims reporting issues. Linked to operator Amit Verma.",
            "details": {
                "handle": "@bijli_helpdesk",
                "channel_name": "Bijli Pay India — Customer Support",
                "created": "2025-05-20",
                "subscriber_count": 3842,
                "posting_frequency": "2-3 posts/day",
                "language": "Hindi",
                "linked_domains": ["bijli-pay-india.com"],
                "admin_contacts": ["+917891234560"],
                "misdirection_tactics": [
                    "Tells victims 'payment is processing, wait 48 hours'",
                    "Asks victims to reinstall APK for 'updated version'",
                    "Provides fake 'complaint number' to delay police reports",
                ],
                "associated_groups": ["APK-Dropper-Ring-MH", "OTP-Stealer-Network"],
            },
            "risk_indicators": [
                "Fake support channel for known phishing domain",
                "Misdirection tactics to delay victim reporting",
                "Linked to APK dropper and OTP stealer threat groups",
                "Admin phone matches SMS campaign number",
            ],
        },
        "risk_score": 83,
        "graph": {
            "nodes": [
                {"id": "telegram:@bijli_helpdesk", "label": "Fake Support\n@bijli_helpdesk", "type": "telegram", "threat_level": "high"},
                {"id": "person:AmitVerma", "label": "Operator\nAmit Verma", "type": "person", "threat_level": "critical"},
                {"id": "domain:bijli-pay-india.com", "label": "Phishing Site\nbijli-pay-india.com", "type": "domain", "threat_level": "critical"},
            ],
            "edges": [
                {"source": "telegram:@bijli_helpdesk", "target": "domain:bijli-pay-india.com", "relation": "Fake support for", "threat_level": "high"},
                {"source": "telegram:@bijli_helpdesk", "target": "person:AmitVerma", "relation": "Administered by", "threat_level": "high"},
            ],
        },
    },

    "lookup_phone_osint:+917891234560": {
        "status": "fallback",
        "query": "+917891234560",
        "evidence": {
            "summary": "Bulk SMS SIM used for phishing campaign. Airtel prepaid, Maharashtra circle. 87 spam reports. Linked to bijli-pay-india.com campaign.",
            "details": {
                "number": "+917891234560",
                "valid": True,
                "country": "India",
                "country_code": "IN",
                "carrier": "Bharti Airtel",
                "line_type": "Mobile (Prepaid)",
                "region": "Maharashtra — Mumbai circle",
                "is_voip": False,
                "spam_reports": 87,
                "truecaller_name": "SPAM — Electricity Scam",
                "linked_upi": [],
                "linked_accounts": ["Telegram: @bijli_helpdesk (admin)"],
                "first_seen_spam": "2025-04-12",
                "reported_categories": ["Phishing", "Malware Distribution", "Financial Fraud"],
                "sms_volume_estimate": "15,000+ messages sent in first 30 days",
            },
            "risk_indicators": [
                "87 spam/fraud reports — extremely high",
                "Bulk SMS sending pattern (15K+ in 30 days)",
                "Truecaller universally tagged as SPAM",
                "Linked to @bijli_helpdesk Telegram channel",
            ],
        },
        "risk_score": 86,
        "graph": {
            "nodes": [
                {"id": "phone:+917891234560", "label": "SMS Campaign\n+91-78912-34560", "type": "phone", "threat_level": "high"},
                {"id": "domain:bijli-pay-india.com", "label": "Phishing Site\nbijli-pay-india.com", "type": "domain", "threat_level": "critical"},
            ],
            "edges": [
                {"source": "phone:+917891234560", "target": "domain:bijli-pay-india.com", "relation": "SMS links to phishing site", "threat_level": "high"},
            ],
        },
    },

    "lookup_upi_osint:quickpay.merchant@oksbi": {
        "status": "fallback",
        "query": "quickpay.merchant@oksbi",
        "evidence": {
            "summary": "SBI merchant UPI used as the primary collection account for Operation Vidyut. ₹8.7 crore inbound from drained victim accounts.",
            "details": {
                "vpa": "quickpay.merchant@oksbi",
                "vpa_valid": True,
                "psp": "State Bank of India (OKSBI handle)",
                "bank_ifsc_prefix": "SBIN",
                "account_holder_hint": "QuickPay Digital Services",
                "account_type": "Current Account (Merchant)",
                "account_age_days": 320,
                "transaction_velocity": {
                    "daily_avg_inbound": 83,
                    "daily_avg_outbound": 2,
                    "peak_day_inbound": 347,
                    "avg_inbound_amount": 28700,
                },
                "mule_flags": [
                    "MERCHANT_ABUSE: Merchant VPA used for fraudulent collections",
                    "EXTREME_VELOCITY: 83 inbound tx/day from unique victims",
                    "HIGH_VALUE: Average ₹28,700 per transaction — drained savings",
                    "SINGLE_OUTBOUND: Most outbound to one SBI account (XX4521)",
                ],
                "linked_complaints": 142,
                "i4c_freeze_status": "Frozen (since 2026-01-20)",
                "total_inbound_volume": "₹8,71,42,000 (~₹8.71 Cr)",
            },
            "risk_indicators": [
                "142 linked NCRP complaints — highest in this network",
                "Merchant VPA abused for victim fund collection",
                "₹8.71 Cr total inbound — massive fraud proceeds",
                "Frozen by I4C since 2026-01-20",
            ],
        },
        "risk_score": 97,
        "graph": {
            "nodes": [
                {"id": "upi:quickpay.merchant@oksbi", "label": "Collection UPI\nquickpay.merchant@oksbi", "type": "upi", "threat_level": "critical"},
                {"id": "bank:SBI_XX4521", "label": "SBI Account\nXX4521", "type": "bank", "threat_level": "high"},
                {"id": "person:AmitVerma", "label": "Operator\nAmit Verma", "type": "person", "threat_level": "critical"},
            ],
            "edges": [
                {"source": "upi:quickpay.merchant@oksbi", "target": "bank:SBI_XX4521", "relation": "Linked bank account", "threat_level": "high"},
                {"source": "person:AmitVerma", "target": "upi:quickpay.merchant@oksbi", "relation": "Controls", "threat_level": "critical"},
            ],
        },
    },

    "lookup_crypto_wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68": {
        "status": "fallback",
        "query": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68",
        "chain": "ETH",
        "evidence": {
            "summary": "Ethereum wallet receiving INR-to-ETH conversions from Indian exchanges. Funds forwarded to Sinbad.io mixer. Part of Operation Vidyut laundering chain.",
            "details": {
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68",
                "chain": "ETH",
                "balance": {"ETH": 14.283, "USDT-ERC20": 42180.00},
                "total_transactions": 892,
                "first_seen": "2025-08-01T09:14:22Z",
                "last_seen": "2026-11-17T18:42:11Z",
                "inbound_volume_eth": 312.7,
                "outbound_volume_eth": 298.4,
                "top_counterparties": [
                    {"address": "0x28C6c06298d514Db089934071355E5743bf21d60", "tx_count": 94, "label": "Binance Hot Wallet"},
                    {"address": "0x3CBdeD43EFdAf0FC77b9C55F6fC9988fCC9b757d", "tx_count": 142, "label": "Sinbad.io Deposit"},
                    {"address": "0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2", "tx_count": 38, "label": "WazirX Hot Wallet"},
                ],
                "risk_flags": [
                    "MIXER_INTERACTION: 142 tx with Sinbad.io",
                    "EXCHANGE_SOURCED: Inbound from Indian exchanges (WazirX, CoinDCX)",
                    "LAYERING: Split transactions across 8 intermediate wallets before mixer",
                ],
            },
            "risk_indicators": [
                "Sinbad.io mixer interaction — 142 deposits",
                "Funds sourced from Indian exchanges post INR conversion",
                "Layering pattern with 8 intermediate wallets",
                "312.7 ETH total volume (~$780K at avg price)",
            ],
        },
        "risk_score": 93,
        "graph": {
            "nodes": [
                {"id": "wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "label": "ETH Wallet\n0x742d...bD68", "type": "wallet", "threat_level": "critical"},
                {"id": "mixer:Sinbad", "label": "Sinbad.io\nMixer", "type": "mixer", "threat_level": "critical"},
                {"id": "bank:SBI_XX4521", "label": "SBI Account\nXX4521", "type": "bank", "threat_level": "high"},
            ],
            "edges": [
                {"source": "bank:SBI_XX4521", "target": "wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "relation": "INR converted to ETH", "threat_level": "critical"},
                {"source": "wallet:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "target": "mixer:Sinbad", "relation": "Mixed (142 deposits)", "threat_level": "critical"},
            ],
        },
    },

    "lookup_crypto_wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": {
        "status": "fallback",
        "query": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "chain": "BTC",
        "evidence": {
            "summary": "Bitcoin wallet receiving post-mixer output from Sinbad.io. Final cash-out layer via Binance. 23.4 BTC cashed out.",
            "details": {
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "chain": "BTC",
                "balance": {"BTC": 1.847},
                "total_transactions": 234,
                "first_seen": "2025-10-15T06:33:19Z",
                "last_seen": "2026-11-14T21:08:44Z",
                "inbound_volume_btc": 25.2,
                "outbound_volume_btc": 23.4,
                "top_counterparties": [
                    {"address": "bc1q5shngj24323nsrmxv99st02na6srekfctt30ch", "tx_count": 68, "label": "Sinbad.io Output"},
                    {"address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "tx_count": 42, "label": "Binance Deposit"},
                ],
                "risk_flags": [
                    "MIXER_OUTPUT: Receives from Sinbad.io post-mix addresses",
                    "EXCHANGE_CASHOUT: 23.4 BTC sent to Binance ($1.6M at time)",
                    "CROSS_CHAIN: ETH→Mixer→BTC chain hop detected",
                ],
            },
            "risk_indicators": [
                "Post-mixer BTC wallet — Sinbad.io output recipient",
                "23.4 BTC cashed out via Binance",
                "Cross-chain laundering: ETH → Sinbad mixer → BTC → Binance",
            ],
        },
        "risk_score": 91,
        "graph": {
            "nodes": [
                {"id": "wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "label": "BTC Wallet\nbc1qxy2...wlh", "type": "wallet", "threat_level": "critical"},
                {"id": "mixer:Sinbad", "label": "Sinbad.io\nMixer", "type": "mixer", "threat_level": "critical"},
                {"id": "exchange:Binance", "label": "Binance\nExchange", "type": "exchange", "threat_level": "high"},
            ],
            "edges": [
                {"source": "mixer:Sinbad", "target": "wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "relation": "Post-mix BTC output", "threat_level": "critical"},
                {"source": "wallet:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "target": "exchange:Binance", "relation": "Cash-out (23.4 BTC)", "threat_level": "critical"},
            ],
        },
    },
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def get_case(case_id: str) -> dict:
    """Return a case definition by ID. Returns empty dict if not found."""
    return CASES.get(case_id, {})


def get_fallback(tool_name: str, query: str) -> dict:
    """Return fallback data for a tool+query combination. Returns None if no fallback exists."""
    key = f"{tool_name}:{query}"
    return FALLBACK_DATA.get(key)


def get_case_for_entity(entity: str) -> dict:
    """Check if an entity belongs to a pre-seeded case. Returns the case dict or None."""
    entity = entity.strip()
    for case_id, case in CASES.items():
        if entity == case.get("primary_entity"):
            return case
        for ent_type, ent_values in case.get("all_entities", {}).items():
            if isinstance(ent_values, list) and entity in ent_values:
                return case
            elif isinstance(ent_values, str) and entity == ent_values:
                return case
    return None


def get_all_case_tools(case: dict) -> list:
    """Given a case dict, return a list of (tool_name, kwargs) for all entities."""
    tool_calls = []
    ents = case.get("all_entities", {})
    for tg in ents.get("telegram", []):
        tool_calls.append(("lookup_telegram_threat_intel", {"handle_or_channel": tg}))
    for upi in ents.get("upi", []):
        tool_calls.append(("lookup_upi_osint", {"upi_id": upi}))
    for addr in ents.get("crypto_tron", []):
        tool_calls.append(("lookup_crypto_wallet", {"address": addr, "chain": "TRON"}))
    for addr in ents.get("crypto_eth", []):
        tool_calls.append(("lookup_crypto_wallet", {"address": addr, "chain": "ETH"}))
    for addr in ents.get("crypto_btc", []):
        tool_calls.append(("lookup_crypto_wallet", {"address": addr, "chain": "BTC"}))
    for dom in ents.get("domain", []):
        tool_calls.append(("lookup_domain_whois_dns", {"domain": dom}))
    for ip in ents.get("ip", []):
        tool_calls.append(("lookup_ip_geolocation", {"ip_address": ip}))
    for ph in ents.get("phone", []):
        tool_calls.append(("lookup_phone_osint", {"phone_number": ph}))
    return tool_calls
