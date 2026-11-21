"""
ShadowTrace — Universal Entity Detector & Normalizer
Accurately categorizes and normalizes:
- Crypto Wallets (EVM 0x..., TRON T..., Bitcoin 1/3/bc1...)
- Indian UPI VPAs (name@psp, upi://pay links)
- Phone Numbers (10-digit Indian mobiles without +, +91, 0..., international)
- Telegram Handles, Channels & URLs (t.me/xxx, @xxx, xxx_bot)
- Domain Names & Full URLs (http://..., https://..., naked domains)
- IPv4 & IPv6 Addresses
"""

import re
import ipaddress
from typing import Tuple


def detect_and_normalize_entity(raw_input: str) -> Tuple[str, str, str]:
    """Detect entity category, return (category, normalized_value, human_label).

    Categories:
        - "evm_wallet"     (Ethereum, BSC, Polygon, Arbitrum, Base)
        - "tron_wallet"    (TRON TRC-20)
        - "btc_wallet"     (Bitcoin)
        - "upi"            (Indian Unified Payments Interface VPA)
        - "telegram"       (Telegram Handle or Channel)
        - "phone"          (E.164 Phone Number)
        - "domain"         (FQDN Hostname)
        - "ip"             (IP Address)
        - "unknown"        (Unclassified)
    """
    raw = raw_input.strip()
    if not raw:
        return "unknown", "", "Empty Input"

    # 1. Telegram URLs & Handles
    # e.g. https://t.me/earnmoneyfast_bot, t.me/s/channel, @handle, my_bot
    if "t.me/" in raw.lower():
        # Handle t.me/s/channel or t.me/channel
        sub = re.sub(r"^https?://", "", raw, flags=re.I)
        parts = sub.split("t.me/")[-1].strip("/").split("/")
        channel = parts[-1].split("?")[0]
        if not channel.startswith("@"):
            channel = "@" + channel
        return "telegram", channel, f"Telegram Channel ({channel})"

    if raw.startswith("@"):
        return "telegram", raw, f"Telegram Handle ({raw})"

    if raw.lower().endswith("_bot") and re.match(r"^[a-zA-Z0-9_]{4,32}$", raw):
        return "telegram", "@" + raw, f"Telegram Bot (@{raw})"

    # 2. Crypto Addresses
    # EVM (Ethereum / Polygon / BSC / Arbitrum / Base): 0x followed by 40 hex chars
    if re.match(r"^0x[0-9a-fA-F]{40}$", raw):
        return "evm_wallet", raw, f"EVM Wallet ({raw[:6]}...{raw[-4:]})"

    # TRON (TRC-20): starts with T, 34 alphanumeric chars
    if re.match(r"^T[a-zA-Z0-9]{33}$", raw):
        return "tron_wallet", raw, f"TRON Wallet ({raw[:6]}...{raw[-4:]})"

    # Bitcoin: 1..., 3..., or bc1...
    if re.match(r"^(1|3)[a-km-zA-HJ-NP-Z1-9]{24,33}$", raw) or re.match(r"^bc1[a-zA-HJ-NP-Z0-9]{25,62}$", raw):
        return "btc_wallet", raw, f"Bitcoin Wallet ({raw[:6]}...{raw[-4:]})"

    # 3. UPI VPAs & Payment Links
    # e.g. user@ybl, rajesh.k@paytm, upi://pay?pa=mule@oksbi
    if "pa=" in raw.lower():
        match = re.search(r"pa=([a-zA-Z0-9._-]+@[a-zA-Z]{2,})", raw, re.I)
        if match:
            vpa = match.group(1).lower()
            return "upi", vpa, f"UPI VPA ({vpa})"

    if re.match(r"^[a-zA-Z0-9._-]+@[a-zA-Z]{2,}$", raw):
        return "upi", raw.lower(), f"UPI VPA ({raw.lower()})"

    # 4. IP Address (IPv4 & IPv6) - Check before phone to avoid period-stripping collisions
    try:
        ip_obj = ipaddress.ip_address(raw)
        return "ip", str(ip_obj), f"IP Address ({ip_obj})"
    except ValueError:
        pass

    # 5. Phone Numbers (Indian mobile & international)
    # Strip spaces, hyphens, parentheses (do not strip dots so IPs aren't confused)
    clean_digits = re.sub(r"[\s\-\(\)]", "", raw)
    if re.match(r"^\+?[0-9]{10,14}$", clean_digits):
        # 10 digits starting with 6, 7, 8, or 9 -> Standard Indian Mobile
        if len(clean_digits) == 10 and clean_digits[0] in "6789":
            normalized_phone = "+91" + clean_digits
            return "phone", normalized_phone, f"Indian Mobile ({clean_digits})"
        # 11 digits starting with 0 followed by 6-9 -> Indian Mobile with trunk 0
        elif clean_digits.startswith("0") and len(clean_digits) == 11 and clean_digits[1] in "6789":
            normalized_phone = "+91" + clean_digits[1:]
            return "phone", normalized_phone, f"Indian Mobile ({clean_digits[1:]})"
        # 12 digits starting with 91 followed by 6-9
        elif clean_digits.startswith("91") and len(clean_digits) == 12 and clean_digits[2] in "6789":
            normalized_phone = "+" + clean_digits
            return "phone", normalized_phone, f"Indian Mobile (+{clean_digits})"
        # Already starts with +
        elif clean_digits.startswith("+"):
            return "phone", clean_digits, f"Phone Number ({clean_digits})"
        elif len(clean_digits) >= 10:
            return "phone", "+" + clean_digits, f"Phone Number (+{clean_digits})"

    # 6. Domain / URL
    # Strip protocol and paths to check hostname
    cleaned_url = re.sub(r"^https?://", "", raw, flags=re.I).rstrip("/")
    domain_candidate = cleaned_url.split("/")[0].split(":")[0].lower()
    if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$", domain_candidate):
        return "domain", domain_candidate, f"Domain Host ({domain_candidate})"

    return "unknown", raw, f"Unclassified Entity ({raw})"
