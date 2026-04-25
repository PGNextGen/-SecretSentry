"""Stage 4: Prefix Intelligence — 35+ known provider prefix database."""

import re

from ..models import ScanContext
from ..utils import is_comment

PREFIX_DB = [
    {"prefix": "AKIA",        "provider": "AWS",       "type": "Access Key ID",       "length": 20, "score": 95},
    {"prefix": "ABIA",        "provider": "AWS",       "type": "STS Token",           "length": 20, "score": 85},
    {"prefix": "ACCA",        "provider": "AWS",       "type": "Context Key",         "length": 20, "score": 85},
    {"prefix": "ASIA",        "provider": "AWS",       "type": "Temp Credentials",    "length": 20, "score": 90},
    {"prefix": "AIza",        "provider": "Google",    "type": "API Key",             "length": 39, "score": 90},
    {"prefix": "ghp_",        "provider": "GitHub",    "type": "Personal Token",      "length": 40, "score": 95},
    {"prefix": "gho_",        "provider": "GitHub",    "type": "OAuth Token",         "length": 40, "score": 90},
    {"prefix": "ghu_",        "provider": "GitHub",    "type": "User Token",          "length": 40, "score": 90},
    {"prefix": "ghs_",        "provider": "GitHub",    "type": "Server Token",        "length": 40, "score": 90},
    {"prefix": "ghr_",        "provider": "GitHub",    "type": "Refresh Token",       "length": 40, "score": 90},
    {"prefix": "glpat-",      "provider": "GitLab",    "type": "Personal Token",      "length": 26, "score": 90},
    {"prefix": "sk_live_",    "provider": "Stripe",    "type": "Live Secret Key",     "length": 32, "score": 95},
    {"prefix": "rk_live_",    "provider": "Stripe",    "type": "Restricted Key",      "length": 32, "score": 90},
    {"prefix": "sk_test_",    "provider": "Stripe",    "type": "Test Secret Key",     "length": 32, "score": 50},
    {"prefix": "pk_live_",    "provider": "Stripe",    "type": "Live Publishable",    "length": 32, "score": 60},
    {"prefix": "SG.",         "provider": "SendGrid",  "type": "API Key",             "length": 69, "score": 95},
    {"prefix": "xoxb-",       "provider": "Slack",     "type": "Bot Token",           "length": 50, "score": 90},
    {"prefix": "xoxp-",       "provider": "Slack",     "type": "User Token",          "length": 50, "score": 90},
    {"prefix": "xoxa-",       "provider": "Slack",     "type": "App Token",           "length": 50, "score": 90},
    {"prefix": "xoxr-",       "provider": "Slack",     "type": "Refresh Token",       "length": 50, "score": 90},
    {"prefix": "sq0atp-",     "provider": "Square",    "type": "Access Token",        "length": 30, "score": 90},
    {"prefix": "sq0csp-",     "provider": "Square",    "type": "Secret",              "length": 50, "score": 90},
    {"prefix": "pypi-",       "provider": "PyPI",      "type": "API Token",           "length": 50, "score": 90},
    {"prefix": "npm_",        "provider": "npm",       "type": "Access Token",        "length": 36, "score": 90},
    {"prefix": "eyJ",         "provider": "JWT",       "type": "JSON Web Token",      "length": 30, "score": 65},
    {"prefix": "key-",        "provider": "Mailgun",   "type": "API Key",             "length": 36, "score": 85},
    {"prefix": "SK",          "provider": "Twilio",    "type": "API Key",             "length": 34, "score": 75},
    {"prefix": "amzn.mws.",   "provider": "Amazon",    "type": "MWS Key",             "length": 40, "score": 90},
    {"prefix": "shpat_",      "provider": "Shopify",   "type": "Access Token",        "length": 40, "score": 90},
    {"prefix": "shpca_",      "provider": "Shopify",   "type": "Custom App Token",    "length": 40, "score": 90},
    {"prefix": "shppa_",      "provider": "Shopify",   "type": "Private App Token",   "length": 40, "score": 90},
    {"prefix": "whsec_",      "provider": "Stripe",    "type": "Webhook Secret",      "length": 40, "score": 85},
    {"prefix": "AC",          "provider": "Twilio",    "type": "Account SID",         "length": 34, "score": 70},
    {"prefix": "dop_v1_",     "provider": "DigitalOcean", "type": "Personal Token",   "length": 64, "score": 90},
    {"prefix": "v2.",         "provider": "Cloudflare","type": "API Token",           "length": 40, "score": 80},
]


def has_known_prefix(value: str) -> bool:
    return any(value.startswith(p["prefix"]) for p in PREFIX_DB)


def stage_prefix_intelligence(ctx: ScanContext) -> None:
    """Scan all lines for known provider prefixes."""
    all_values = []

    for line_num, line in enumerate(ctx.normalized_lines, 1):
        stripped = line.strip()
        if not stripped or is_comment(stripped):
            continue
        for m in re.finditer(r"['\"]([^'\"]{8,})['\"]", line):
            all_values.append((line_num, m.group(1), line, "quoted"))
        m = re.search(r"[\w.]+\s*[=:]\s*(\S{8,})", line)
        if m:
            all_values.append((line_num, m.group(1), line, "unquoted"))

    for dv in ctx.decoded_values:
        all_values.append((dv["line"], dv["decoded"], dv["original_line"], f"decoded:{dv['encoding']}"))
    for rv in ctx.reconstructed_values:
        all_values.append((rv["line"], rv["value"], rv["original_line"], f"reconstructed:{rv['method']}"))

    seen = set()
    for line_num, value, original_line, source in all_values:
        for pinfo in PREFIX_DB:
            if value.startswith(pinfo["prefix"]):
                dedup = (line_num, pinfo["provider"], pinfo["type"])
                if dedup in seen:
                    continue
                seen.add(dedup)
                ctx.prefix_hits.append({
                    "line": line_num, "value": value,
                    "provider": pinfo["provider"], "type": pinfo["type"],
                    "expected_length": pinfo["length"], "base_score": pinfo["score"],
                    "source": source, "original_line": original_line,
                })
