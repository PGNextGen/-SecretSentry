# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp"]
# ///

from mcp.server.fastmcp import FastMCP
import re
import math
import os
import base64
import binascii
import codecs
from dataclasses import dataclass, field

mcp = FastMCP("secret-sentry")


# ══════════════════════════════════════════════════════════════════
# PIPELINE ARCHITECTURE
#
# Detection now flows through a multi-stage pipeline:
#
#   Raw Code
#     → Stage 1: NORMALIZATION (unicode decode, case normalize)
#     → Stage 2: DECODING (base64, hex, unicode escapes)
#     → Stage 3: RECONSTRUCTION (string concat, split values)
#     → Stage 4: PREFIX INTELLIGENCE (known provider prefixes)
#     → Stage 5: REGEX PATTERN MATCHING (existing 40+ rules)
#     → Stage 6: CONFIDENCE SCORING (6-factor scoring)
#     → Output: Findings sorted by confidence
#
# Each stage produces intermediate results that feed the next.
# ══════════════════════════════════════════════════════════════════


@dataclass
class ScanContext:
    """Shared context passed through all pipeline stages."""
    code: str
    filename: str
    lines: list[str] = field(default_factory=list)
    normalized_lines: list[str] = field(default_factory=list)
    decoded_values: list[dict] = field(default_factory=list)
    reconstructed_values: list[dict] = field(default_factory=list)
    prefix_hits: list[dict] = field(default_factory=list)
    regex_hits: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    is_test: bool = False


# ══════════════════════════════════════════════════════════════════
# STAGE 1: NORMALIZATION
# ══════════════════════════════════════════════════════════════════


def _stage_normalize(ctx: ScanContext) -> None:
    """Normalize unicode tricks, escape sequences, URL encoding, and whitespace."""
    ctx.lines = ctx.code.splitlines()
    ctx.is_test = _is_test_file(ctx.filename)
    normalized = []
    for line in ctx.lines:
        n = line
        # Decode unicode escapes: \u0061 → a
        try:
            n = codecs.decode(n, "unicode_escape")
        except Exception:
            pass
        # Decode hex escapes: \x67 → g
        try:
            n = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), n)
        except Exception:
            pass
        # Normalize common unicode confusables
        n = _normalize_confusables(n)
        normalized.append(n)
    ctx.normalized_lines = normalized


_CONFUSABLE_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",  # Cyrillic
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o",  # Fullwidth
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',  # Smart quotes
})


def _normalize_confusables(s: str) -> str:
    return s.translate(_CONFUSABLE_MAP)


# ══════════════════════════════════════════════════════════════════
# STAGE 2: DECODING
# ══════════════════════════════════════════════════════════════════


def _stage_decode(ctx: ScanContext) -> None:
    """Find and decode base64, hex, URL-encoded, and chained-encoded values."""
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue

        # Extract all potential encoded values from the line
        raw_values = []
        # Quoted values
        for m in re.finditer(r"['\"]([^\s'\"]{12,})['\"]", line):
            raw_values.append(m.group(1))
        # Unquoted assignments
        m = re.search(r"[\w.]+\s*[=:]\s*['\"]?([^\s'\"]{12,})['\"]?", line)
        if m and m.group(1) not in raw_values:
            raw_values.append(m.group(1))

        for raw_value in raw_values:
            # Run chained decode — tries multiple layers
            _decode_chained(ctx, line_num, raw_value, line, max_depth=3)

    # Stage 2b: Simulate command substitution patterns
    _stage_command_substitution(ctx)


def _decode_chained(ctx: ScanContext, line_num: int, value: str,
                    original_line: str, max_depth: int, chain: str = "") -> None:
    """Recursively decode through multiple encoding layers."""
    if max_depth <= 0 or len(value) < 8:
        return

    decoders = [
        ("base64", _try_base64_decode),
        ("hex", _try_hex_decode),
        ("url", _try_url_decode),
    ]

    for enc_name, decoder in decoders:
        decoded = decoder(value)
        if decoded and decoded != value:
            layer = f"{chain}→{enc_name}" if chain else enc_name
            ctx.decoded_values.append({
                "line": line_num,
                "original": value,
                "decoded": decoded,
                "encoding": layer,
                "original_line": original_line,
            })
            # Recurse: try decoding the decoded value (chained transforms)
            _decode_chained(ctx, line_num, decoded, original_line, max_depth - 1, layer)

    # Also try extracting embedded encoded values from decoded JSON
    if value.startswith("{") or value.startswith("["):
        for m in re.finditer(r"['\"]([A-Za-z0-9+/=_-]{16,})['\"]", value):
            inner = m.group(1)
            _decode_chained(ctx, line_num, inner, original_line, max_depth - 1, chain + "→json_extract")


def _stage_command_substitution(ctx: ScanContext) -> None:
    """Simulate common command substitution patterns without execution."""
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        # Pattern: $(echo "BASE64" | base64 --decode)
        m = re.search(r"""\$\(echo\s+['\"]?([A-Za-z0-9+/=_-]{12,})['\"]?\s*\|\s*base64\s+--decode\)""", line)
        if m:
            encoded = m.group(1)
            decoded = _try_base64_decode(encoded)
            if decoded:
                ctx.decoded_values.append({
                    "line": line_num,
                    "original": encoded,
                    "decoded": decoded,
                    "encoding": "cmd:base64_decode",
                    "original_line": line,
                })

        # Pattern: `echo BASE64 | base64 --decode`
        m = re.search(r"""`echo\s+['\"]?([A-Za-z0-9+/=_-]{12,})['\"]?\s*\|\s*base64\s+--decode`""", line)
        if m:
            encoded = m.group(1)
            decoded = _try_base64_decode(encoded)
            if decoded:
                ctx.decoded_values.append({
                    "line": line_num,
                    "original": encoded,
                    "decoded": decoded,
                    "encoding": "cmd:base64_decode",
                    "original_line": line,
                })

        # Pattern: echo "string" | rev (reverse)
        m = re.search(r"""echo\s+['\"]?(\S{8,})['\"]?\s*\|\s*rev""", line)
        if m:
            reversed_val = m.group(1)[::-1]
            if _has_known_prefix(reversed_val) or _shannon_entropy(reversed_val) > 4.0:
                ctx.decoded_values.append({
                    "line": line_num,
                    "original": m.group(1),
                    "decoded": reversed_val,
                    "encoding": "cmd:reverse",
                    "original_line": line,
                })

        # Pattern: function that echoes a secret
        m = re.search(r"""echo\s+['\"]([^'\"]{8,})['\"]""", line)
        if m:
            val = m.group(1)
            if _has_known_prefix(val):
                ctx.decoded_values.append({
                    "line": line_num,
                    "original": val,
                    "decoded": val,
                    "encoding": "cmd:echo",
                    "original_line": line,
                })


def _try_base64_decode(value: str) -> str | None:
    """Attempt base64 decode. Returns decoded string or None."""
    if len(value) < 12:
        return None
    if not re.match(r"^[A-Za-z0-9+/=_-]+$", value):
        return None
    padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded = decoded_bytes.decode("utf-8", errors="strict")
        if decoded.isprintable() and len(decoded) >= 6:
            return decoded
    except Exception:
        pass
    try:
        decoded_bytes = base64.urlsafe_b64decode(padded)
        decoded = decoded_bytes.decode("utf-8", errors="strict")
        if decoded.isprintable() and len(decoded) >= 6:
            return decoded
    except Exception:
        pass
    return None


def _try_hex_decode(value: str) -> str | None:
    """Attempt hex decode. Returns decoded string or None."""
    if len(value) < 16 or len(value) % 2 != 0:
        return None
    if not re.match(r"^[0-9a-fA-F]+$", value):
        return None
    try:
        decoded_bytes = binascii.unhexlify(value)
        decoded = decoded_bytes.decode("utf-8", errors="strict")
        if decoded.isprintable() and len(decoded) >= 8:
            return decoded
    except Exception:
        pass
    return None


def _try_url_decode(value: str) -> str | None:
    """Attempt URL percent-encoding decode. Returns decoded string or None."""
    if "%" not in value:
        return None
    try:
        from urllib.parse import unquote
        decoded = unquote(value)
        if decoded != value and len(decoded) >= 6:
            return decoded
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════
# STAGE 3: RECONSTRUCTION
# ══════════════════════════════════════════════════════════════════


def _stage_reconstruct(ctx: ScanContext) -> None:
    """Detect string concatenation and split-value patterns."""
    lines = ctx.normalized_lines

    # Pattern 1: String concatenation in code
    # e.g., "sk_live_" + suffix or `sk_live_${var}`
    for line_num, line in enumerate(lines, 1):
        # Python/JS concat: "prefix" + var
        m = re.search(
            r"""['\"]([a-zA-Z0-9_-]{3,})['\"]"""
            r"""\s*[\+\.]\s*"""
            r"""(?:['\"]([a-zA-Z0-9_-]{3,})['\"]|(\w+))""",
            line,
        )
        if m:
            prefix = m.group(1)
            suffix = m.group(2) or f"<{m.group(3)}>"
            combined = prefix + suffix
            if _has_known_prefix(prefix):
                ctx.reconstructed_values.append({
                    "line": line_num,
                    "value": combined,
                    "method": "string_concat",
                    "prefix": prefix,
                    "original_line": line,
                })

    # Pattern 2: Split across sequential assignments
    # e.g., part1=sk_live_51H / part2=xxABC / part3=xyz
    part_groups: dict[str, list[tuple[int, str, str]]] = {}
    for line_num, line in enumerate(lines, 1):
        m = re.match(r"(\w+?)(\d+)\s*[=:]\s*['\"]?(\S+?)['\"]?\s*$", line.strip())
        if m:
            base_name = m.group(1)
            idx = int(m.group(2))
            val = m.group(3)
            part_groups.setdefault(base_name, []).append((idx, val, str(line_num)))

    for base_name, parts in part_groups.items():
        if len(parts) < 2:
            continue
        parts.sort(key=lambda x: x[0])
        combined = "".join(p[1] for p in parts)
        first_line = int(parts[0][2])
        if _has_known_prefix(combined) or _shannon_entropy(combined) > 4.0:
            ctx.reconstructed_values.append({
                "line": first_line,
                "value": combined,
                "method": "split_assignment",
                "prefix": combined[:10],
                "original_line": lines[first_line - 1] if first_line <= len(lines) else "",
            })

    # Pattern 3: Array-style splits
    # e.g., keys[0]=AIza / keys[1]=SyD / keys[2]=xxx
    array_groups: dict[str, list[tuple[int, str, int]]] = {}
    for line_num, line in enumerate(lines, 1):
        m = re.match(r"([\w.]+)\[(\d+)\]\s*[=:]\s*['\"]?(\S+?)['\"]?\s*$", line.strip())
        if m:
            arr_name = m.group(1)
            idx = int(m.group(2))
            val = m.group(3)
            array_groups.setdefault(arr_name, []).append((idx, val, line_num))

    for arr_name, parts in array_groups.items():
        if len(parts) < 2:
            continue
        parts.sort(key=lambda x: x[0])
        combined = "".join(p[1] for p in parts)
        first_line = parts[0][2]
        if _has_known_prefix(combined) or _shannon_entropy(combined) > 3.5:
            ctx.reconstructed_values.append({
                "line": first_line,
                "value": combined,
                "method": "array_split",
                "prefix": combined[:10],
                "original_line": lines[first_line - 1] if first_line <= len(lines) else "",
            })


# ══════════════════════════════════════════════════════════════════
# STAGE 4: PREFIX INTELLIGENCE
# ══════════════════════════════════════════════════════════════════

# Known provider prefixes with metadata
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


def _has_known_prefix(value: str) -> bool:
    """Check if a value starts with any known provider prefix."""
    return any(value.startswith(p["prefix"]) for p in PREFIX_DB)


def _stage_prefix_intelligence(ctx: ScanContext) -> None:
    """Scan all lines for known provider prefixes — independent of regex rules."""
    all_values_to_check = []

    # Collect values from raw lines
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue
        # Extract any string values
        for m in re.finditer(r"['\"]([^'\"]{8,})['\"]", line):
            all_values_to_check.append((line_num, m.group(1), line, "quoted"))
        # Unquoted assignments
        m = re.search(r"[\w.]+\s*[=:]\s*(\S{8,})", line)
        if m:
            all_values_to_check.append((line_num, m.group(1), line, "unquoted"))

    # Also check decoded values
    for dv in ctx.decoded_values:
        all_values_to_check.append((dv["line"], dv["decoded"], dv["original_line"], f"decoded:{dv['encoding']}"))

    # Also check reconstructed values
    for rv in ctx.reconstructed_values:
        all_values_to_check.append((rv["line"], rv["value"], rv["original_line"], f"reconstructed:{rv['method']}"))

    # Match against prefix database
    seen = set()
    for line_num, value, original_line, source in all_values_to_check:
        for pinfo in PREFIX_DB:
            if value.startswith(pinfo["prefix"]):
                dedup = (line_num, pinfo["provider"], pinfo["type"])
                if dedup in seen:
                    continue
                seen.add(dedup)
                ctx.prefix_hits.append({
                    "line": line_num,
                    "value": value,
                    "provider": pinfo["provider"],
                    "type": pinfo["type"],
                    "expected_length": pinfo["length"],
                    "base_score": pinfo["score"],
                    "source": source,
                    "original_line": original_line,
                })


# ══════════════════════════════════════════════════════════════════
# STAGE 5: REGEX PATTERN MATCHING (existing rules)
# ══════════════════════════════════════════════════════════════════

RULES = [
    # ── AWS ───────────────────────────────────────────────────
    {"name": "AWS Access Key ID", "pattern": r"(AKIA[0-9A-Z]{16})", "base_score": 95, "fix": "Use IAM roles, environment variables, or AWS Secrets Manager.", "category": "cloud"},
    {"name": "AWS Secret Access Key", "pattern": r"(?:aws_secret_access_key|aws_secret_key|AWS_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "base_score": 95, "fix": "Use ~/.aws/credentials, environment variables, or IAM roles.", "category": "cloud", "needs_entropy": True},
    {"name": "AWS MWS Key", "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "base_score": 90, "fix": "Store MWS keys in a secrets manager.", "category": "cloud"},
    # ── GCP ───────────────────────────────────────────────────
    {"name": "Google API Key", "pattern": r"(AIza[0-9A-Za-z_-]{35})", "base_score": 90, "fix": "Restrict the key in GCP Console and use environment variables.", "category": "cloud"},
    {"name": "Google OAuth Client Secret", "pattern": r"(?:client_secret)\s*[=:]\s*['\"]([A-Za-z0-9_-]{24,})['\"]", "base_score": 85, "fix": "Use OAuth flow with server-side token exchange.", "category": "cloud", "needs_entropy": True},
    {"name": "GCP Service Account Key", "pattern": r"\"type\"\s*:\s*\"service_account\"", "base_score": 90, "fix": "Use Workload Identity Federation instead of key files.", "category": "cloud"},
    # ── Azure ─────────────────────────────────────────────────
    {"name": "Azure Storage Account Key", "pattern": r"(?:AccountKey|azure_storage_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{86,88})['\"]?", "base_score": 90, "fix": "Use Azure Managed Identity or Key Vault.", "category": "cloud"},
    {"name": "Azure Connection String", "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+", "base_score": 90, "fix": "Store in Azure Key Vault or app settings.", "category": "cloud"},
    # ── GitHub ────────────────────────────────────────────────
    {"name": "GitHub Personal Access Token", "pattern": r"(ghp_[A-Za-z0-9_]{36,})", "base_score": 95, "fix": "Use GITHUB_TOKEN in CI or environment variables.", "category": "vcs"},
    {"name": "GitHub OAuth Token", "pattern": r"(gho_[A-Za-z0-9_]{36,})", "base_score": 90, "fix": "Use GitHub App tokens or environment variables.", "category": "vcs"},
    {"name": "GitHub App Token", "pattern": r"(ghu_[A-Za-z0-9_]{36,}|ghs_[A-Za-z0-9_]{36,}|ghr_[A-Za-z0-9_]{36,})", "base_score": 90, "fix": "Rotate and store in environment variables.", "category": "vcs"},
    {"name": "GitLab Token", "pattern": r"(glpat-[A-Za-z0-9_-]{20,})", "base_score": 90, "fix": "Use CI/CD variables or environment variables.", "category": "vcs"},
    # ── Payment ───────────────────────────────────────────────
    {"name": "Stripe Live Secret Key", "pattern": r"(sk_live_[A-Za-z0-9]{20,})", "base_score": 95, "fix": "Use environment variables. Use sk_test_ for development.", "category": "payment"},
    {"name": "Stripe Restricted Key", "pattern": r"(rk_live_[A-Za-z0-9]{20,})", "base_score": 90, "fix": "Store restricted keys in environment variables.", "category": "payment"},
    {"name": "PayPal Braintree Token", "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "base_score": 90, "fix": "Use server-side environment variables.", "category": "payment"},
    {"name": "Square Access Token", "pattern": r"sq0atp-[0-9A-Za-z_-]{22,}", "base_score": 90, "fix": "Store Square tokens in environment variables.", "category": "payment"},
    # ── Communication ─────────────────────────────────────────
    {"name": "Slack Webhook URL", "pattern": r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)", "base_score": 85, "fix": "Store webhook URLs in environment variables.", "category": "communication"},
    {"name": "Slack Bot Token", "pattern": r"(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})", "base_score": 90, "fix": "Use environment variables for Slack bot tokens.", "category": "communication"},
    {"name": "Discord Webhook URL", "pattern": r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)", "base_score": 85, "fix": "Store webhook URLs in environment variables.", "category": "communication"},
    {"name": "Twilio API Key", "pattern": r"(SK[0-9a-fA-F]{32})", "base_score": 75, "fix": "Store Twilio credentials in environment variables.", "category": "communication", "needs_entropy": True},
    {"name": "SendGrid API Key", "pattern": r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", "base_score": 95, "fix": "Use environment variables for SendGrid API keys.", "category": "communication"},
    {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "base_score": 85, "fix": "Store Mailgun keys in environment variables.", "category": "communication"},
    # ── Monitoring ────────────────────────────────────────────
    {"name": "Datadog API Key", "pattern": r"(?:datadog_api_key|DD_API_KEY)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "base_score": 80, "fix": "Use environment variables for Datadog keys.", "category": "monitoring", "needs_entropy": True},
    {"name": "New Relic License Key", "pattern": r"(?:NEW_RELIC_LICENSE_KEY|newrelic_key)\s*[=:]\s*['\"]?([A-Za-z0-9]{40})['\"]?", "base_score": 80, "fix": "Use environment variables for New Relic keys.", "category": "monitoring", "needs_entropy": True},
    {"name": "Sentry DSN", "pattern": r"https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+", "base_score": 60, "fix": "Sentry DSNs are semi-public but best kept in env config.", "category": "monitoring"},
    # ── Database ──────────────────────────────────────────────
    {"name": "Database Connection String", "pattern": r"((?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql|mariadb)://[^\s'\"]{10,})", "base_score": 85, "fix": "Use environment variables for connection strings.", "category": "database"},
    {"name": "JDBC Connection with Password", "pattern": r"(jdbc:[a-z]+://[^\s'\"]*(?:password|pwd)=[^\s&'\"]+)", "base_score": 90, "fix": "Use a connection pool config with externalized credentials.", "category": "database"},
    # ── Crypto ────────────────────────────────────────────────
    {"name": "RSA Private Key", "pattern": r"-----BEGIN RSA PRIVATE KEY-----", "base_score": 98, "fix": "Store private keys in a vault or HSM.", "category": "crypto"},
    {"name": "EC Private Key", "pattern": r"-----BEGIN EC PRIVATE KEY-----", "base_score": 98, "fix": "Store private keys in a vault or HSM.", "category": "crypto"},
    {"name": "OpenSSH Private Key", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----", "base_score": 98, "fix": "Never commit SSH keys. Use ssh-agent.", "category": "crypto"},
    {"name": "PGP Private Key", "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "base_score": 98, "fix": "Store PGP keys in a keyring.", "category": "crypto"},
    {"name": "Generic Private Key", "pattern": r"-----BEGIN (?:DSA |ENCRYPTED )?PRIVATE KEY-----", "base_score": 95, "fix": "Store private keys in a secure vault.", "category": "crypto"},
    # ── JWT ───────────────────────────────────────────────────
    {"name": "JWT Token", "pattern": r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", "base_score": 65, "fix": "JWTs should be obtained at runtime.", "category": "auth"},
    # ── Generic Credentials ───────────────────────────────────
    {"name": "Hardcoded Password", "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]", "base_score": 75, "fix": "Never hardcode passwords. Use env vars or credential store.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded API Key", "pattern": r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 75, "fix": "Move API keys to environment variables.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded Secret", "pattern": r"(?:secret|secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 80, "fix": "Use a secrets manager or environment variables.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded Auth Token", "pattern": r"(?:auth[_-]?token|access[_-]?token|bearer[_-]?token|refresh[_-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 80, "fix": "Tokens should come from OAuth flows or env vars.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded Encryption Key", "pattern": r"(?:encryption[_-]?key|encrypt[_-]?key|aes[_-]?key|signing[_-]?key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 85, "fix": "Use a KMS for encryption keys.", "skip_test": True, "needs_entropy": True, "category": "crypto"},
    # ── URLs ──────────────────────────────────────────────────
    {"name": "URL with Embedded Credentials", "pattern": r"(https?://[^:]+:[^@]+@[^\s'\"]+)", "base_score": 85, "fix": "Never embed credentials in URLs.", "category": "credential"},
    # ── Infra ─────────────────────────────────────────────────
    {"name": "Hardcoded IP Address", "pattern": r"['\"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['\"]", "base_score": 25, "fix": "Use config files or env vars for IPs.", "category": "infra"},
    # ── Android ───────────────────────────────────────────────
    {"name": "Android Manifest API Key", "pattern": r"android:value\s*=\s*\"([A-Za-z0-9_-]{20,})\"", "base_score": 70, "fix": "Use BuildConfig from local.properties.", "file_pattern": r"AndroidManifest\.xml", "needs_entropy": True, "category": "android"},
    {"name": "BuildConfig Hardcoded Secret", "pattern": r"buildConfigField\s+['\"]String['\"]\s*,\s*['\"].*(?:KEY|SECRET|TOKEN).*['\"]\s*,\s*['\"]\\\"([^\"]+)\\\"['\"]", "base_score": 80, "fix": "Read from local.properties.", "file_pattern": r"\.gradle", "category": "android"},
    {"name": "Firebase Config Inline", "pattern": r"(?:firebase|firebaseConfig)\s*[=:]\s*\{[^}]*apiKey\s*:", "base_score": 60, "fix": "Use google-services.json.", "category": "android"},
    # ── Registry ──────────────────────────────────────────────
    {"name": "npm Token", "pattern": r"//registry\.npmjs\.org/:_authToken=([A-Za-z0-9_-]+)", "base_score": 90, "fix": "Use npm login or CI env vars.", "category": "registry"},
    {"name": "PyPI Token", "pattern": r"(pypi-[A-Za-z0-9_-]{50,})", "base_score": 90, "fix": "Use keyring or CI secrets.", "category": "registry"},
    {"name": "Docker Hub Token", "pattern": r"(?:DOCKER_PASSWORD|DOCKER_TOKEN)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 80, "fix": "Use docker credential helpers.", "category": "registry", "needs_entropy": True},
    # ── Catch-All ─────────────────────────────────────────────
    {"name": "High Entropy String", "pattern": r"['\"]([A-Za-z0-9+/=_-]{32,})['\"]", "base_score": 35, "fix": "Review — high entropy strings may be secrets.", "needs_entropy": True, "skip_test": True, "category": "entropy"},
    # ── ENV-Style Candidates ──────────────────────────────────
    {"name": "Possible Password (unquoted)", "pattern": r"(?:PASSWORD|PASSWD|PWD|DB_PASSWORD|EMAIL_PASSWORD|ADMIN_PASSWORD)\s*=\s*(\S{4,})", "base_score": 40, "fix": "If real, move to secrets manager or .gitignored .env.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible Secret/Key (unquoted)", "pattern": r"(?:SECRET|SECRET_KEY|JWT_SECRET|APP_SECRET|SIGNING_KEY|ENCRYPTION_KEY)\s*=\s*(\S{6,})", "base_score": 40, "fix": "If real, use env vars or secrets manager.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible Token (unquoted)", "pattern": r"(?:TOKEN|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|BEARER_TOKEN|API_TOKEN|GITHUB_TOKEN)\s*=\s*(\S{8,})", "base_score": 40, "fix": "If real, store in env vars or secrets manager.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible API Key (unquoted)", "pattern": r"(?:API_KEY|APIKEY|API_SECRET|GOOGLE_API_KEY|STRIPE_API_KEY|MAPS_API_KEY)\s*=\s*(\S{8,})", "base_score": 40, "fix": "If real, move to env vars or secrets manager.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible Connection String (unquoted)", "pattern": r"(?:DATABASE_URL|DB_URL|REDIS_URL|MONGO_URI|CONNECTION_STRING)\s*=\s*(\S{10,})", "base_score": 45, "fix": "Connection strings often contain credentials.", "skip_test": True, "category": "candidate"},
]


def _stage_regex(ctx: ScanContext) -> None:
    """Run regex rules against normalized lines."""
    seen = set()
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule in RULES:
            if rule.get("skip_test") and ctx.is_test:
                continue
            if rule.get("file_pattern") and not re.search(rule["file_pattern"], ctx.filename):
                continue
            for match in re.finditer(rule["pattern"], line, re.IGNORECASE):
                matched_text = match.group(0)
                secret_value = match.group(1) if match.lastindex else matched_text
                if _is_placeholder(secret_value):
                    continue
                dedup_key = (line_num, rule["name"])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                ctx.regex_hits.append({
                    "line": line_num,
                    "rule": rule["name"],
                    "category": rule.get("category", "unknown"),
                    "base_score": rule.get("base_score", 50),
                    "match": matched_text,
                    "secret_value": secret_value,
                    "fix": rule["fix"],
                    "needs_entropy": rule.get("needs_entropy", False),
                    "original_line": line,
                })


# ══════════════════════════════════════════════════════════════════
# STAGE 6: CONFIDENCE SCORING + MERGE
# ══════════════════════════════════════════════════════════════════


def _stage_score_and_merge(ctx: ScanContext) -> None:
    """Score all hits and merge into final findings."""
    seen_lines: dict[int, set[str]] = {}

    # Score regex hits
    for hit in ctx.regex_hits:
        confidence = _compute_confidence(
            hit, hit["secret_value"], hit["original_line"],
            ctx.filename, hit["line"], ctx.lines,
        )
        if confidence < 15:
            continue
        _add_finding(ctx, seen_lines, {
            "line": hit["line"],
            "rule": hit["rule"],
            "category": hit["category"],
            "severity": _score_to_severity(confidence),
            "confidence": confidence,
            "match": _mask_finding(hit["match"]),
            "fix": hit["fix"],
            "source": "regex",
        })

    # Score prefix intelligence hits (only add if not already found by regex)
    for hit in ctx.prefix_hits:
        confidence = hit["base_score"]
        # Adjust for context
        if ctx.is_test:
            confidence -= 25
        if _is_placeholder(hit["value"]):
            confidence -= 40
        line = hit["original_line"]
        if re.search(r"(?:example|sample|dummy|fake|mock|test)", line.lower()):
            confidence -= 20
        entropy = _shannon_entropy(hit["value"])
        if entropy >= 4.5:
            confidence += 10
        elif entropy < 3.0 and hit["base_score"] < 90:
            confidence -= 15
        # Length check vs expected
        if len(hit["value"]) < hit["expected_length"] * 0.5:
            confidence -= 20
        confidence = max(0, min(100, confidence))
        if confidence < 15:
            continue

        source_label = f"prefix:{hit['provider']}"
        if hit["source"] not in ("quoted", "unquoted"):
            source_label = f"prefix:{hit['provider']}({hit['source']})"

        _add_finding(ctx, seen_lines, {
            "line": hit["line"],
            "rule": f"{hit['provider']} {hit['type']}",
            "category": "prefix",
            "severity": _score_to_severity(confidence),
            "confidence": confidence,
            "match": _mask_finding(hit["value"]),
            "fix": f"Detected {hit['provider']} {hit['type']}. Store in env vars or secrets manager.",
            "source": source_label,
        })

    # Score decoded value findings
    for dv in ctx.decoded_values:
        decoded = dv["decoded"]
        # Run prefix check on decoded content
        for pinfo in PREFIX_DB:
            if decoded.startswith(pinfo["prefix"]):
                confidence = pinfo["score"] + 5  # bonus for being hidden
                confidence = max(0, min(100, confidence))
                _add_finding(ctx, seen_lines, {
                    "line": dv["line"],
                    "rule": f"{pinfo['provider']} {pinfo['type']} ({dv['encoding']} encoded)",
                    "category": "decoded",
                    "severity": _score_to_severity(confidence),
                    "confidence": confidence,
                    "match": _mask_finding(f"[{dv['encoding']}] {dv['original'][:30]}... → {decoded[:30]}..."),
                    "fix": f"Found {dv['encoding']}-encoded {pinfo['provider']} key. Encoding is not security.",
                    "source": f"decoded:{dv['encoding']}",
                })
                break
        else:
            # No prefix match — check entropy of decoded value
            entropy = _shannon_entropy(decoded)
            if entropy >= 4.0 and len(decoded) >= 16:
                confidence = 45 + int(entropy * 5)
                confidence = max(0, min(100, confidence))
                if confidence >= 30:
                    _add_finding(ctx, seen_lines, {
                        "line": dv["line"],
                        "rule": f"High-entropy {dv['encoding']}-decoded value",
                        "category": "decoded",
                        "severity": _score_to_severity(confidence),
                        "confidence": confidence,
                        "match": _mask_finding(f"[{dv['encoding']}] → {decoded[:40]}"),
                        "fix": f"This {dv['encoding']}-encoded value decodes to a suspicious string. Review it.",
                        "source": f"decoded:{dv['encoding']}",
                    })

    # Score reconstructed value findings
    for rv in ctx.reconstructed_values:
        value = rv["value"]
        for pinfo in PREFIX_DB:
            if value.startswith(pinfo["prefix"]):
                confidence = pinfo["score"] + 5
                confidence = max(0, min(100, confidence))
                _add_finding(ctx, seen_lines, {
                    "line": rv["line"],
                    "rule": f"{pinfo['provider']} {pinfo['type']} (reconstructed via {rv['method']})",
                    "category": "reconstructed",
                    "severity": _score_to_severity(confidence),
                    "confidence": confidence,
                    "match": _mask_finding(f"[{rv['method']}] {value}"),
                    "fix": f"Found split/concatenated {pinfo['provider']} key. Splitting doesn't hide secrets.",
                    "source": f"reconstructed:{rv['method']}",
                })
                break
        else:
            entropy = _shannon_entropy(value)
            if entropy >= 4.0 and len(value) >= 20:
                confidence = 40 + int(entropy * 5)
                confidence = max(0, min(100, confidence))
                if confidence >= 30:
                    _add_finding(ctx, seen_lines, {
                        "line": rv["line"],
                        "rule": f"High-entropy reconstructed value ({rv['method']})",
                        "category": "reconstructed",
                        "severity": _score_to_severity(confidence),
                        "confidence": confidence,
                        "match": _mask_finding(f"[{rv['method']}] {value}"),
                        "fix": "Reconstructed value has high entropy. Review if it's a secret.",
                        "source": f"reconstructed:{rv['method']}",
                    })

    ctx.findings.sort(key=lambda f: f["confidence"], reverse=True)


def _add_finding(ctx: ScanContext, seen: dict, finding: dict) -> None:
    """Add finding with deduplication per line+rule."""
    line = finding["line"]
    rule = finding["rule"]
    if line not in seen:
        seen[line] = set()
    if rule in seen[line]:
        return
    seen[line].add(rule)
    ctx.findings.append(finding)


# ══════════════════════════════════════════════════════════════════
# PIPELINE RUNNER
# ══════════════════════════════════════════════════════════════════


def _scan(code: str, filename: str) -> list[dict]:
    """Run the full detection pipeline."""
    ctx = ScanContext(code=code, filename=filename)

    _stage_normalize(ctx)     # Stage 1
    _stage_decode(ctx)        # Stage 2
    _stage_reconstruct(ctx)   # Stage 3
    _stage_prefix_intelligence(ctx)  # Stage 4
    _stage_regex(ctx)         # Stage 5
    _stage_score_and_merge(ctx)      # Stage 6

    return ctx.findings


# ══════════════════════════════════════════════════════════════════
# CONFIDENCE SCORING (unchanged logic, adapted for pipeline)
# ══════════════════════════════════════════════════════════════════


def _compute_confidence(rule: dict, matched_value: str, line: str,
                        filename: str, line_num: int, all_lines: list[str]) -> int:
    score = rule.get("base_score", 50)
    entropy = _shannon_entropy(matched_value)

    # ── Entropy + Length combined signal (noise vs signal) ────
    vlen = len(matched_value)
    if entropy >= 5.0 and vlen >= 32:
        score += 20  # very high entropy + long = almost certainly a secret
    elif entropy >= 5.0:
        score += 15
    elif entropy >= 4.5 and vlen >= 20:
        score += 12
    elif entropy >= 4.5:
        score += 10
    elif entropy >= 4.0:
        score += 5
    elif entropy < 2.5 and rule.get("needs_entropy", False):
        score -= 20

    if vlen >= 40:
        score += 10
    elif vlen >= 24:
        score += 5
    elif vlen < 8 and rule.get("needs_entropy", False):
        score -= 15

    # ── Noise detection (strong penalty for obvious non-secrets) ──
    # Repeating characters: aaaaaaa, 1111111, xxxxxxx
    if vlen >= 16 and len(set(matched_value)) <= 3:
        score -= 50  # almost certainly noise
    elif vlen >= 16 and entropy < 2.0:
        score -= 35  # very low entropy for a long string = noise
    # Sequential patterns: abcdef, 123456
    if re.match(r"^(?:0123456789|abcdefghij|ABCDEFGHIJ)", matched_value):
        score -= 15
    # All same case alphanumeric with no special chars and low entropy
    if re.match(r"^[a-z]+$", matched_value) and entropy < 3.5:
        score -= 20
    if re.match(r"^[0-9]+$", matched_value) and entropy < 3.0:
        score -= 25

    # ── Keyword proximity ─────────────────────────────────────
    sensitive_kw = ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth", "credential", "private", "access_key"]
    line_lower = line.lower()
    if any(kw in line_lower for kw in sensitive_kw):
        score += 10

    # ── Context penalties ─────────────────────────────────────
    if _is_test_file(filename):
        score -= 25
    if _is_placeholder(matched_value):
        score -= 40
    if _is_comment(line.strip()):
        score -= 20
    if re.search(r"\$\{|\$\(|process\.env|os\.environ|getenv|System\.getenv", line):
        score -= 30
    if re.search(r"(?:example|sample|dummy|fake|mock|test|placeholder)", line_lower):
        score -= 20

    # ── Nearby context bonus ──────────────────────────────────
    nearby = 0
    for offset in [-2, -1, 1, 2]:
        idx = line_num - 1 + offset
        if 0 <= idx < len(all_lines):
            if any(kw in all_lines[idx].lower() for kw in ["password", "secret", "key", "token"]):
                nearby += 1
    if nearby >= 2:
        score += 5

    # ── Pattern + context combined signal ─────────────────────
    # If high entropy AND near sensitive keyword AND not a test file = strong signal
    if entropy >= 4.5 and any(kw in line_lower for kw in sensitive_kw) and not _is_test_file(filename):
        score += 5

    return max(0, min(100, score))


def _score_to_severity(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 50: return "MEDIUM"
    if score >= 30: return "LOW"
    return "INFO"


def _severity_emoji(sev: str) -> str:
    return {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}.get(sev, "❓")


# ══════════════════════════════════════════════════════════════════
# MCP TOOLS
# ══════════════════════════════════════════════════════════════════


def _format_findings(findings: list[dict], filename: str) -> str:
    """Format findings into tabular output."""
    if not findings:
        return "✅ No secrets or risky values detected. Code looks clean."

    confirmed = [f for f in findings if f["category"] not in ("candidate",)]
    candidates = [f for f in findings if f["category"] == "candidate"]

    sections = []
    sections.append("🔐 SecretSentry Scan Results")
    sections.append(f"   File: {filename}")
    sections.append(f"   Pipeline: normalize → decode → reconstruct → prefix → regex → score")
    sections.append(f"   Findings: {len(confirmed)} confirmed | {len(candidates)} candidates")
    sections.append("")

    if confirmed:
        sections.append("## Confirmed Findings")
        sections.append("")
        sections.append("| # | Severity | Score | File | Line | Source | Rule | Match | Fix |")
        sections.append("|---|----------|-------|------|------|--------|------|-------|-----|")
        for i, f in enumerate(confirmed, 1):
            emoji = _severity_emoji(f["severity"])
            src = f.get("source", "regex")
            sections.append(
                f"| {i} | {emoji} {f['severity']} | {f['confidence']}/100 "
                f"| {filename} | {f['line']} | {src} | {f['rule']} "
                f"| `{f['match']}` | {f['fix']} |"
            )
        sections.append("")

    if candidates:
        sections.append("## Possible Candidates (Review Recommended)")
        sections.append("")
        sections.append("| # | Severity | Score | File | Line | Source | Rule | Match | Fix |")
        sections.append("|---|----------|-------|------|------|--------|------|-------|-----|")
        for i, f in enumerate(candidates, 1):
            emoji = _severity_emoji(f["severity"])
            src = f.get("source", "regex")
            sections.append(
                f"| {i} | {emoji} {f['severity']} | {f['confidence']}/100 "
                f"| {filename} | {f['line']} | {src} | {f['rule']} "
                f"| `{f['match']}` | {f['fix']} |"
            )
        sections.append("")

    return "\n".join(sections)


@mcp.tool()
def scan_code(code: str, filename: str = "unknown") -> str:
    """Scans code for hardcoded secrets, credentials, API keys, and risky values.

    Args:
        code: The source code content to scan.
        filename: The filename (used for context-aware filtering). Defaults to "unknown".
    """
    findings = _scan(code, filename)
    return _format_findings(findings, filename)


@mcp.tool()
def scan_file(filepath: str) -> str:
    """Scans a file on disk for hardcoded secrets and risky values.

    Args:
        filepath: Absolute or relative path to the file to scan.
    """
    path = os.path.expanduser(filepath)
    if not os.path.isfile(path):
        return f"❌ File not found: {filepath}"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        return f"❌ Could not read file: {e}"
    filename = os.path.basename(path)
    return _format_findings(_scan(code, filename), filename)


@mcp.tool()
def scan_directory(dirpath: str, extensions: str = "") -> str:
    """Scans all files in a directory for hardcoded secrets and risky values.

    Args:
        dirpath: Path to the directory to scan.
        extensions: Comma-separated file extensions to include (e.g. ".py,.java,.kt"). Empty means scan all text files.
    """
    path = os.path.expanduser(dirpath)
    if not os.path.isdir(path):
        return f"❌ Directory not found: {dirpath}"

    ext_filter = set()
    if extensions.strip():
        ext_filter = {e.strip() if e.strip().startswith(".") else f".{e.strip()}" for e in extensions.split(",")}

    all_findings: list[dict] = []
    files_scanned = 0
    skip_dirs = {".git", "node_modules", "__pycache__", ".gradle", "build", ".idea", ".vscode", ".kiro", "venv", ".venv", "dist", "target", ".mypy_cache", ".pytest_cache", ".tox", "egg-info"}

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if ext_filter and not any(fname.endswith(ext) for ext in ext_filter):
                continue
            fpath = os.path.join(root, fname)
            if _is_binary(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                findings = _scan(code, fname)
                rel = os.path.relpath(fpath, path)
                for finding in findings:
                    finding["file"] = rel
                all_findings.extend(findings)
                files_scanned += 1
            except Exception:
                continue

    if not all_findings:
        return f"✅ Scanned {files_scanned} files — no secrets or risky values detected."

    all_findings.sort(key=lambda f: f["confidence"], reverse=True)
    confirmed = [f for f in all_findings if f["category"] != "candidate"]
    candidates = [f for f in all_findings if f["category"] == "candidate"]

    sections = []
    sections.append("🔐 SecretSentry Directory Scan Results")
    sections.append(f"   Directory: {dirpath}")
    sections.append(f"   Scanned: {files_scanned} files")
    sections.append(f"   Pipeline: normalize → decode → reconstruct → prefix → regex → score")
    sections.append(f"   Findings: {len(confirmed)} confirmed | {len(candidates)} candidates")
    sections.append("")

    if confirmed:
        sections.append("## Confirmed Findings")
        sections.append("")
        sections.append("| # | Severity | Score | File | Line | Source | Rule | Match | Fix |")
        sections.append("|---|----------|-------|------|------|--------|------|-------|-----|")
        for i, f in enumerate(confirmed, 1):
            emoji = _severity_emoji(f["severity"])
            loc = f.get("file", "?")
            src = f.get("source", "regex")
            sections.append(f"| {i} | {emoji} {f['severity']} | {f['confidence']}/100 | {loc} | {f['line']} | {src} | {f['rule']} | `{f['match']}` | {f['fix']} |")
        sections.append("")

    if candidates:
        sections.append("## Possible Candidates (Review Recommended)")
        sections.append("")
        sections.append("| # | Severity | Score | File | Line | Source | Rule | Match | Fix |")
        sections.append("|---|----------|-------|------|------|--------|------|-------|-----|")
        for i, f in enumerate(candidates, 1):
            emoji = _severity_emoji(f["severity"])
            loc = f.get("file", "?")
            src = f.get("source", "regex")
            sections.append(f"| {i} | {emoji} {f['severity']} | {f['confidence']}/100 | {loc} | {f['line']} | {src} | {f['rule']} | `{f['match']}` | {f['fix']} |")
        sections.append("")

    return "\n".join(sections)


@mcp.tool()
def check_entropy(value: str) -> str:
    """Checks if a string value looks like a secret based on Shannon entropy.

    Args:
        value: The string value to analyze.
    """
    ent = _shannon_entropy(value)
    length = len(value)
    score = 95 if ent >= 5.0 and length >= 32 else 80 if ent >= 4.5 and length >= 24 else 60 if ent >= 4.0 and length >= 16 else 40 if ent >= 3.5 and length >= 12 else 20 if ent >= 3.0 else 5
    severity = _score_to_severity(score)
    emoji = _severity_emoji(severity)

    # Also check prefix intelligence
    prefix_info = ""
    for pinfo in PREFIX_DB:
        if value.startswith(pinfo["prefix"]):
            prefix_info = f"\n   🏷️  Prefix match: {pinfo['provider']} {pinfo['type']}"
            break

    sections = [
        "🎲 Entropy Analysis",
        f"   Value: {_mask(value)}",
        f"   Length: {length} chars",
        f"   Entropy: {ent:.2f} bits/char",
        f"   Confidence: {score}/100 ({severity})",
    ]
    if prefix_info:
        sections.append(prefix_info)
    sections.append("")
    verdict = "Very likely a secret. Do not commit." if score >= 70 else "Possibly a secret. Review before committing." if score >= 50 else "Low probability of being a secret." if score >= 30 else "Unlikely to be a secret."
    sections.append(f"{emoji} Verdict: {verdict}")
    return "\n".join(sections)


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════


def _shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_placeholder(value: str) -> bool:
    placeholders = {"xxx", "yyy", "zzz", "todo", "fixme", "changeme", "replace_me", "your_key_here", "your_secret_here", "your_api_key", "insert_here", "placeholder", "example", "test", "dummy", "sample", "fake", "none", "null", "undefined", "empty", "n/a", "change_me", "your_token_here", "your_password", "enter_here", "update_me"}
    lower = value.lower().strip("'\" ")
    if lower in placeholders: return True
    if re.match(r"^[x*#<>]{4,}$", lower): return True
    if re.match(r"^\$\{.+\}$", value) or re.match(r"^%\(.+\)s$", value): return True
    if re.match(r"^\{\{.+\}\}$", value): return True
    if value.startswith("${") or value.startswith("#{") or value.startswith("%("): return True
    if re.search(r"os\.environ|process\.env|System\.getenv|getenv", value): return True
    return False


def _is_test_file(filename: str) -> bool:
    lower = filename.lower()
    return any(ind in lower for ind in ["test", "spec", "mock", "fake", "fixture", "stub", "example", "sample", "demo", "_test.", ".test."])


def _is_comment(line: str) -> bool:
    return line.startswith("//") or line.startswith("#") or line.startswith("*") or line.startswith("/*") or line.startswith("<!--") or line.startswith("--") or line.startswith("REM ")


def _is_binary(filepath: str) -> bool:
    binary_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".aar", ".apk", ".aab", ".war", ".ear", ".so", ".dylib", ".dll", ".exe", ".class", ".dex", ".o", ".a", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".sqlite", ".db", ".mdb", ".pyc", ".pyo", ".wasm"}
    _, ext = os.path.splitext(filepath)
    return ext.lower() in binary_exts


def _mask(value: str) -> str:
    if len(value) <= 8: return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _mask_finding(text: str) -> str:
    if len(text) > 80: return text[:40] + "..." + text[-20:]
    return text


def main():
    mcp.run()


if __name__ == "__main__":
    main()
