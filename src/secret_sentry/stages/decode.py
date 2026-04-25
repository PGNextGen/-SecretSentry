"""Stage 2: Decoding — base64, hex, URL, chained transforms, command substitution."""

import base64
import binascii
import re

from ..models import ScanContext
from ..utils import is_comment, shannon_entropy
from .prefix import has_known_prefix


def stage_decode(ctx: ScanContext) -> None:
    """Find and decode base64, hex, URL-encoded, and chained-encoded values."""
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        stripped = line.strip()
        if not stripped or is_comment(stripped):
            continue

        raw_values = []
        for m in re.finditer(r"['\"]([^\s'\"]{12,})['\"]", line):
            raw_values.append(m.group(1))
        m = re.search(r"[\w.]+\s*[=:]\s*['\"]?([^\s'\"]{12,})['\"]?", line)
        if m and m.group(1) not in raw_values:
            raw_values.append(m.group(1))

        for raw_value in raw_values:
            _decode_chained(ctx, line_num, raw_value, line, max_depth=3)

    _command_substitution(ctx)


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
                "line": line_num, "original": value, "decoded": decoded,
                "encoding": layer, "original_line": original_line,
            })
            _decode_chained(ctx, line_num, decoded, original_line, max_depth - 1, layer)

    if value.startswith("{") or value.startswith("["):
        for m in re.finditer(r"['\"]([A-Za-z0-9+/=_-]{16,})['\"]", value):
            _decode_chained(ctx, line_num, m.group(1), original_line, max_depth - 1, chain + "→json_extract")


def _command_substitution(ctx: ScanContext) -> None:
    """Simulate common command substitution patterns."""
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        # $(echo BASE64 | base64 --decode)
        m = re.search(r"""\$\(echo\s+['\"]?([A-Za-z0-9+/=_-]{12,})['\"]?\s*\|\s*base64\s+--decode\)""", line)
        if m:
            decoded = _try_base64_decode(m.group(1))
            if decoded:
                ctx.decoded_values.append({"line": line_num, "original": m.group(1), "decoded": decoded, "encoding": "cmd:base64_decode", "original_line": line})

        # `echo BASE64 | base64 --decode`
        m = re.search(r"""`echo\s+['\"]?([A-Za-z0-9+/=_-]{12,})['\"]?\s*\|\s*base64\s+--decode`""", line)
        if m:
            decoded = _try_base64_decode(m.group(1))
            if decoded:
                ctx.decoded_values.append({"line": line_num, "original": m.group(1), "decoded": decoded, "encoding": "cmd:base64_decode", "original_line": line})

        # echo "string" | rev
        m = re.search(r"""echo\s+['\"]?(\S{8,})['\"]?\s*\|\s*rev""", line)
        if m:
            reversed_val = m.group(1)[::-1]
            if has_known_prefix(reversed_val) or shannon_entropy(reversed_val) > 4.0:
                ctx.decoded_values.append({"line": line_num, "original": m.group(1), "decoded": reversed_val, "encoding": "cmd:reverse", "original_line": line})

        # echo "secret_value"
        m = re.search(r"""echo\s+['\"]([^'\"]{8,})['\"]""", line)
        if m and has_known_prefix(m.group(1)):
            ctx.decoded_values.append({"line": line_num, "original": m.group(1), "decoded": m.group(1), "encoding": "cmd:echo", "original_line": line})


# ── Decoders ──────────────────────────────────────────────────────

def _try_base64_decode(value: str) -> str | None:
    if len(value) < 12 or not re.match(r"^[A-Za-z0-9+/=_-]+$", value):
        return None
    padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded, validate=(decoder == base64.b64decode)).decode("utf-8", errors="strict")
            if decoded.isprintable() and len(decoded) >= 6:
                return decoded
        except Exception:
            pass
    return None


def _try_hex_decode(value: str) -> str | None:
    if len(value) < 16 or len(value) % 2 != 0 or not re.match(r"^[0-9a-fA-F]+$", value):
        return None
    try:
        decoded = binascii.unhexlify(value).decode("utf-8", errors="strict")
        return decoded if decoded.isprintable() and len(decoded) >= 8 else None
    except Exception:
        return None


def _try_url_decode(value: str) -> str | None:
    if "%" not in value:
        return None
    try:
        from urllib.parse import unquote
        decoded = unquote(value)
        return decoded if decoded != value and len(decoded) >= 6 else None
    except Exception:
        return None
