"""Stage 1: Normalization — unicode, hex escapes, confusable chars."""

import codecs
import re

from ..models import ScanContext
from ..utils import is_test_file


_CONFUSABLE_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
})


def _normalize_confusables(s: str) -> str:
    return s.translate(_CONFUSABLE_MAP)


def stage_normalize(ctx: ScanContext) -> None:
    """Normalize unicode tricks, escape sequences, URL encoding, and whitespace."""
    ctx.lines = ctx.code.splitlines()
    ctx.is_test = is_test_file(ctx.filename)
    normalized = []
    for line in ctx.lines:
        n = line
        try:
            n = codecs.decode(n, "unicode_escape")
        except Exception:
            pass
        try:
            n = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), n)
        except Exception:
            pass
        n = _normalize_confusables(n)
        normalized.append(n)
    ctx.normalized_lines = normalized
