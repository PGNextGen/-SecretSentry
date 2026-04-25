"""Stage 3: Reconstruction — string concat, split assignments, array splits."""

import re

from ..models import ScanContext
from ..utils import shannon_entropy
from .prefix import has_known_prefix


def stage_reconstruct(ctx: ScanContext) -> None:
    """Detect string concatenation and split-value patterns."""
    lines = ctx.normalized_lines

    # Pattern 1: String concatenation
    for line_num, line in enumerate(lines, 1):
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
            if has_known_prefix(prefix):
                ctx.reconstructed_values.append({
                    "line": line_num, "value": combined, "method": "string_concat",
                    "prefix": prefix, "original_line": line,
                })

    # Pattern 2: Split across sequential assignments
    part_groups: dict[str, list[tuple[int, str, str]]] = {}
    for line_num, line in enumerate(lines, 1):
        m = re.match(r"(\w+?)(\d+)\s*[=:]\s*['\"]?(\S+?)['\"]?\s*$", line.strip())
        if m:
            part_groups.setdefault(m.group(1), []).append((int(m.group(2)), m.group(3), str(line_num)))

    for _, parts in part_groups.items():
        if len(parts) < 2:
            continue
        parts.sort(key=lambda x: x[0])
        combined = "".join(p[1] for p in parts)
        first_line = int(parts[0][2])
        if has_known_prefix(combined) or shannon_entropy(combined) > 4.0:
            ctx.reconstructed_values.append({
                "line": first_line, "value": combined, "method": "split_assignment",
                "prefix": combined[:10],
                "original_line": lines[first_line - 1] if first_line <= len(lines) else "",
            })

    # Pattern 3: Array-style splits
    array_groups: dict[str, list[tuple[int, str, int]]] = {}
    for line_num, line in enumerate(lines, 1):
        m = re.match(r"([\w.]+)\[(\d+)\]\s*[=:]\s*['\"]?(\S+?)['\"]?\s*$", line.strip())
        if m:
            array_groups.setdefault(m.group(1), []).append((int(m.group(2)), m.group(3), line_num))

    for _, parts in array_groups.items():
        if len(parts) < 2:
            continue
        parts.sort(key=lambda x: x[0])
        combined = "".join(p[1] for p in parts)
        first_line = parts[0][2]
        if has_known_prefix(combined) or shannon_entropy(combined) > 3.5:
            ctx.reconstructed_values.append({
                "line": first_line, "value": combined, "method": "array_split",
                "prefix": combined[:10],
                "original_line": lines[first_line - 1] if first_line <= len(lines) else "",
            })
