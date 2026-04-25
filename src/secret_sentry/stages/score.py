"""Stage 6: Confidence Scoring + Merge — score all hits and produce final findings."""

import re

from ..models import ScanContext
from ..utils import shannon_entropy, is_placeholder, is_test_file, is_comment, mask_finding
from .prefix import PREFIX_DB


def stage_score_and_merge(ctx: ScanContext) -> None:
    """Score all hits and merge into final findings."""
    seen_lines: dict[int, set[str]] = {}

    for hit in ctx.regex_hits:
        confidence = _compute_confidence(
            hit, hit["secret_value"], hit["original_line"],
            ctx.filename, hit["line"], ctx.lines,
        )
        if confidence < 15:
            continue
        _add_finding(ctx, seen_lines, {
            "line": hit["line"], "rule": hit["rule"], "category": hit["category"],
            "severity": _score_to_severity(confidence), "confidence": confidence,
            "match": mask_finding(hit["match"]), "fix": hit["fix"], "source": "regex",
        })

    for hit in ctx.prefix_hits:
        confidence = hit["base_score"]
        if ctx.is_test:
            confidence -= 25
        if is_placeholder(hit["value"]):
            confidence -= 40
        line = hit["original_line"]
        if re.search(r"(?:example|sample|dummy|fake|mock|test)", line.lower()):
            confidence -= 20
        entropy = shannon_entropy(hit["value"])
        if entropy >= 4.5:
            confidence += 10
        elif entropy < 3.0 and hit["base_score"] < 90:
            confidence -= 15
        if len(hit["value"]) < hit["expected_length"] * 0.5:
            confidence -= 20
        confidence = max(0, min(100, confidence))
        if confidence < 15:
            continue
        source_label = f"prefix:{hit['provider']}"
        if hit["source"] not in ("quoted", "unquoted"):
            source_label = f"prefix:{hit['provider']}({hit['source']})"
        _add_finding(ctx, seen_lines, {
            "line": hit["line"], "rule": f"{hit['provider']} {hit['type']}",
            "category": "prefix", "severity": _score_to_severity(confidence),
            "confidence": confidence, "match": mask_finding(hit["value"]),
            "fix": f"Detected {hit['provider']} {hit['type']}. Store in env vars or secrets manager.",
            "source": source_label,
        })

    for dv in ctx.decoded_values:
        decoded = dv["decoded"]
        for pinfo in PREFIX_DB:
            if decoded.startswith(pinfo["prefix"]):
                confidence = min(100, pinfo["score"] + 5)
                _add_finding(ctx, seen_lines, {
                    "line": dv["line"],
                    "rule": f"{pinfo['provider']} {pinfo['type']} ({dv['encoding']} encoded)",
                    "category": "decoded", "severity": _score_to_severity(confidence),
                    "confidence": confidence,
                    "match": mask_finding(f"[{dv['encoding']}] {dv['original'][:30]}... → {decoded[:30]}..."),
                    "fix": f"Found {dv['encoding']}-encoded {pinfo['provider']} key. Encoding is not security.",
                    "source": f"decoded:{dv['encoding']}",
                })
                break
        else:
            entropy = shannon_entropy(decoded)
            if entropy >= 4.0 and len(decoded) >= 16:
                confidence = min(100, 45 + int(entropy * 5))
                if confidence >= 30:
                    _add_finding(ctx, seen_lines, {
                        "line": dv["line"],
                        "rule": f"High-entropy {dv['encoding']}-decoded value",
                        "category": "decoded", "severity": _score_to_severity(confidence),
                        "confidence": confidence,
                        "match": mask_finding(f"[{dv['encoding']}] → {decoded[:40]}"),
                        "fix": f"This {dv['encoding']}-encoded value decodes to a suspicious string. Review it.",
                        "source": f"decoded:{dv['encoding']}",
                    })

    for rv in ctx.reconstructed_values:
        value = rv["value"]
        for pinfo in PREFIX_DB:
            if value.startswith(pinfo["prefix"]):
                confidence = min(100, pinfo["score"] + 5)
                _add_finding(ctx, seen_lines, {
                    "line": rv["line"],
                    "rule": f"{pinfo['provider']} {pinfo['type']} (reconstructed via {rv['method']})",
                    "category": "reconstructed", "severity": _score_to_severity(confidence),
                    "confidence": confidence,
                    "match": mask_finding(f"[{rv['method']}] {value}"),
                    "fix": f"Found split/concatenated {pinfo['provider']} key. Splitting doesn't hide secrets.",
                    "source": f"reconstructed:{rv['method']}",
                })
                break
        else:
            entropy = shannon_entropy(value)
            if entropy >= 4.0 and len(value) >= 20:
                confidence = min(100, 40 + int(entropy * 5))
                if confidence >= 30:
                    _add_finding(ctx, seen_lines, {
                        "line": rv["line"],
                        "rule": f"High-entropy reconstructed value ({rv['method']})",
                        "category": "reconstructed", "severity": _score_to_severity(confidence),
                        "confidence": confidence,
                        "match": mask_finding(f"[{rv['method']}] {value}"),
                        "fix": "Reconstructed value has high entropy. Review if it's a secret.",
                        "source": f"reconstructed:{rv['method']}",
                    })

    ctx.findings.sort(key=lambda f: f["confidence"], reverse=True)


def _add_finding(ctx: ScanContext, seen: dict, finding: dict) -> None:
    line, rule = finding["line"], finding["rule"]
    if line not in seen:
        seen[line] = set()
    if rule in seen[line]:
        return
    seen[line].add(rule)
    ctx.findings.append(finding)


def _compute_confidence(rule: dict, matched_value: str, line: str,
                        filename: str, line_num: int, all_lines: list[str]) -> int:
    score = rule.get("base_score", 50)
    entropy = shannon_entropy(matched_value)
    vlen = len(matched_value)

    if entropy >= 5.0 and vlen >= 32:
        score += 20
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

    if vlen >= 40: score += 10
    elif vlen >= 24: score += 5
    elif vlen < 8 and rule.get("needs_entropy", False): score -= 15

    # Noise detection
    if vlen >= 16 and len(set(matched_value)) <= 3: score -= 50
    elif vlen >= 16 and entropy < 2.0: score -= 35
    if re.match(r"^(?:0123456789|abcdefghij|ABCDEFGHIJ)", matched_value): score -= 15
    if re.match(r"^[a-z]+$", matched_value) and entropy < 3.5: score -= 20
    if re.match(r"^[0-9]+$", matched_value) and entropy < 3.0: score -= 25

    sensitive_kw = ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth", "credential", "private", "access_key"]
    line_lower = line.lower()
    if any(kw in line_lower for kw in sensitive_kw): score += 10
    if is_test_file(filename): score -= 25
    if is_placeholder(matched_value): score -= 40
    if is_comment(line.strip()): score -= 20
    if re.search(r"\$\{|\$\(|process\.env|os\.environ|getenv|System\.getenv", line): score -= 30
    if re.search(r"(?:example|sample|dummy|fake|mock|test|placeholder)", line_lower): score -= 20

    nearby = 0
    for offset in [-2, -1, 1, 2]:
        idx = line_num - 1 + offset
        if 0 <= idx < len(all_lines):
            if any(kw in all_lines[idx].lower() for kw in ["password", "secret", "key", "token"]):
                nearby += 1
    if nearby >= 2: score += 5
    if entropy >= 4.5 and any(kw in line_lower for kw in sensitive_kw) and not is_test_file(filename):
        score += 5

    return max(0, min(100, score))


def _score_to_severity(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 50: return "MEDIUM"
    if score >= 30: return "LOW"
    return "INFO"
