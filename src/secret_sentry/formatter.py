"""Output formatting — tabular results with severity and source."""


def severity_emoji(sev: str) -> str:
    return {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}.get(sev, "❓")


def format_findings(findings: list[dict], filename: str) -> str:
    """Format findings into tabular output."""
    if not findings:
        return "✅ No secrets or risky values detected. Code looks clean."

    confirmed = [f for f in findings if f["category"] != "candidate"]
    candidates = [f for f in findings if f["category"] == "candidate"]

    sections = [
        "🔐 SecretSentry Scan Results",
        f"   File: {filename}",
        f"   Pipeline: normalize → decode → reconstruct → prefix → regex → score",
        f"   Findings: {len(confirmed)} confirmed | {len(candidates)} candidates",
        "",
    ]

    if confirmed:
        sections.append("## Confirmed Findings")
        sections.append("")
        sections.append("| # | Severity | Score | File | Line | Source | Rule | Match | Fix |")
        sections.append("|---|----------|-------|------|------|--------|------|-------|-----|")
        for i, f in enumerate(confirmed, 1):
            emoji = severity_emoji(f["severity"])
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
            emoji = severity_emoji(f["severity"])
            src = f.get("source", "regex")
            sections.append(
                f"| {i} | {emoji} {f['severity']} | {f['confidence']}/100 "
                f"| {filename} | {f['line']} | {src} | {f['rule']} "
                f"| `{f['match']}` | {f['fix']} |"
            )
        sections.append("")

    return "\n".join(sections)


def format_directory_findings(findings: list[dict], dirpath: str, files_scanned: int) -> str:
    """Format directory scan findings."""
    if not findings:
        return f"✅ Scanned {files_scanned} files — no secrets or risky values detected."

    confirmed = [f for f in findings if f["category"] != "candidate"]
    candidates = [f for f in findings if f["category"] == "candidate"]

    sections = [
        "🔐 SecretSentry Directory Scan Results",
        f"   Directory: {dirpath}",
        f"   Scanned: {files_scanned} files",
        f"   Pipeline: normalize → decode → reconstruct → prefix → regex → score",
        f"   Findings: {len(confirmed)} confirmed | {len(candidates)} candidates",
        "",
    ]

    for label, items in [("## Confirmed Findings", confirmed), ("## Possible Candidates (Review Recommended)", candidates)]:
        if not items:
            continue
        sections.append(label)
        sections.append("")
        sections.append("| # | Severity | Score | File | Line | Source | Rule | Match | Fix |")
        sections.append("|---|----------|-------|------|------|--------|------|-------|-----|")
        for i, f in enumerate(items, 1):
            emoji = severity_emoji(f["severity"])
            loc = f.get("file", "?")
            src = f.get("source", "regex")
            sections.append(f"| {i} | {emoji} {f['severity']} | {f['confidence']}/100 | {loc} | {f['line']} | {src} | {f['rule']} | `{f['match']}` | {f['fix']} |")
        sections.append("")

    return "\n".join(sections)
