"""SecretSentry MCP Server — tool definitions and entry point."""

import os

from mcp.server.fastmcp import FastMCP

from .pipeline import scan
from .formatter import format_findings, format_directory_findings, severity_emoji
from .utils import shannon_entropy, mask, is_binary
from .stages.prefix import PREFIX_DB

mcp = FastMCP("secret-sentry")


@mcp.tool()
def scan_code(code: str, filename: str = "unknown") -> str:
    """Scans code for hardcoded secrets, credentials, API keys, and risky values.

    Args:
        code: The source code content to scan.
        filename: The filename (used for context-aware filtering). Defaults to "unknown".
    """
    return format_findings(scan(code, filename), filename)


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
    return format_findings(scan(code, filename), filename)


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
    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".gradle", "build",
        ".idea", ".vscode", ".kiro", "venv", ".venv", "dist", "target",
        ".mypy_cache", ".pytest_cache", ".tox", "egg-info",
    }

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if ext_filter and not any(fname.endswith(ext) for ext in ext_filter):
                continue
            fpath = os.path.join(root, fname)
            if is_binary(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                findings = scan(code, fname)
                rel = os.path.relpath(fpath, path)
                for finding in findings:
                    finding["file"] = rel
                all_findings.extend(findings)
                files_scanned += 1
            except Exception:
                continue

    all_findings.sort(key=lambda f: f["confidence"], reverse=True)
    return format_directory_findings(all_findings, dirpath, files_scanned)


@mcp.tool()
def check_entropy(value: str) -> str:
    """Checks if a string value looks like a secret based on Shannon entropy.

    Args:
        value: The string value to analyze.
    """
    ent = shannon_entropy(value)
    length = len(value)
    score = 95 if ent >= 5.0 and length >= 32 else 80 if ent >= 4.5 and length >= 24 else 60 if ent >= 4.0 and length >= 16 else 40 if ent >= 3.5 and length >= 12 else 20 if ent >= 3.0 else 5

    sev = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 50 else "LOW" if score >= 30 else "INFO"
    emoji = severity_emoji(sev)

    prefix_info = ""
    for pinfo in PREFIX_DB:
        if value.startswith(pinfo["prefix"]):
            prefix_info = f"\n   🏷️  Prefix match: {pinfo['provider']} {pinfo['type']}"
            break

    verdict = "Very likely a secret. Do not commit." if score >= 70 else "Possibly a secret. Review before committing." if score >= 50 else "Low probability of being a secret." if score >= 30 else "Unlikely to be a secret."

    sections = [
        "🎲 Entropy Analysis",
        f"   Value: {mask(value)}",
        f"   Length: {length} chars",
        f"   Entropy: {ent:.2f} bits/char",
        f"   Confidence: {score}/100 ({sev})",
    ]
    if prefix_info:
        sections.append(prefix_info)
    sections.append("")
    sections.append(f"{emoji} Verdict: {verdict}")
    return "\n".join(sections)


def main():
    mcp.run()
