"""Shared utility functions used across pipeline stages."""

import math
import os
import re


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_placeholder(value: str) -> bool:
    placeholders = {
        "xxx", "yyy", "zzz", "todo", "fixme", "changeme", "replace_me",
        "your_key_here", "your_secret_here", "your_api_key", "insert_here",
        "placeholder", "example", "test", "dummy", "sample", "fake",
        "none", "null", "undefined", "empty", "n/a", "change_me",
        "your_token_here", "your_password", "enter_here", "update_me",
    }
    lower = value.lower().strip("'\" ")
    if lower in placeholders:
        return True
    if re.match(r"^[x*#<>]{4,}$", lower):
        return True
    if re.match(r"^\$\{.+\}$", value) or re.match(r"^%\(.+\)s$", value):
        return True
    if re.match(r"^\{\{.+\}\}$", value):
        return True
    if value.startswith("${") or value.startswith("#{") or value.startswith("%("):
        return True
    if re.search(r"os\.environ|process\.env|System\.getenv|getenv", value):
        return True
    return False


def is_test_file(filename: str) -> bool:
    lower = filename.lower()
    return any(ind in lower for ind in [
        "test", "spec", "mock", "fake", "fixture", "stub",
        "example", "sample", "demo", "_test.", ".test.",
    ])


def is_comment(line: str) -> bool:
    return (
        line.startswith("//") or line.startswith("#") or line.startswith("*")
        or line.startswith("/*") or line.startswith("<!--")
        or line.startswith("--") or line.startswith("REM ")
    )


def is_binary(filepath: str) -> bool:
    binary_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".jar", ".aar", ".apk", ".aab", ".war", ".ear",
        ".so", ".dylib", ".dll", ".exe", ".class", ".dex", ".o", ".a",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".sqlite", ".db", ".mdb", ".pyc", ".pyo", ".wasm",
    }
    _, ext = os.path.splitext(filepath)
    return ext.lower() in binary_exts


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def mask_finding(text: str) -> str:
    if len(text) > 80:
        return text[:40] + "..." + text[-20:]
    return text
