"""Shared data models for the detection pipeline."""

from dataclasses import dataclass, field


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
