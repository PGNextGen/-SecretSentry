"""Pipeline runner — orchestrates all 6 detection stages."""

from .models import ScanContext
from .stages import (
    stage_normalize,
    stage_decode,
    stage_reconstruct,
    stage_prefix_intelligence,
    stage_regex,
    stage_score_and_merge,
)


def scan(code: str, filename: str) -> list[dict]:
    """Run the full 6-stage detection pipeline."""
    ctx = ScanContext(code=code, filename=filename)

    stage_normalize(ctx)            # Stage 1: Normalization
    stage_decode(ctx)               # Stage 2: Decoding + chained transforms
    stage_reconstruct(ctx)          # Stage 3: Reconstruction
    stage_prefix_intelligence(ctx)  # Stage 4: Prefix intelligence
    stage_regex(ctx)                # Stage 5: Regex pattern matching
    stage_score_and_merge(ctx)      # Stage 6: Confidence scoring + merge

    return ctx.findings
