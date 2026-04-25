# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp"]
# ///

"""Thin entry point for `uv run server.py` — delegates to the package."""

import sys
import os

# Add src to path so the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from secret_sentry.server import main

if __name__ == "__main__":
    main()
