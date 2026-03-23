"""
Shared utilities for the Verifier Agent.
"""
from __future__ import annotations

import re
from typing import Any


def sanitize_sql(value: Any) -> str:
    """
    Minimal SQL-injection sanitiser for ClickHouse string interpolation.
    Strips single quotes, double quotes, semicolons, backslashes, and
    backticks to prevent injection via identifier or value escaping.
    """
    return re.sub(r"[';\"\\`]", "", str(value))
