#!/usr/bin/env python3
"""Exact-head completion state used by the composite action cache."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def completed_marker_matches(payload: Any, head_sha: str) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("status") == "completed"
        and payload.get("sha") == head_sha
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("marker", type=Path)
    parser.add_argument("head_sha")
    args = parser.parse_args()

    try:
        payload = json.loads(args.marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("false")
        return 0

    print(str(completed_marker_matches(payload, args.head_sha)).lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
