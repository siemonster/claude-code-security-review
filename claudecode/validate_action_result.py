#!/usr/bin/env python3
"""Fail-closed validation for the composite action's review result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class ReviewValidationError(ValueError):
    """The reviewer did not produce a completed, trustworthy result."""


def validate_review_result(payload: Any, process_exit_code: int) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ReviewValidationError("review result must be a JSON object")

    if payload.get("error"):
        raise ReviewValidationError("reviewer reported an operational error")

    findings = payload.get("findings")
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ReviewValidationError("review result must contain a findings array")

    summary = payload.get("analysis_summary")
    if not isinstance(summary, dict) or summary.get("review_completed") is not True:
        raise ReviewValidationError("review did not attest completion")

    has_high_finding = any(
        str(finding.get("severity", "")).upper() == "HIGH" for finding in findings
    )
    expected_exit_codes = {0, 1} if has_high_finding else {0}
    if process_exit_code not in expected_exit_codes:
        raise ReviewValidationError(
            f"reviewer exit code {process_exit_code} is inconsistent with the validated result"
        )

    return findings


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--process-exit-code", type=int, required=True)
    parser.add_argument("--findings-output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--reviewed-head-sha", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        payload = json.loads(args.results.read_text(encoding="utf-8"))
        findings = validate_review_result(payload, args.process_exit_code)
    except (OSError, json.JSONDecodeError, ReviewValidationError) as exc:
        print(f"::error::Security review failed closed: {exc}")
        return 1

    args.findings_output.write_text(
        json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with args.github_output.open("a", encoding="utf-8") as output:
        output.write(f"findings_count={len(findings)}\n")
        output.write("results_file=claudecode-results.json\n")
        output.write("review_status=completed\n")
        output.write(f"reviewed_head_sha={args.reviewed_head_sha}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
