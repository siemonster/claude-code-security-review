import pytest

from claudecode.validate_action_result import ReviewValidationError, validate_review_result


def completed(findings=None):
    return {
        "findings": [] if findings is None else findings,
        "analysis_summary": {"review_completed": True},
    }


def test_accepts_completed_review_without_findings():
    assert validate_review_result(completed(), 0) == []


def test_accepts_exit_one_only_for_completed_high_finding():
    findings = [{"severity": "HIGH", "file": "service.go", "line": 12}]
    assert validate_review_result(completed(findings), 1) == findings


@pytest.mark.parametrize(
    ("payload", "exit_code", "message"),
    [
        ({"error": "authentication failed"}, 1, "operational error"),
        (completed(), 1, "inconsistent"),
        ({"findings": []}, 0, "attest completion"),
        ({"findings": "none", "analysis_summary": {"review_completed": True}}, 0, "findings array"),
        (completed(), 2, "inconsistent"),
    ],
)
def test_rejects_incomplete_or_operational_results(payload, exit_code, message):
    with pytest.raises(ReviewValidationError, match=message):
        validate_review_result(payload, exit_code)
