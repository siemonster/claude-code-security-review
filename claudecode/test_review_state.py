from pathlib import Path

from claudecode.review_state import completed_marker_matches


def test_completed_marker_matches_only_exact_head():
    marker = {"status": "completed", "sha": "head-a"}
    assert completed_marker_matches(marker, "head-a") is True
    assert completed_marker_matches(marker, "head-b") is False


def test_reserved_or_malformed_marker_never_satisfies_review():
    assert completed_marker_matches({"status": "reserved", "sha": "head-a"}, "head-a") is False
    assert completed_marker_matches({}, "head-a") is False
    assert completed_marker_matches([], "head-a") is False


def test_action_cache_is_exact_head_and_has_no_prefix_restore():
    action_source = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")
    exact_key = "pr-${{ github.event.pull_request.number }}-${{ github.event.pull_request.head.sha }}"
    assert action_source.count(exact_key) == 2
    assert "restore-keys:" not in action_source
    assert "uses: actions/cache/restore@" in action_source
    assert "uses: actions/cache@" not in action_source
    assert 'status") == "completed"' not in action_source  # helper owns marker semantics
