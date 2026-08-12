"""Contract tests for the action's Claude credential wiring.

The credential selection lives in action.yml shell, which no other suite
covers. These tests pin the two properties that make an out-of-credit API key
survivable: either credential is accepted, and an explicitly-supplied OAuth
token wins over an API key the CLI would otherwise prefer.
"""

import subprocess
from pathlib import Path

import yaml

ACTION_YML = Path(__file__).resolve().parents[1] / "action.yml"


def _action():
    return yaml.safe_load(ACTION_YML.read_text())


def _scan_step():
    steps = _action()["runs"]["steps"]
    return next(s for s in steps if s.get("id") == "claudecode-scan")


def test_either_credential_input_is_accepted():
    inputs = _action()["inputs"]
    assert inputs["claude-api-key"]["required"] is False
    assert "claude-code-oauth-token" in inputs
    assert inputs["claude-code-oauth-token"]["required"] is False


def test_scan_step_exports_both_credentials():
    env = _scan_step()["env"]
    assert env["ANTHROPIC_API_KEY"] == "${{ inputs.claude-api-key }}"
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "${{ inputs.claude-code-oauth-token }}"


def test_oauth_token_clears_the_api_key_so_the_cli_uses_it():
    run = _scan_step()["run"]
    assert 'if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ]; then' in run
    assert "unset ANTHROPIC_API_KEY" in run


def _credential_gate(api_key: str, oauth_token: str) -> int:
    """Execute the action's fail-closed credential gate in isolation."""
    gate = (
        'if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$CLAUDE_CODE_OAUTH_TOKEN" ]; then\n'
        "  exit 1\nfi\nexit 0\n"
    )
    assert gate.splitlines()[0] in _scan_step()["run"]
    return subprocess.run(
        ["bash", "-c", gate],
        env={"ANTHROPIC_API_KEY": api_key, "CLAUDE_CODE_OAUTH_TOKEN": oauth_token},
    ).returncode


def test_gate_fails_closed_without_any_credential():
    assert _credential_gate("", "") == 1


def test_gate_passes_with_either_credential():
    assert _credential_gate("sk-test", "") == 0
    assert _credential_gate("", "oauth-test") == 0
    assert _credential_gate("sk-test", "oauth-test") == 0
