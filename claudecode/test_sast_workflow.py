"""Offline contract for every GitHub workflow in this repository.

The checks read workflow text and the local tree. They do not call GitHub
and they do not use a live credential. Retired self-scan bytes are pinned so
a depth-1 checkout can still reject them. git show must match that pin when
the revision is present.
"""

import base64
import hashlib
import re
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
RETAINED = "test-claudecode.yml"
CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"
CHECKOUT_USES = "actions/checkout@" + CHECKOUT_PIN
ACTION_SHA256 = "25790befaff78640c13e46724eedb0e54e878c119340d9a46f0fc726ecca37a8"
BASE = "060c75a700cb23da3ce30ce6154f899dea7d0212"
ROUND1 = "9462229fbf760f6beaf247cf432f622bff54fc9a"
SAST_PATH = ".github/workflows/sast.yml"
# Exact git blobs. These are not workflow files in the tree.
PINNED_SAST_SHA256 = {
    BASE: "3c0e2b25840e3a4c385c03ec1b72df943be067b480f905ae0311615744457a72",
    ROUND1: "e9be7118491afe5d421f68ff99982a3c55563b7d11b7904fa3d81d343eba8608",
}
PINNED_SAST_B64 = {
    BASE: (
        "bmFtZTogU0FTVAoKb246CiAgcHVsbF9yZXF1ZXN0OgogIHB1c2g6CiAgICBicmFuY2hlczoK"
        "ICAgICAgLSBtYWluCiAgd29ya2Zsb3dfZGlzcGF0Y2g6Cgpqb2JzOgogIHNlY3VyaXR5LXJldmlldzoK"
        "ICAgIHJ1bnMtb246IHVidW50dS0yNC4wNAogICAgcGVybWlzc2lvbnM6CiAgICAgIGNvbnRlbnRzOiByZWFk"
        "CiAgICAgIHB1bGwtcmVxdWVzdHM6IHdyaXRlCiAgICBzdGVwczoKICAgICAgLSB1c2VzOiBhY3Rpb25zL2"
        "NoZWNrb3V0QDM0ZTExNDg3NmIwYjExYzM5MGE1NjM4MWFkMTZlYmQxMzkxNGY4ZDUgIyB2NC4zLjEgcGlubmVk"
        "IHRvIGNvbW1pdCBoYXNoCgogICAgICAtIHVzZXM6IC4vICMgUG9pbnRzIGRpcmVjdGx5IHRvIGFjdGlvbi55bWwK"
        "ICAgICAgICB3aXRoOgogICAgICAgICAgIyBUaGlzIHJlcG9zaXRvcnkgaXMgcHVibGljLCBzbyBpdHMgcmV2aWV3"
        "IGNvbW1lbnRzIGFuZCBhcnRpZmFjdHMgYXJlIHRvby4KICAgICAgICAgICMgVGhlIHNjYW4gcnVucyB3aXRoIGEg"
        "Q2xhdWRlIGNyZWRlbnRpYWw7IGtlZXAgaXRzIG91dHB1dCBvdXQgb2YgYm90aC4KICAgICAgICAgIGNvbW1lbnQtcHI6"
        "IGZhbHNlCiAgICAgICAgICB1cGxvYWQtcmVzdWx0czogZmFsc2UKICAgICAgICAgIGV4Y2x1ZGUtZGlyZWN0b3JpZXM6"
        "ICJ0ZXN0cy92dWxuZXJhYmxlIgogICAgICAgICAgY2xhdWRlLWFwaS1rZXk6ICR7eyBzZWNyZXRzLkNMQVVERV9BUElf"
        "S0VZIH19CiAgICAgICAgICBjbGF1ZGUtY29kZS1vYXV0aC10b2tlbjogJHt7IHNlY3JldHMuQ0xBVURFX0NPREVfT0FV"
        "VEhfVE9LRU4gfX0KICAgICAgICAgIHJ1bi1ldmVyeS1jb21taXQ6IHRydWUK"
    ),
    ROUND1: (
        "bmFtZTogU0FTVAoKb246CiAgcHVzaDoKICAgIGJyYW5jaGVzOgogICAgICAtIG1haW4KICB3b3JrZmxvd19kaXNw"
        "YXRjaDoKCmpvYnM6CiAgc2VjdXJpdHktcmV2aWV3OgogICAgIyBSZXBvc2l0b3J5IHNlY3JldHMgYXJlIGF2YWls"
        "YWJsZSB0byB0aGlzIHdvcmtmbG93LiBSdW4gb25seSB3aGVuIHRoZQogICAgIyBjaGVja2VkLW91dCBjb21taXQgaXMg"
        "dGhlIHRydXN0ZWQgbWFpbiByZWY6IGEgcHVzaCB0byBtYWluLCBvciBhIG1hbnVhbAogICAgIyBkaXNwYXRjaCBvZiBt"
        "YWluLiBBbnkgb3RoZXIgcmVmIGlzIHVudHJ1c3RlZCBjb2RlLgogICAgaWY6ICJnaXRodWIucmVmID09ICdyZWZzL2hl"
        "YWRzL21haW4nICYmIChnaXRodWIuZXZlbnRfbmFtZSA9PSAncHVzaCcgfHwgZ2l0aHViLmV2ZW50X25hbWUgPT0gJ3dv"
        "cmtmbG93X2Rpc3BhdGNoJykiCiAgICBydW5zLW9uOiB1YnVudHUtMjQuMDQKICAgIHBlcm1pc3Npb25zOgogICAgICBj"
        "b250ZW50czogcmVhZAogICAgICBwdWxsLXJlcXVlc3RzOiB3cml0ZQogICAgc3RlcHM6CiAgICAgIC0gdXNlczogYWN0"
        "aW9ucy9jaGVja291dEAzNGUxMTQ4NzZiMGIxMWMzOTBhNTYzODFhZDE2ZWJkMTM5MTRmOGQ1ICMgdjQuMy4xIHBpbm5l"
        "ZCB0byBjb21taXQgaGFzaAoKICAgICAgLSB1c2VzOiAuLyAjIFBvaW50cyBkaXJlY3RseSB0byBhY3Rpb24ueW1sCiAg"
        "ICAgICAgd2l0aDoKICAgICAgICAgICMgVGhpcyByZXBvc2l0b3J5IGlzIHB1YmxpYywgc28gaXRzIHJldmlldyBjb21t"
        "ZW50cyBhbmQgYXJ0aWZhY3RzIGFyZSB0b28uCiAgICAgICAgICAjIFRoZSBzY2FuIHJ1bnMgd2l0aCBhIENsYXVkZSBj"
        "cmVkZW50aWFsOyBrZWVwIGl0cyBvdXRwdXQgb3V0IG9mIGJvdGguCiAgICAgICAgICBjb21tZW50LXByOiBmYWxzZQog"
        "ICAgICAgICAgdXBsb2FkLXJlc3VsdHM6IGZhbHNlCiAgICAgICAgICBleGNsdWRlLWRpcmVjdG9yaWVzOiAidGVzdHMv"
        "dnVsbmVyYWJsZSIKICAgICAgICAgIGNsYXVkZS1hcGkta2V5OiAke3sgc2VjcmV0cy5DTEFVREVfQVBJX0tFWSB9fQog"
        "ICAgICAgICAgY2xhdWRlLWNvZGUtb2F1dGgtdG9rZW46ICR7eyBzZWNyZXRzLkNMQVVERV9DT0RFX09BVVRIX1RPS0VO"
        "IH19CiAgICAgICAgICBydW4tZXZlcnktY29tbWl0OiB0cnVlCg=="
    ),
}
SECRET_MARKERS = ("CLAUDE_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "secrets.CLAUDE_")
RETAINED_PERMISSIONS = {
    "contents": "read",
    "pull-requests": "read",
    "actions": "read",
    "checks": "read",
}
SCAN_GUARD = (
    '        # Skip ClaudeCode if not a PR\n'
    '        if [ "${{ github.event_name }}" != "pull_request" ]; then\n'
    '          echo "ClaudeCode only runs on pull requests, skipping"\n'
    '          exit 0\n'
    '        fi\n'
)


class WorkflowLoader(yaml.SafeLoader):
    """Parse a workflow without treating the trigger key as a boolean."""


def _install_workflow_bool_resolver():
    copied = {}
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items():
        copied[first] = [
            (tag, pattern)
            for tag, pattern in resolvers
            if tag != "tag:yaml.org,2002:bool"
        ]
    WorkflowLoader.yaml_implicit_resolvers = copied
    WorkflowLoader.add_implicit_resolver(
        "tag:yaml.org,2002:bool",
        re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
        list("tTfF"),
    )


_install_workflow_bool_resolver()


def git_show(rev, path):
    result = subprocess.run(
        ["git", "show", "%s:%s" % (rev, path)],
        cwd=ROOT,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _trigger_names(on_value):
    if isinstance(on_value, str):
        return {on_value}
    if isinstance(on_value, list):
        return {item for item in on_value if isinstance(item, str)}
    if isinstance(on_value, dict):
        return {key for key in on_value if isinstance(key, str)}
    return set()


def _is_true(value):
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _permission_problems(value, scope):
    problems = []
    if isinstance(value, str) and value.lower() == "write-all":
        problems.append("%s permissions write-all" % scope)
        return problems
    if not isinstance(value, dict):
        return problems
    for key, item in value.items():
        if isinstance(item, str) and item.lower() == "write-all":
            problems.append("%s permissions write-all" % scope)
        if str(key).lower() == "pull-requests" and isinstance(item, str) and item.lower() == "write":
            problems.append("%s pull-requests write" % scope)
    return problems


def _if_disables(value):
    """True when a job if is boolean false or a string that means false."""
    if value is False:
        return True
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if stripped.lower() == "false":
        return True
    return re.fullmatch(r"\$\{\{\s*false\s*\}\}", stripped, re.IGNORECASE) is not None


def _step_rows(loaded):
    """Return (job name, step index, step mapping) without mixing jobs together."""
    jobs = loaded.get("jobs")
    if not isinstance(jobs, dict):
        return []
    rows = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if isinstance(step, dict):
                rows.append((str(job_name), index, step))
    return rows


def _baseline_rows(rows, jobs):
    """The one unconditional checkout in the retained test job, if it exists."""
    job = jobs.get("test-claudecode") if isinstance(jobs, dict) else None
    disabled = isinstance(job, dict) and "if" in job and _if_disables(job.get("if"))
    matches = []
    for index, (job_name, _step_index, step) in enumerate(rows):
        if job_name != "test-claudecode" or disabled:
            continue
        if step.get("uses") != CHECKOUT_USES or "if" in step:
            continue
        matches.append(index)
    if len(matches) == 1:
        return matches, []
    if len(matches) == 0:
        return [], ["baseline checkout is missing"]
    return [], ["baseline checkout is not unique"]


def _checkout_problems(uses, with_block, baseline):
    """Judge one checkout step.

    Only the identified baseline step may omit persist-credentials. That
    step may also set the flag to boolean false. Every other checkout must
    set it to boolean false, and true is rejected on every step.
    """
    problems = []
    if not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", uses):
        problems.append("actions/checkout is not pinned to a 40-hex SHA")
    if not isinstance(with_block, dict):
        with_block = {}
    if "persist-credentials" not in with_block:
        if not baseline:
            problems.append("persist-credentials false is required")
        return problems
    flag = with_block["persist-credentials"]
    if _is_true(flag):
        problems.append("persist-credentials true")
    if flag is not False:
        problems.append("persist-credentials is not false")
    return problems


def _secret_problems(value, prefix):
    problems = []
    if not isinstance(value, str):
        return problems
    lowered = value.lower()
    for marker in SECRET_MARKERS:
        if marker.lower() in lowered:
            problems.append("%s %s" % (prefix, marker))
    return problems


def workflow_problems(text, name):
    """Return contract violations for one workflow file's text."""
    problems = []
    if not isinstance(text, str):
        return ["workflow text is not a string"]
    problems.extend(_secret_problems(text, "secret reference"))
    if "pull_request_target" in text:
        problems.append("pull_request_target trigger")
    try:
        loaded = yaml.load(text, Loader=WorkflowLoader)
    except yaml.YAMLError as exc:
        problems.append("workflow YAML rejected: %s" % exc)
        return problems
    if not isinstance(loaded, dict):
        problems.append("workflow root is not a mapping")
        return problems
    if True in loaded:
        problems.append("trigger key parsed as a boolean")
    for value in _strings(loaded):
        problems.extend(_secret_problems(value, "parsed secret reference"))
    for node in _walk(loaded):
        uses = node.get("uses")
        if isinstance(uses, str) and (uses == "./" or uses.startswith("./")):
            problems.append("local composite uses")
        if "comment-pr" in node and _is_true(node["comment-pr"]):
            problems.append("comment-pr true")
        if "upload-results" in node and _is_true(node["upload-results"]):
            problems.append("upload-results true")
    rows = _step_rows(loaded)
    exempt = []
    if name == RETAINED:
        exempt, baseline_problems = _baseline_rows(rows, loaded.get("jobs"))
        problems.extend(baseline_problems)
    for index, (_job_name, _step_index, step) in enumerate(rows):
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("actions/checkout"):
            problems.extend(_checkout_problems(uses, step.get("with"), index in exempt))
    if "pull_request_target" in _trigger_names(loaded.get("on")):
        problems.append("pull_request_target trigger")
    if "permissions" in loaded:
        problems.extend(_permission_problems(loaded["permissions"], "workflow"))
    jobs = loaded.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if "permissions" in job:
                if name == RETAINED:
                    problems.append("job-level permissions")
                problems.extend(_permission_problems(job["permissions"], "job %s" % job_name))
    if name == RETAINED and loaded.get("permissions") != RETAINED_PERMISSIONS:
        problems.append("retained permissions are not the read set")
    return problems


def assert_workflow(text, name):
    problems = workflow_problems(text, name)
    if problems:
        raise AssertionError("\n".join(problems))


def live_problems(root=ROOT):
    problems = []
    directory = root / ".github" / "workflows"
    if (directory / "sast.yml").exists() or (directory / "sast.yaml").exists():
        problems.append("sast.yml exists")
    if not directory.is_dir():
        return problems + ["workflows directory is missing"]
    found = sorted(
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    if found != [RETAINED]:
        problems.append("workflow set is %s" % found)
    for name in found:
        text = (directory / name).read_text()
        for problem in workflow_problems(text, name):
            problems.append("%s: %s" % (name, problem))
    return problems


def _once(text, old, new):
    count = text.count(old)
    if count != 1:
        raise AssertionError("expected one occurrence, found %s" % count)
    return text.replace(old, new, 1)


def _rejected(text, name, needle):
    problems = workflow_problems(text, name)
    assert problems, "mutant survived"
    assert any(needle in problem for problem in problems), problems


def _historical(rev):
    pinned = base64.b64decode(PINNED_SAST_B64[rev])
    assert hashlib.sha256(pinned).hexdigest() == PINNED_SAST_SHA256[rev]
    shown = git_show(rev, SAST_PATH)
    if shown is None:
        return pinned.decode()
    assert shown == pinned
    return shown.decode()


def test_loader_does_not_change_default_yaml_bools():
    loaded = yaml.load("on:\n  push:\n", Loader=WorkflowLoader)
    assert "on" in loaded
    assert yaml.safe_load("value: on\n")["value"] is True
    assert yaml.safe_load("value: false\n")["value"] is False


def test_live_tree_passes():
    assert live_problems() == []


def test_action_yml_matches_base_digest():
    path = ROOT / "action.yml"
    assert path.is_file()
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == ACTION_SHA256
    assert SCAN_GUARD.encode() in data
    shown = git_show(BASE, "action.yml")
    if shown is not None:
        assert shown == data


def test_pinned_self_scan_is_used_when_git_show_is_absent(monkeypatch):
    monkeypatch.setattr("%s.git_show" % __name__, lambda rev, path: None)
    text = _historical(BASE)
    assert "refs/heads/main" not in text
    _rejected(text, "sast.yml", "local composite uses")
    _rejected(_historical(ROUND1), "sast.yml", "job security-review pull-requests write")


def test_base_self_scan_is_rejected():
    text = _historical(BASE)
    _rejected(text, "sast.yml", "secret reference CLAUDE_API_KEY")
    _rejected(text, "sast.yml", "secret reference CLAUDE_CODE_OAUTH_TOKEN")
    _rejected(text, "sast.yml", "local composite uses")
    _rejected(text, "sast.yml", "pull-requests write")


def test_round1_self_scan_is_rejected_including_case_variant_ref():
    text = _historical(ROUND1)
    _rejected(text, "sast.yml", "secret reference CLAUDE_API_KEY")
    _rejected(text, "sast.yml", "local composite uses")
    _rejected(text, "sast.yml", "job security-review pull-requests write")
    variant = _once(text, "refs/heads/main", "refs/heads/Main")
    _rejected(variant, "sast.yml", "secret reference CLAUDE_CODE_OAUTH_TOKEN")
    _rejected(variant, "sast.yml", "local composite uses")
    _rejected(variant, "sast.yml", "pull-requests write")


def test_added_secret_references_are_rejected():
    text = (WORKFLOWS / RETAINED).read_text()
    api = text + "\n      - run: echo\n        env:\n          EXAMPLE: ${{ secrets.CLAUDE_API_KEY }}\n"
    oauth = text + "\n      - run: echo\n        env:\n          EXAMPLE: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}\n"
    _rejected(api, RETAINED, "secret reference CLAUDE_API_KEY")
    _rejected(oauth, RETAINED, "secret reference CLAUDE_CODE_OAUTH_TOKEN")


def test_secret_identifiers_are_case_insensitive():
    text = (WORKFLOWS / RETAINED).read_text()
    assert "Install Claude CLI" in text
    assert "claude-code" in text
    assert workflow_problems(text, RETAINED) == []
    lower = text + "\n      - run: echo\n        env:\n          EXAMPLE: ${{ secrets.claude_api_key }}\n"
    mixed = text + "\n      - run: echo\n        env:\n          EXAMPLE: ${{ secrets.Claude_Code_OAuth_Token }}\n"
    custom = text + "\n      - run: echo\n        env:\n          EXAMPLE: ${{ secrets.claude_custom }}\n"
    _rejected(lower, RETAINED, "secret reference CLAUDE_API_KEY")
    _rejected(mixed, RETAINED, "secret reference CLAUDE_CODE_OAUTH_TOKEN")
    _rejected(custom, RETAINED, "secret reference secrets.CLAUDE_")
    ordinary = (
        "name: extra\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo Install Claude CLI && npm install @anthropic-ai/claude-code\n"
    )
    assert not any("secret reference" in problem for problem in workflow_problems(ordinary, "extra.yml"))


def test_local_composite_is_rejected():
    text = (WORKFLOWS / RETAINED).read_text() + "\n      - uses: ./\n"
    _rejected(text, RETAINED, "local composite uses")


def test_pull_request_target_is_rejected():
    text = _once(
        (WORKFLOWS / RETAINED).read_text(),
        "on:\n  pull_request:\n",
        "on:\n  pull_request:\n  pull_request_target:\n",
    )
    _rejected(text, RETAINED, "pull_request_target trigger")


def test_pull_requests_write_is_rejected():
    text = _once((WORKFLOWS / RETAINED).read_text(), "pull-requests: read", "pull-requests: write")
    _rejected(text, RETAINED, "pull-requests write")


def test_write_all_is_rejected():
    text = _once(
        (WORKFLOWS / RETAINED).read_text(),
        "permissions:\n  contents: read\n  pull-requests: read\n  actions: read\n  checks: read\n",
        "permissions: write-all\n",
    )
    _rejected(text, RETAINED, "write-all")
    job_level = _once(
        (WORKFLOWS / RETAINED).read_text(),
        "  test-claudecode:\n    runs-on: ubuntu-latest\n",
        "  test-claudecode:\n    permissions: write-all\n    runs-on: ubuntu-latest\n",
    )
    _rejected(job_level, RETAINED, "write-all")


def test_public_output_flags_are_rejected():
    text = (WORKFLOWS / RETAINED).read_text()
    comment = text + "\n      - run: echo\n        with:\n          comment-pr: true\n"
    upload = text + "\n      - run: echo\n        with:\n          upload-results: true\n"
    _rejected(comment, RETAINED, "comment-pr true")
    _rejected(upload, RETAINED, "upload-results true")


def test_unpinned_checkout_is_rejected():
    text = _once(
        (WORKFLOWS / RETAINED).read_text(),
        CHECKOUT_USES,
        "actions/checkout@v4",
    )
    _rejected(text, RETAINED, "actions/checkout is not pinned to a 40-hex SHA")


def test_nonbaseline_checkout_must_disable_persist_credentials():
    bare = (
        "name: extra\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: %s\n" % CHECKOUT_USES
    )
    closed = bare + "        with:\n          persist-credentials: false\n"
    _rejected(bare, "extra.yml", "persist-credentials false is required")
    assert workflow_problems(closed, "extra.yml") == []
    enabled = bare + "        with:\n          persist-credentials: true\n"
    _rejected(enabled, "extra.yml", "persist-credentials true")
    retained = _once(
        (WORKFLOWS / RETAINED).read_text(),
        "      - uses: %s # v4.3.1 pinned to commit hash\n" % CHECKOUT_USES,
        "      - uses: %s # v4.3.1 pinned to commit hash\n"
        "        with:\n"
        "          persist-credentials: true\n" % CHECKOUT_USES,
    )
    _rejected(retained, RETAINED, "persist-credentials true")


def _checkout_line():
    return "      - uses: %s # v4.3.1 pinned to commit hash\n" % CHECKOUT_USES


def test_retained_baseline_checkout_is_required():
    text = (WORKFLOWS / RETAINED).read_text()
    assert workflow_problems(text, RETAINED) == []
    removed = _once(text, _checkout_line(), "")
    _rejected(removed, RETAINED, "baseline checkout is missing")


def test_second_retained_checkout_must_disable_persist_credentials():
    text = (WORKFLOWS / RETAINED).read_text()
    line = _checkout_line()
    bare = _once(text, line, line + "      - uses: %s\n" % CHECKOUT_USES)
    _rejected(bare, RETAINED, "persist-credentials false is required")
    other_pin = "actions/checkout@" + ("a" * 40)
    other = _once(text, line, line + "      - uses: %s\n" % other_pin)
    _rejected(other, RETAINED, "persist-credentials false is required")
    closed = _once(
        text,
        line,
        line + "      - uses: %s\n        with:\n          persist-credentials: false\n" % other_pin,
    )
    assert workflow_problems(closed, RETAINED) == []


def test_baseline_checkout_moved_to_another_job_is_rejected():
    text = (WORKFLOWS / RETAINED).read_text()
    line = _checkout_line()
    moved = _once(text, line, "")
    if not moved.endswith("\n"):
        moved += "\n"
    moved += "  other:\n    runs-on: ubuntu-latest\n    steps:\n" + line
    _rejected(moved, RETAINED, "baseline checkout is missing")


def test_disabled_baseline_checkout_is_rejected():
    text = (WORKFLOWS / RETAINED).read_text()
    line = _checkout_line()
    disabled = _once(text, line, line + "        if: false\n")
    _rejected(disabled, RETAINED, "baseline checkout is missing")
    conditional = _once(
        text,
        line,
        line + "        if: github.event_name == 'pull_request'\n",
    )
    _rejected(conditional, RETAINED, "baseline checkout is missing")
    job_disabled = _once(
        text,
        "  test-claudecode:\n    runs-on: ubuntu-latest\n",
        "  test-claudecode:\n    if: false\n    runs-on: ubuntu-latest\n",
    )
    _rejected(job_disabled, RETAINED, "baseline checkout is missing")


def test_baseline_checkout_may_set_persist_credentials_false():
    text = (WORKFLOWS / RETAINED).read_text()
    line = _checkout_line()
    closed = _once(
        text,
        line,
        "      - uses: %s # v4.3.1 pinned to commit hash\n"
        "        with:\n"
        "          persist-credentials: false\n" % CHECKOUT_USES,
    )
    assert "if:" not in closed.split("jobs:", 1)[1].split("steps:", 1)[1].split("- name:", 1)[0]
    assert workflow_problems(closed, RETAINED) == []
