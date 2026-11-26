"""Offline contract for the SAST workflow credential boundary.

The checks read .github/workflows/sast.yml. They do not call GitHub or use a
live credential. A copy that lets an untrusted event reach the local action,
turns either public output on, unpins actions/checkout, or drops either
Claude secret must fail. The workflow file as committed must pass.
"""

import re
from pathlib import Path

import pytest
import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "sast.yml"
CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"
CHECKOUT_USES = "actions/checkout@" + CHECKOUT_PIN
API_SECRET = "${{secrets.CLAUDE_API_KEY}}"
OAUTH_SECRET = "${{secrets.CLAUDE_CODE_OAUTH_TOKEN}}"
TRUSTED = (
    ("push", "refs/heads/main"),
    ("workflow_dispatch", "refs/heads/main"),
)
UNTRUSTED = (
    ("pull_request", "refs/pull/1/merge"),
    ("pull_request", "refs/heads/main"),
    ("pull_request_target", "refs/heads/main"),
    ("push", "refs/heads/other"),
    ("workflow_dispatch", "refs/heads/other"),
)
ALLOWED_TRIGGERS = {"push", "workflow_dispatch"}


class WorkflowLoader(yaml.SafeLoader):
    """Parse GitHub workflow YAML without treating the trigger key as a bool."""


def _install_workflow_bool_resolver():
    # SafeLoader's resolver map is shared with its subclasses until replaced.
    # Copy first so action.yml tests in this process still see YAML 1.1 bools.
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


class _ExprError(Exception):
    pass


class _Parser:
    def __init__(self, text, env):
        self.text = text
        self.n = len(text)
        self.i = 0
        self.env = env

    def parse(self):
        value = self._or()
        self._skip()
        if self.i != self.n:
            raise _ExprError("trailing %r" % self.text[self.i:])
        return value

    def _skip(self):
        while self.i < self.n and self.text[self.i].isspace():
            self.i += 1

    def _starts(self, token):
        return self.text.startswith(token, self.i)

    def _or(self):
        value = self._and()
        while True:
            self._skip()
            if not self._starts("||"):
                return value
            self.i += 2
            rhs = self._and()
            value = value or rhs

    def _and(self):
        value = self._unary()
        while True:
            self._skip()
            if not self._starts("&&"):
                return value
            self.i += 2
            rhs = self._unary()
            value = value and rhs

    def _unary(self):
        self._skip()
        if self._starts("!"):
            self.i += 1
            return not self._unary()
        return self._primary()

    def _primary(self):
        self._skip()
        if self._starts("("):
            self.i += 1
            value = self._or()
            self._skip()
            if not self._starts(")"):
                raise _ExprError("expected )")
            self.i += 1
            return value
        left = self._atom()
        self._skip()
        for op in ("==", "!="):
            if self._starts(op):
                self.i += len(op)
                right = self._atom()
                return left == right if op == "==" else left != right
        if isinstance(left, bool):
            return left
        raise _ExprError("expected comparison")

    def _atom(self):
        self._skip()
        if self.i < self.n and self.text[self.i] in ("'", '"'):
            quote = self.text[self.i]
            end = self.text.find(quote, self.i + 1)
            if end < 0:
                raise _ExprError("unterminated string")
            value = self.text[self.i + 1:end]
            self.i = end + 1
            return value
        for literal, value in (("true", True), ("false", False)):
            if self._starts(literal):
                after = self.i + len(literal)
                if after == self.n or not self.text[after].isalnum():
                    self.i = after
                    return value
        start = self.i
        while self.i < self.n and (self.text[self.i].isalnum() or self.text[self.i] in "._"):
            self.i += 1
        ident = self.text[start:self.i]
        if not ident or ident not in self.env:
            raise _ExprError("unknown %r" % ident)
        return self.env[ident]


def load_workflow(text):
    loaded = yaml.load(text, Loader=WorkflowLoader)
    if not isinstance(loaded, dict):
        raise AssertionError("workflow root is not a mapping")
    return loaded


def _runs(condition, event, ref):
    if condition is None:
        return True
    if condition is True:
        return True
    if condition is False:
        return False
    if not isinstance(condition, str):
        raise _ExprError("job if is %s" % type(condition).__name__)
    expr = condition.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2].strip()
    env = {"github.event_name": event, "github.ref": ref}
    return bool(_Parser(expr, env).parse())


def _trigger_names(on_value):
    if isinstance(on_value, str):
        return {on_value}
    if isinstance(on_value, list):
        return {item for item in on_value if isinstance(item, str)}
    if isinstance(on_value, dict):
        return {key for key in on_value if isinstance(key, str)}
    return set()


def _walk_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _walk_strings(key)
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_strings(item)


def _compact(value):
    if not isinstance(value, str):
        return ""
    return "".join(value.split())


def _local_action(step):
    uses = step.get("uses")
    return isinstance(uses, str) and (uses == "./" or uses.startswith("./"))


def _problems(text):
    problems = []
    for banned in ("pull_request_target", "github.event.pull_request", "github.event.inputs"):
        if banned in text:
            problems.append("%s trigger can reach uses: ./ or a Claude secret" % banned)
    doc = load_workflow(text)
    if "on" not in doc:
        problems.append("workflow trigger key is missing")
        triggers = set()
    else:
        triggers = _trigger_names(doc["on"])
    for name in sorted(triggers - ALLOWED_TRIGGERS):
        problems.append("%s trigger can reach uses: ./ or a Claude secret" % name)
    if "pull_request" in text and "pull_request" not in triggers and "pull_request_target" not in text:
        problems.append("pull_request trigger can reach uses: ./ or a Claude secret")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append("workflow has no jobs")
        return problems

    saw_local = False
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            problems.append("job %s is not a mapping" % job_name)
            continue
        steps = job.get("steps") or []
        secret_text = " ".join(_walk_strings(job))
        has_secret = "secrets.CLAUDE_API_KEY" in secret_text or "secrets.CLAUDE_CODE_OAUTH_TOKEN" in secret_text
        local_steps = [step for step in steps if isinstance(step, dict) and _local_action(step)]
        if not local_steps and not has_secret:
            continue
        if not local_steps:
            problems.append("Claude secret is outside the local action")
            continue
        saw_local = True
        try:
            trusted_ok = {ctx: _runs(job.get("if"), ctx[0], ctx[1]) for ctx in TRUSTED}
            untrusted_ok = {ctx: _runs(job.get("if"), ctx[0], ctx[1]) for ctx in UNTRUSTED}
        except _ExprError as exc:
            problems.append("job if is not a closed main-only guard (%s)" % exc)
            trusted_ok = {}
            untrusted_ok = {}
        for event, ref in TRUSTED:
            if trusted_ok and not trusted_ok[(event, ref)]:
                problems.append("trusted %s %s does not run the secret-bearing job" % (event, ref))
        for event, ref in UNTRUSTED:
            if untrusted_ok and untrusted_ok[(event, ref)]:
                problems.append("%s at %s can reach uses: ./ or a Claude secret" % (event, ref))

        checkouts = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("actions/checkout"):
                checkouts.append(step)
        if not checkouts:
            problems.append("actions/checkout is not pinned to a 40-hex SHA")
        for step in checkouts:
            uses = step.get("uses")
            pinned = isinstance(uses, str) and re.fullmatch(r"actions/checkout@[0-9a-f]{40}", uses)
            if not pinned or uses != CHECKOUT_USES:
                problems.append("actions/checkout is not pinned to a 40-hex SHA")
            with_block = step.get("with") or {}
            if "ref" in with_block:
                problems.append("actions/checkout ref can reach an untrusted commit")

        for step in local_steps:
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                problems.append("local action is missing its inputs")
                continue
            if with_block.get("comment-pr") is not False:
                problems.append("comment-pr is not false")
            if with_block.get("upload-results") is not False:
                problems.append("upload-results is not false")
            if _compact(with_block.get("claude-api-key")) != API_SECRET:
                problems.append("CLAUDE_API_KEY reference is missing")
            if _compact(with_block.get("claude-code-oauth-token")) != OAUTH_SECRET:
                problems.append("CLAUDE_CODE_OAUTH_TOKEN reference is missing")
    if not saw_local:
        problems.append("uses: ./ is missing")
        problems.append("CLAUDE_API_KEY reference is missing")
        problems.append("CLAUDE_CODE_OAUTH_TOKEN reference is missing")
    return problems


def assert_contract(text):
    problems = _problems(text)
    if problems:
        raise AssertionError("\n".join(problems))


def _dump(doc):
    return yaml.safe_dump(doc, sort_keys=False)


def _only_job(doc):
    return next(iter(doc["jobs"].values()))


def _local_step(doc):
    for step in _only_job(doc)["steps"]:
        if isinstance(step, dict) and step.get("uses") == "./":
            return step
    raise AssertionError("local action step is missing")


def mutate_pull_request_reaches(text):
    """Add both untrusted triggers and drop the job guard so they run the action."""
    doc = load_workflow(text)
    doc["on"]["pull_request"] = {}
    doc["on"]["pull_request_target"] = {}
    _only_job(doc).pop("if", None)
    return _dump(doc)


def mutate_ref_only_guard(text):
    """A ref check alone still runs pull_request_target, whose ref is the base."""
    doc = load_workflow(text)
    doc["on"]["pull_request_target"] = {}
    _only_job(doc)["if"] = "github.ref == 'refs/heads/main'"
    return _dump(doc)


def mutate_or_pull_request(text):
    """Precedence: an extra OR lets pull_request through a guard that still mentions main."""
    doc = load_workflow(text)
    doc["on"]["pull_request"] = {}
    _only_job(doc)["if"] = (
        "github.ref == 'refs/heads/main' && (github.event_name == 'push' || "
        "github.event_name == 'workflow_dispatch') || github.event_name == 'pull_request'"
    )
    return _dump(doc)


def mutate_comment_pr_true(text):
    doc = load_workflow(text)
    _local_step(doc)["with"]["comment-pr"] = True
    return _dump(doc)


def mutate_upload_results_true(text):
    doc = load_workflow(text)
    _local_step(doc)["with"]["upload-results"] = True
    return _dump(doc)


def mutate_comment_pr_string_false(text):
    doc = load_workflow(text)
    _local_step(doc)["with"]["comment-pr"] = "false"
    return _dump(doc)


def mutate_checkout_tag(text):
    doc = load_workflow(text)
    for step in _only_job(doc)["steps"]:
        if isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/checkout"):
            step["uses"] = "actions/checkout@v4"
    return _dump(doc)


def mutate_drop_api_key(text):
    doc = load_workflow(text)
    _local_step(doc)["with"].pop("claude-api-key")
    return _dump(doc)


def mutate_drop_oauth_token(text):
    doc = load_workflow(text)
    _local_step(doc)["with"].pop("claude-code-oauth-token")
    return _dump(doc)


def _reject(text, needle):
    with pytest.raises(AssertionError, match=needle):
        assert_contract(text)


def test_loader_does_not_change_default_yaml_bools():
    loaded = load_workflow("on:\n  push:\n")
    assert "on" in loaded
    assert yaml.safe_load("value: on\n")["value"] is True
    assert yaml.safe_load("value: false\n")["value"] is False


def test_fixed_workflow_passes():
    assert_contract(WORKFLOW.read_text())


def test_pull_request_trigger_mutant_is_rejected():
    text = WORKFLOW.read_text()
    rejected = mutate_pull_request_reaches(text)
    assert rejected != text
    _reject(rejected, r"pull_request at refs/pull/1/merge can reach")
    _reject(rejected, r"pull_request_target at refs/heads/main can reach")
    _reject(mutate_ref_only_guard(text), r"pull_request_target at refs/heads/main can reach")
    _reject(mutate_or_pull_request(text), r"pull_request at refs/pull/1/merge can reach")


def test_output_flag_mutants_are_rejected():
    text = WORKFLOW.read_text()
    _reject(mutate_comment_pr_true(text), "comment-pr is not false")
    _reject(mutate_upload_results_true(text), "upload-results is not false")
    _reject(mutate_comment_pr_string_false(text), "comment-pr is not false")


def test_checkout_pin_and_secret_mutants_are_rejected():
    text = WORKFLOW.read_text()
    _reject(mutate_checkout_tag(text), "actions/checkout is not pinned to a 40-hex SHA")
    _reject(mutate_drop_api_key(text), "CLAUDE_API_KEY reference is missing")
    _reject(mutate_drop_oauth_token(text), "CLAUDE_CODE_OAUTH_TOKEN reference is missing")
