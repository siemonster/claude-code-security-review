"""Pure, explicitly selected legacy r2 and compact r3 receipt evaluation.

The public entries take a cooperative JSON-value tree. The caller owns any
allocation before entry and must keep the input stable during evaluation.
The result records internal byte associations in MODEL_ONLY/NOT_ADMITTED
scope. The evaluator performs no transport, scheduling, or authentication.

G0 measures the outer JSON tree against 16 MiB, excluding the config subtree;
G1 separately bounds config to 64 KiB. Individual field/chunk ceilings are
additional refusal limits, not a promise that their Cartesian product fits:
legacy requests repeat common artifact hex; compact input retains it once.
Caller preallocation and Python allocation multipliers are outside that bound.
Legacy binding materializes every planned frame at once, bounded by max_chunks
times the smaller plan/config request-byte limit (at most 1 MiB per frame).
The conservative payload ceiling is about 128 MiB at the hard caps, without a
claim that all other input bounds permit reaching it. The 16 MiB input bound is
separate; neither figure bounds Python RSS, copies or allocator overhead.
Returned request, receipt and finding records may share caller-owned objects;
this API does not provide a detached snapshot. Consumers must use internal_status
and aggregate findings, not treat retained attempt evidence as an admitted result.

Under legacy r2, flags are retained declarations; byte-union checks do not recompute
ATOMIC placement or minimum stream overlap. Pinned source hashes identify the
injected formats and do not attest that either sibling produced the inputs.

Compact r3 adds exact derived flags, supplied ATOMIC placement and ordered
overlap checks. A compact-only fragment renderer retains no whole generated
frame, DATA or wire-body copy; length/hash facts and interval metadata are
separate. Generic input/artifact parsing and tree measurement still allocate
bounded input-derived values/encodings and are not covered by the frame scratch
bound or a Python RSS guarantee. Both APIs remain MODEL_ONLY/NOT_ADMITTED with
all qualification flags false; output storage format is distinct from trust.
"""

import hashlib
import json
import re


_PLANNER = "5433860d497a863f6e0c56a27e8b4f10131e1fd0"
_ACQUISITION = "a739fd5901eefd055e89337ff6092559f5fca4ed"
_VERSION = "2026-10-21"
_MAX_INTEGER = 9007199254740991
_FRAME_LIMIT = 1048576
_BLOB_LIMIT = 2097152
_HEX = re.compile(r"[0-9a-f]*")
_STRUCTURAL = re.compile(r'["{}\[\]]')
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_CURRENT = "repository pr base_tip merge_base comparison_base head workflow_run_id workflow_attempt"
_ROOTS = "repository pr base_tip merge_base comparison_base head"
_SPLIT = (
    "owner_config_hex acquisition_manifest_hex plan_hex prompt_hex policy_hex "
    "caller_dependency_assertion_hex framed_request_hex"
)
_COMMON = _SPLIT.rsplit(" ", 1)[0]
_BYTE_BLOCK = 1024
_TEXT_BLOCK = 256
_JSON_BLOCK = 128
_CAPS = dict(
    max_string_bytes=8388608, max_path_bytes=1024, max_integer_digits=16,
    max_integer_value=_MAX_INTEGER, max_pr=2147483647, max_workflow_attempt=1000000,
    max_request_bytes=4194304, max_response_bytes=1048576, max_artifact_bytes=8388608,
    max_json_depth=32, max_json_members=100000, max_chunks=128, max_ranges_per_chunk=256,
    max_findings_per_chunk=128, max_findings_per_run=4096, max_limitations=128,
    max_attempts_per_chunk=8, max_attempts_per_run=1024, max_input_tokens=1000000,
    max_output_tokens=1000000, max_context_tokens=2000000, max_run_reserved_tokens=1000000000,
    attempt_timeout_ns=_MAX_INTEGER, max_run_duration_ns=_MAX_INTEGER,
    max_run_cost_units=_MAX_INTEGER, max_parallel_chunks=128,
)
_ACQ_CAPS = dict(
    max_files=128, max_total_bytes=_BLOB_LIMIT, max_objects=2048, max_commits=128,
    max_pages=128, max_depth=32, max_structural_bytes=262144, max_tree_entries=8192,
    max_object_bytes=4194304,
)
_USAGE = "input_tokens cache_creation_input_tokens cache_read_input_tokens output_tokens"
_ELIGIBLE = "RETRY_ELIGIBLE_UNDER_INJECTED_POLICY"


class _Refusal(Exception):
    pass


def _need(condition, reason):
    if not condition:
        raise _Refusal(reason)


def _keys(value, required, reason, optional=""):
    required = set(required.split())
    _need(type(value) is dict and required <= value.keys() <= required | set(optional.split()), reason)


def _fixed(value, reason, **fields):
    for key, expected in fields.items():
        _need(type(value[key]) is type(expected) and value[key] == expected, reason)


def _int(value, reason, minimum=0, maximum=_MAX_INTEGER):
    _need(type(value) is int and minimum <= value <= maximum, reason)


def _text(value, reason, minimum=1, maximum=_CAPS["max_string_bytes"], streamed=False):
    _need(type(value) is str and len(value) <= maximum, reason)
    try:
        if streamed:
            size = sum(len(part) for part in _utf8_parts(value))
        else:
            size = len(value.encode("utf-8"))
    except UnicodeError:
        raise _Refusal(reason) from None
    _need(minimum <= size <= maximum, reason)


def _hex(value, reason, length=None):
    _need(type(value) is str and len(value) % 2 == 0 and
          (length is None or len(value) == length) and _HEX.fullmatch(value), reason)


def _array(value, reason, minimum=0, maximum=4096):
    _need(type(value) is list and minimum <= len(value) <= maximum, reason)


def _choice(value, choices, reason):
    _need(type(value) is str and value in choices, reason)


def _path(value, maximum, reason):
    _text(value, reason, maximum=maximum)
    _need("\\" not in value and not any(ord(char) < 32 for char in value)
          and all(part not in ("", ".", "..") for part in value.split("/")), reason)


def _canonical(value, ascii_only=False):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only, allow_nan=False
    ).encode("utf-8")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _named_digest(label, **fields):
    return _digest(label + _canonical(fields))


def _frame(raw):
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def _measure(value, reason, *, byte_limit, depth_limit=32, member_limit=100000,
             integer_limit=_MAX_INTEGER, digits=16, omit_config=False, string_limit=None,
             streamed_strings=False):
    """Bound the JSON value tree before canonical serialization or reliance."""
    size = members = 0
    maximum_text = min(byte_limit, _CAPS["max_string_bytes"])
    if string_limit is not None:
        maximum_text = min(maximum_text, string_limit)
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        kind = type(item)
        if kind is dict or kind is list:
            _need(depth <= depth_limit, reason)
            members += len(item)
            _need(members <= member_limit and (kind is dict or len(item) <= 4096), reason)
            size += 2 + max(0, len(item) - 1)
            if kind is list:
                pending.extend((child, depth + 1) for child in item)
            else:
                size += len(item)
                for key, child in item.items():
                    _need(type(key) is str, reason)
                    pending.append((key, depth + 1))
                    if omit_config and depth == 1 and key == "config":
                        continue
                    pending.append((child, depth + 1))
        elif kind is str:
            _text(item, reason, minimum=0, maximum=maximum_text, streamed=streamed_strings)
            if streamed_strings:
                size += sum(len(part) for part in _canonical_parts(item))
            else:
                size += len(json.encoder.encode_basestring(item).encode("utf-8"))
        elif kind is int:
            _int(item, reason, maximum=integer_limit)
            decimal = str(item)
            _need(len(decimal) <= digits, reason)
            size += len(decimal)
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise _Refusal(reason)
        _need(size <= byte_limit, reason)


def _measure_configured(value, limits, byte_limit, reason, string_limit=None, streamed_strings=False):
    _measure(value, reason, byte_limit=byte_limit, depth_limit=limits["max_json_depth"],
             member_limit=limits["max_json_members"], integer_limit=limits["max_integer_value"],
             digits=limits["max_integer_digits"], string_limit=string_limit, streamed_strings=streamed_strings)


def _parse(raw, limits, reason, string_limit=None):
    """Read one bounded JSON value without coercing duplicate keys or numbers."""
    def pairs(values):
        result = dict(values)
        _need(len(result) == len(values), reason)
        return result

    def integer(token):
        _need(len(token.lstrip("-")) <= limits["max_integer_digits"], reason)
        return int(token)

    def reject_number(_token):
        raise _Refusal(reason)

    try:
        text = raw.decode("utf-8")
        # Preflight nesting before json.loads recurses. scanstring skips
        # escaped quotes so delimiters in text do not affect depth.
        position = depth = 0
        while True:
            match = _STRUCTURAL.search(text, position)
            if match is None:
                break
            position = match.end()
            token = match.group()
            if token == '"':
                _, position = json.decoder.scanstring(text, position)
            elif token in "[{":
                depth += 1
                _need(depth <= limits["max_json_depth"], reason)
            else:
                depth -= 1
                _need(depth >= 0, reason)
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=reject_number, parse_constant=reject_number)
        _measure_configured(value, limits, 16777216, reason, string_limit)
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise _Refusal(reason) from None


def _identity_shape(identity, reason, full=True):
    _keys(identity, _CURRENT if full else _ROOTS, reason)
    for key in ("base_tip", "merge_base", "comparison_base", "head"):
        _hex(identity[key], reason, 40)
    _text(identity["repository"], reason)
    _int(identity["pr"], reason, 1)
    if full:
        _text(identity["workflow_run_id"], reason)
        _int(identity["workflow_attempt"], reason, 1)


def _wire_shape(wire, reason, streamed_strings=False):
    _keys(wire, "model max_tokens system messages stream", reason)
    _fixed(wire, reason, stream=False)
    _text(wire["model"], reason, streamed=streamed_strings)
    _text(wire["system"], reason, streamed=streamed_strings)
    _int(wire["max_tokens"], reason, 1)
    _array(wire["messages"], reason, 1, 1)
    message = wire["messages"][0]
    _keys(message, "role content", reason)
    _fixed(message, reason, role="user")
    _array(message["content"], reason, 1, 1)
    text = message["content"][0]
    _keys(text, "type text", reason)
    _fixed(text, reason, type="text")
    _text(text["text"], reason, streamed=streamed_strings)


def _request_shape(request, reason, compact=False):
    _keys(request, "binding ranges framed_request_sha256 framed_request_bytes chunk_challenge "
          "stable_request_id method url public_headers body_hex body_bytes body_sha256 wire_request "
          "split_artifacts declared_input_token_bound declared_cost_bound_units", reason)
    binding = request["binding"]
    hashes = (
        "acquisition_manifest_sha256 caller_dependency_assertion_sha256 config_sha256 "
        "plan_sha256 policy_sha256 prompt_sha256 run_challenge"
    )
    _keys(binding, _CURRENT + " " + hashes + " acquisition_closure acquisition_source_sha "
          "chunk_count chunk_id plan_dependency_assertion plan_schema planner_source_sha "
          "roots_authenticated schema3_identity_model", reason)
    _identity_shape({key: binding[key] for key in _CURRENT.split()}, reason)
    _fixed(binding, reason, acquisition_closure="NOT_EVALUATED", acquisition_source_sha=_ACQUISITION,
           planner_source_sha=_PLANNER, roots_authenticated=False, plan_schema=3,
           plan_dependency_assertion="CALLER_ASSERTED_UNVERIFIED")
    for key in hashes.split():
        _hex(binding[key], reason, 64)
    _int(binding["chunk_count"], reason, 1)
    _int(binding["chunk_id"], reason)
    _text(binding["schema3_identity_model"], reason)
    _fixed(request, reason, method="POST", url="https://api.anthropic.com/v1/messages")
    _keys(request["public_headers"], "anthropic-version content-type", reason)
    _fixed(request["public_headers"], reason,
           **{"anthropic-version": _VERSION, "content-type": "application/json"})
    for key in ("body_sha256", "stable_request_id", "chunk_challenge", "framed_request_sha256"):
        _hex(request[key], reason, 64)
    _hex(request["body_hex"], reason)
    for key in ("body_bytes", "framed_request_bytes", "declared_input_token_bound"):
        _int(request[key], reason, 1)
    _int(request["declared_cost_bound_units"], reason)
    _keys(request["split_artifacts"], "framed_request_hex" if compact else _SPLIT, reason)
    for value in request["split_artifacts"].values():
        _hex(value, reason)
    _wire_shape(request["wire_request"], reason, compact)
    _array(request["ranges"], reason)
    for row in request["ranges"]:
        _keys(row, "blob_sha256 end oid old_path path side start", reason)
        _hex(row["blob_sha256"], reason, 64)
        _hex(row["oid"], reason, 40)
        _choice(row["side"], ("base", "head"), reason)
        _text(row["path"], reason)
        if row["old_path"] is not None:
            _text(row["old_path"], reason)
        _int(row["start"], reason)
        _int(row["end"], reason)


def _receipt_shape(receipt, reason):
    _keys(receipt, "attempt_id body_sha256 captured_prefix_sha256 chunk_id content_encoding "
          "content_type dispatch_state finished_monotonic_ns http_framing_complete http_status "
          "provider_retry_index response_bytes response_capture response_hex response_overflow_observed "
          "response_retry_after_raw response_sha256 retry_not_before_monotonic_ns stable_request_id "
          "started_monotonic_ns transport_state workflow_attempt", reason)
    for key in ("attempt_id", "body_sha256", "stable_request_id"):
        _hex(receipt[key], reason, 64)
    for key in ("captured_prefix_sha256", "response_sha256"):
        if receipt[key] is not None:
            _hex(receipt[key], reason, 64)
    if receipt["response_hex"] is not None:
        _hex(receipt["response_hex"], reason)
    for key in ("content_encoding", "content_type", "response_retry_after_raw"):
        if receipt[key] is not None:
            _text(receipt[key], reason)
    for key in ("chunk_id", "provider_retry_index", "response_bytes", "started_monotonic_ns",
                "finished_monotonic_ns"):
        _int(receipt[key], reason)
    _int(receipt["workflow_attempt"], reason, 1)
    if receipt["http_status"] is not None:
        _int(receipt["http_status"], reason, 100, 599)
    if receipt["retry_not_before_monotonic_ns"] is not None:
        _int(receipt["retry_not_before_monotonic_ns"], reason)
    for key in ("http_framing_complete", "response_overflow_observed"):
        _need(type(receipt[key]) is bool, reason)
    _choice(receipt["dispatch_state"], ("NOT_SENT", "SENT", "UNKNOWN"), reason)
    _choice(receipt["transport_state"], ("COMPLETE", "ERROR", "TIMEOUT", "CANCELLED", "AMBIGUOUS"), reason)
    _choice(receipt["response_capture"], ("COMPLETE", "PREFIX_ONLY", "NOT_OBSERVED"), reason)


def _budget_shape(budget, reason):
    integers = ("attempts_dispatched deadline_monotonic_ns reserved_attempts reserved_cost_units "
                "reserved_input_tokens reserved_output_tokens run_started_monotonic_ns unresolved_attempts")
    _keys(budget, integers + " config_sha256 price_accounting_ref provider_reported_input_total "
          "provider_reported_output_total reservation_state token_accounting_ref", reason)
    for key in integers.split():
        _int(budget[key], reason)
    for key in ("provider_reported_input_total", "provider_reported_output_total"):
        if budget[key] is not None:
            _int(budget[key], reason)
    _hex(budget["config_sha256"], reason, 64)
    _text(budget["price_accounting_ref"], reason)
    _text(budget["token_accounting_ref"], reason)
    _choice(budget["reservation_state"], ("UNQUALIFIED", "RESERVED", "EXHAUSTED"), reason)


def _raw_shape(bundle, compact=False):
    reason = "INPUT_SHAPE"
    _keys(bundle, "attempts budget_receipt current_identity requests"
          + (" bundle_format common_artifacts" if compact else ""), reason, "config")
    _measure(bundle, reason, byte_limit=16777216, omit_config=True, streamed_strings=compact)
    if compact:
        _fixed(bundle, reason, bundle_format=2)
        _keys(bundle["common_artifacts"], _COMMON, reason)
        for value in bundle["common_artifacts"].values():
            _hex(value, reason)
    _identity_shape(bundle["current_identity"], reason)
    _array(bundle["requests"], reason)
    _array(bundle["attempts"], reason)
    for request in bundle["requests"]:
        _request_shape(request, reason, compact)
    for receipt in bundle["attempts"]:
        _receipt_shape(receipt, reason)
    _budget_shape(bundle["budget_receipt"], reason)


def _configuration(config):
    reason = "CONFIG_UNQUALIFIED"
    names = (
        "api_model_id closure_policy_ref cost_unit price_accounting_ref "
        "provider_account_authorization_ref retention_policy_ref retry_policy_ref "
        "token_accounting_ref transport_version_ref"
    )
    _keys(config, names + " api_version approved_inference_geos approved_reported_models "
          "approved_service_tiers approved_speeds display_model_intent evidence_mode limits "
          "production_ready retry_policy", reason)
    _measure(config, reason, byte_limit=65536)
    _fixed(config, reason, api_version=_VERSION, display_model_intent="Fable 5.2",
           evidence_mode="INJECTED_SYNTHETIC", production_ready=False)
    limits = config["limits"]
    _keys(limits, " ".join(_CAPS), reason)
    for key, ceiling in _CAPS.items():
        _int(limits[key], reason, 1, ceiling)
    _need(limits["max_artifact_bytes"] >= max(limits["max_request_bytes"], limits["max_response_bytes"]), reason)
    for key in names.split():
        _text(config[key], reason, maximum=limits["max_string_bytes"])
    for key in ("approved_inference_geos", "approved_reported_models", "approved_service_tiers", "approved_speeds"):
        values = config[key]
        _array(values, reason, 1, limits["max_json_members"])
        for value in values:
            _text(value, reason, maximum=limits["max_string_bytes"])
        _need(len(set(values)) == len(values), reason)
    _need(config["api_model_id"] in config["approved_reported_models"]
          and set(config["approved_service_tiers"]) <= {"standard", "priority"}
          and set(config["approved_speeds"]) <= {"standard", "fast"}, reason)
    retry = config["retry_policy"]
    _keys(retry, "allow_ambiguous_dispatch allowed_http_statuses backoff_ns_by_retry max_inflight_per_chunk model_fallback", reason)
    _fixed(retry, reason, allow_ambiguous_dispatch=False, max_inflight_per_chunk=1, model_fallback=False)
    _array(retry["allowed_http_statuses"], reason, maximum=limits["max_json_members"])
    for status in retry["allowed_http_statuses"]:
        _need(type(status) is int and status in (429, 500, 502, 503, 504, 529), reason)
    backoff_count = limits["max_attempts_per_chunk"] - 1
    _array(retry["backoff_ns_by_retry"], reason, backoff_count, backoff_count)
    for delay in retry["backoff_ns_by_retry"]:
        _int(delay, reason, maximum=min(limits["max_run_duration_ns"], limits["max_integer_value"]))
        _need(len(str(delay)) <= limits["max_integer_digits"], reason)
    return limits


def _binary(hex_value, maximum, reason):
    _need(len(hex_value) <= 2 * maximum, reason)
    return bytes.fromhex(hex_value)


def _artifact(raw, limits, reason, ascii_only=False):
    value = _parse(raw, limits, reason, limits["max_string_bytes"])
    _need(_canonical(value, ascii_only) == raw, reason)
    return value


def _acquisition(value, limits, reason):
    _keys(value, "schema scope qualification acquisition_authenticated gate_wired identity trust "
          "object_format ancestry pages closure unchanged_context declared_changed_files files "
          "blobs limits raw_bytes logical_bytes verified_objects", reason)
    _fixed(value, reason, schema=1, scope="MODEL_ONLY", qualification="NOT_ADMITTED",
           acquisition_authenticated=False, gate_wired=False, object_format="sha1",
           trust="CALLER_SUPPLIED_UNAUTHENTICATED_UNFRESH", closure="NOT_EVALUATED",
           pages="SELF_CONSISTENT_AND_EQUAL_TO_TREE_SET", unchanged_context="NOT_ACQUIRED")
    identity = value["identity"]
    _identity_shape(identity, reason, full=False)
    _need(len(identity["repository"]) <= 256 and _REPOSITORY.fullmatch(identity["repository"])
          and all(part not in (".", "..") for part in identity["repository"].split("/"))
          and identity["pr"] <= limits["max_pr"], reason)
    _text(identity["repository"], reason, maximum=limits["max_path_bytes"])
    _need(identity["base_tip"] == identity["comparison_base"] == identity["merge_base"]
          and identity["head"] != identity["base_tip"], reason)
    _keys(value["limits"], " ".join(_ACQ_CAPS), reason)
    for key, cap in _ACQ_CAPS.items():
        _int(value["limits"][key], reason, 1, cap)
    ancestry, verified = value["ancestry"], value["verified_objects"]
    _array(ancestry, reason, 2, value["limits"]["max_commits"])
    _array(verified, reason, 1, value["limits"]["max_objects"])
    for oid in ancestry + verified:
        _hex(oid, reason, 40)
    _need(ancestry[0] == identity["head"] and ancestry[-1] == identity["base_tip"]
          and len(ancestry) == len(set(ancestry)) and verified == sorted(set(verified))
          and set(ancestry) <= set(verified), reason)
    _int(value["declared_changed_files"], reason, 1, value["limits"]["max_files"])
    for key in ("raw_bytes", "logical_bytes"):
        _int(value[key], reason, maximum=value["limits"]["max_total_bytes"])


def _files_and_blobs(files, blobs, budget, limits, reason):
    _array(files, reason, 1, budget["max_files"])
    _need(type(blobs) is dict and len(blobs) <= 2 * budget["max_files"], reason)
    raw_blobs = {}
    raw_size = 0
    for oid, encoded in blobs.items():
        _hex(oid, reason, 40)
        _hex(encoded, reason)
        raw = _binary(encoded, budget["max_total_bytes"] - raw_size, reason)
        raw_size += len(raw)
        _need(b"\0" not in raw, reason)
        try:
            raw.decode("utf-8")
        except UnicodeError:
            raise _Refusal(reason) from None
        _need(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid, reason)
        raw_blobs[oid] = raw
    rows, used, old_paths = {}, set(), set()
    logical_size = 0
    for row in files:
        _keys(row, "path old_path status base head", reason)
        path, status, old = row["path"], row["status"], row["old_path"]
        _path(path, limits["max_path_bytes"], reason)
        _choice(status, ("A", "D", "M", "R"), reason)
        _need(path not in rows, reason)
        rows[path] = row
        if status == "R":
            _path(old, limits["max_path_bytes"], reason)
            _need(old != path and old not in old_paths, reason)
            old_paths.add(old)
        else:
            _need(old is None, reason)
        for side, absent in (("base", "A"), ("head", "D")):
            desc = row[side]
            if status == absent:
                _need(desc is None, reason)
                continue
            _keys(desc, "oid bytes sha256 mode", reason)
            _hex(desc["oid"], reason, 40)
            _hex(desc["sha256"], reason, 64)
            _choice(desc["mode"], ("100644", "100755"), reason)
            _int(desc["bytes"], reason, maximum=budget["max_total_bytes"] - logical_size)
            raw = raw_blobs.get(desc["oid"])
            _need(raw is not None and len(raw) == desc["bytes"] and _digest(raw) == desc["sha256"], reason)
            logical_size += len(raw)
            used.add(desc["oid"])
    _need(list(rows) == sorted(rows) and not old_paths.intersection(rows)
          and used == raw_blobs.keys(), reason)
    return rows, raw_blobs, raw_size, logical_size


def _caller_groups(assertion, dependencies, paths, reason):
    _keys(assertion, "scope source claimed_status groups acquisition_closure closure_sufficiency", reason)
    _fixed(assertion, reason, scope="INJECTED_SYNTHETIC", source="CALLER_ASSERTED_UNVERIFIED",
           claimed_status="SUPPLIED_COMPLETE", acquisition_closure="NOT_EVALUATED",
           closure_sufficiency="UNVERIFIED")
    _keys(dependencies, "status groups", reason)
    _fixed(dependencies, reason, status="SUPPLIED_COMPLETE")
    groups = assertion["groups"]
    _array(groups, reason, 1, len(paths))
    assigned = []
    for group in groups:
        _keys(group, "kind paths", reason)
        _choice(group["kind"], ("ATOMIC", "STREAM"), reason)
        members = group["paths"]
        _array(members, reason, 1, 1 if group["kind"] == "STREAM" else len(paths))
        for path in members:
            _need(type(path) is str and path in paths, reason)
        _need(members == sorted(members), reason)
        assigned.extend(members)
        _need(len(assigned) <= len(paths), reason)
    _need(sorted(assigned) == sorted(paths)
          and [g["paths"] for g in groups] == sorted(g["paths"] for g in groups)
          and _canonical(groups) == _canonical(dependencies["groups"]), reason)


def _plan_metadata(plan, acquisition, assertion, count, limits, reason):
    _keys(plan, "schema scope qualification gate_wired inventory blobs budget chunks flagged_paths plan_sha256", reason)
    _fixed(plan, reason, schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False)
    _hex(plan["plan_sha256"], reason, 64)
    _need(plan["plan_sha256"] == _digest(_canonical(
        {key: value for key, value in plan.items() if key != "plan_sha256"}, True)), reason)
    budget = plan["budget"]
    caps = dict(max_request_bytes=_FRAME_LIMIT, max_chunks=128, overlap_bytes=_FRAME_LIMIT,
                max_files=128, max_total_bytes=_BLOB_LIMIT)
    _keys(budget, " ".join(caps), reason)
    for key, cap in caps.items():
        _int(budget[key], reason, 1, cap)
    _need(budget["overlap_bytes"] < budget["max_request_bytes"], reason)
    inventory = plan["inventory"]
    _keys(inventory, "schema identity compare_file_count files dependencies", reason)
    _fixed(inventory, reason, schema=3)
    identity = inventory["identity"]
    _keys(identity, "repository pr base head planner_sha prompt_sha256 policy_sha256 model run_id attempt challenge", reason)
    roots = acquisition["identity"]
    _fixed(identity, reason, repository=roots["repository"], pr=roots["pr"], base=roots["comparison_base"],
           head=roots["head"], planner_sha=_PLANNER)
    for key in ("prompt_sha256", "policy_sha256", "challenge"):
        _hex(identity[key], reason, 64)
    for key in ("model", "run_id"):
        _text(identity[key], reason, maximum=min(limits["max_string_bytes"], 1024))
        _need(not any(ord(c) < 32 for c in identity[key]), reason)
    _int(identity["attempt"], reason, 1, limits["max_workflow_attempt"])
    _need(_canonical(inventory["files"]) == _canonical(acquisition["files"])
          and _canonical(plan["blobs"]) == _canonical(acquisition["blobs"]), reason)
    files, raw_blobs, raw_size, logical_size = _files_and_blobs(
        inventory["files"], plan["blobs"], budget, limits, reason,
    )
    _fixed(inventory, reason, compare_file_count=len(files))
    _fixed(acquisition, reason, declared_changed_files=len(files), raw_bytes=raw_size, logical_bytes=logical_size)
    _need(set(raw_blobs) <= set(acquisition["verified_objects"]), reason)
    _caller_groups(assertion, inventory["dependencies"], files, reason)
    _array(plan["chunks"], reason, count, count)
    _need(count <= budget["max_chunks"], reason)
    flags = {}
    _array(plan["flagged_paths"], reason, maximum=len(files))
    for row in plan["flagged_paths"]:
        _keys(row, "path old_path flags", reason)
        path = row["path"]
        _need(type(path) is str and path in files and path not in flags, reason)
        _fixed(row, reason, old_path=files[path]["old_path"])
        _array(row["flags"], reason, 1, 4)
        for flag in row["flags"]:
            _choice(flag, ("WORKFLOW", "DELETION", "RENAME", "MODE_CHANGE"), reason)
        _need(len(set(row["flags"])) == len(row["flags"]), reason)
        flags[path] = row["flags"]
    _need(list(flags) == sorted(flags), reason)
    return identity, files, raw_blobs, flags


def _plan_frames(plan, identity, files, raw_blobs, flags, limits, reason):
    """Bind every supplied slice and the complete byte union of each side."""
    coverage = {(path, side): [] for path, row in files.items()
                for side in ("base", "head") if row[side] is not None}
    intervals = set()
    frame_limit = min(plan["budget"]["max_request_bytes"], limits["max_request_bytes"])
    frames = []
    for index, chunk in enumerate(plan["chunks"]):
        _keys(chunk, "id items request_bytes request_sha256", reason)
        _fixed(chunk, reason, id=index)
        _array(chunk["items"], reason, 1, limits["max_ranges_per_chunk"])
        envelope = dict(schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                        identity=identity, chunk_id=index, item_count=len(chunk["items"]))
        parts = [b"C003-INERT-BYTE-PLAN-3\n", _frame(_canonical(envelope, True))]
        size = sum(map(len, parts))
        ranges = []
        for item in chunk["items"]:
            _keys(item, "path side oid start end", reason)
            path, side = item["path"], item["side"]
            _need(type(path) is str and type(side) is str and (path, side) in coverage, reason)
            row = files[path]
            desc = row[side]
            raw = raw_blobs[desc["oid"]]
            _fixed(item, reason, oid=desc["oid"])
            start, end = item["start"], item["end"]
            _int(start, reason, maximum=len(raw))
            _int(end, reason, minimum=start, maximum=len(raw))
            interval = (path, side, start, end)
            _need(interval not in intervals and (start < end or not raw), reason)
            _need(all(point == len(raw) or raw[point] & 192 != 128 for point in (start, end)), reason)
            intervals.add(interval)
            coverage[(path, side)].append((start, end))
            header = dict(item, old_path=row["old_path"], status=row["status"], mode=desc["mode"],
                          size=desc["bytes"], sha256=desc["sha256"], disposition="REVIEWED_RAW",
                          flags=flags.get(path, []))
            header_bytes = _frame(_canonical(header, True))
            payload_size = end - start
            size += len(header_bytes) + len(str(payload_size)) + 2 + payload_size
            _need(size <= frame_limit, reason)
            parts.extend((header_bytes, _frame(raw[start:end])))
            ranges.append(dict(item, old_path=row["old_path"], blob_sha256=desc["sha256"]))
        frame = b"".join(parts)
        _fixed(chunk, reason, request_bytes=len(frame), request_sha256=_digest(frame))
        frames.append((frame, ranges))
    for (path, side), spans in coverage.items():
        end = 0
        for start, stop in sorted(spans):
            _need(start <= end, reason)
            end = max(end, stop)
        _need(bool(spans) and end == files[path][side]["bytes"], reason)
    return frames


def _artifact_metadata(split, config, count, limits, reason):
    cap = limits["max_artifact_bytes"]
    common = {key: _binary(value, cap, reason) for key, value in split.items()
              if key != "framed_request_hex"}
    _need(common["owner_config_hex"] == _canonical(config), reason)
    acquisition = _artifact(common["acquisition_manifest_hex"], limits, reason)
    plan = _artifact(common["plan_hex"], limits, reason, ascii_only=True)
    assertion = _artifact(common["caller_dependency_assertion_hex"], limits, reason)
    _acquisition(acquisition, limits, reason)
    identity, files, raw_blobs, flags = _plan_metadata(plan, acquisition, assertion, count, limits, reason)
    return common, acquisition, plan, identity, files, raw_blobs, flags


def _artifact_binding(common, acquisition, plan, identity, config, count, limits, reason):
    _need(len(common["prompt_hex"]) + len(common["policy_hex"]) + 1 <= limits["max_request_bytes"], reason)
    try:
        system = (common["prompt_hex"] + b"\n" + common["policy_hex"]).decode("utf-8")
    except UnicodeError:
        raise _Refusal(reason) from None
    _need(identity["prompt_sha256"] == _digest(common["prompt_hex"])
          and identity["policy_sha256"] == _digest(common["policy_hex"])
          and identity["model"] == config["api_model_id"], reason)
    binding_fields = dict(
        acquisition["identity"], workflow_run_id=identity["run_id"], workflow_attempt=identity["attempt"],
        run_challenge=identity["challenge"], plan_sha256=plan["plan_sha256"],
        prompt_sha256=identity["prompt_sha256"], policy_sha256=identity["policy_sha256"],
        schema3_identity_model=identity["model"], chunk_count=count,
        acquisition_manifest_sha256=_digest(common["acquisition_manifest_hex"]),
        config_sha256=_digest(common["owner_config_hex"]),
        caller_dependency_assertion_sha256=_digest(common["caller_dependency_assertion_hex"]),
    )
    return binding_fields, system



def _read_request_artifacts(split, config, count, limits, reason):
    common, acquisition, plan, identity, files, raw_blobs, flags = _artifact_metadata(
        split, config, count, limits, reason,
    )
    frames = _plan_frames(plan, identity, files, raw_blobs, flags, limits, reason)
    binding_fields, system = _artifact_binding(
        common, acquisition, plan, identity, config, count, limits, reason,
    )
    return binding_fields, frames, system


def _bound_requests(requests, config, limits):
    reason = "BINDING"
    count = len(requests)
    _need(1 <= count <= min(limits["max_chunks"], 128), reason)
    first_split = requests[0]["split_artifacts"]
    binding_fields, frames, system = _read_request_artifacts(first_split, config, count, limits, reason)
    for request in requests:
        split = request["split_artifacts"]
        _need(all(split[key] == first_split[key] for key in split if key != "framed_request_hex"), reason)
        binding = request["binding"]
        _fixed(binding, reason, **binding_fields)
        index = binding["chunk_id"]
        _need(index < count, reason)
        frame, ranges = frames[index]
        _need(request["ranges"] == ranges, reason)
        _need(_binary(split["framed_request_hex"], min(limits["max_artifact_bytes"], _FRAME_LIMIT), reason)
              == frame, reason)
        _fixed(request, reason, framed_request_bytes=len(frame), framed_request_sha256=_digest(frame))
        challenge = _named_digest(
            b"C003-CHALLENGE-1\n", binding=binding, ranges=ranges, framed_request_sha256=_digest(frame),
        )
        _fixed(request, reason, chunk_challenge=challenge)
        wire = request["wire_request"]
        _measure_configured(wire, limits, limits["max_request_bytes"], reason)
        _fixed(wire, reason, model=config["api_model_id"], system=system)
        data = (b"C003-DIRECT-API-DATA-1\n"
                + _frame(_canonical(dict(binding=binding, ranges=ranges, chunk_challenge=challenge)))
                + _frame(frame))
        _need(data == wire["messages"][0]["content"][0]["text"].encode("utf-8"), reason)
        body = _canonical(wire)
        _need(_binary(request["body_hex"], limits["max_request_bytes"], reason) == body, reason)
        _fixed(request, reason, body_bytes=len(body), body_sha256=_digest(body))
        _fixed(request, reason, stable_request_id=_named_digest(
            b"C003-REQUEST-1\n", binding=binding, chunk_challenge=challenge, body_sha256=_digest(body),
            public_headers=request["public_headers"],
        ))


def _canonical_parts(value, ascii_only=False, string_block=_JSON_BLOCK):
    """Canonical JSON without materializing a whole DATA string or wire body.

    Only already checked builtin trees reach this encoder. A string block is at
    most 128 characters (<=1538 encoded bytes even for ASCII-escaped astral text).
    """
    if type(value) is str:
        yield b'"'
        for start in range(0, len(value), string_block):
            raw = _canonical(value[start:start + string_block], ascii_only)
            yield memoryview(raw)[1:-1]
        yield b'"'
    elif type(value) is dict:
        yield b"{"
        for index, key in enumerate(sorted(value)):
            if index:
                yield b","
            yield from _canonical_parts(key, ascii_only, string_block)
            yield b":"
            yield from _canonical_parts(value[key], ascii_only, string_block)
        yield b"}"
    elif type(value) is list:
        yield b"["
        for index, item in enumerate(value):
            if index:
                yield b","
            yield from _canonical_parts(item, ascii_only, string_block)
        yield b"]"
    else:
        _need(type(value) in (int, bool, type(None)), "BINDING")
        yield _canonical(value, ascii_only)


def _json_frame_parts(value, ascii_only=False, maximum=None):
    # Budget the counting pass too. A rejected small-Q frame must not first
    # encode an entire large header. ASCII escaping costs <=12 bytes/character.
    block = _JSON_BLOCK if maximum is None else min(_JSON_BLOCK, max(1, maximum // 12))
    size = 0
    for part in _canonical_parts(value, ascii_only, block):
        size += len(part)
        if maximum is not None:
            _need(size <= maximum, "BINDING")
    if maximum is not None:
        _need(size + len(str(size)) + 2 <= maximum, "BINDING")
    yield str(size).encode("ascii") + b":"
    yield from _canonical_parts(value, ascii_only, block)
    yield b","


def _compact_frame_parts(identity, index, chunk, files, raw_blobs, flags, maximum):
    """No frame buffer, payload copies, all-frame list or rendered-frame cache."""
    used = 0

    def emit(parts):
        nonlocal used
        for part in parts:
            _need(used + len(part) <= maximum, "BINDING")
            used += len(part)
            yield part

    yield from emit((b"C003-INERT-BYTE-PLAN-3\n",))
    envelope = dict(schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                    identity=identity, chunk_id=index, item_count=len(chunk["items"]))
    yield from emit(_json_frame_parts(envelope, True, maximum - used))
    for item in chunk["items"]:
        row = files[item["path"]]
        desc = row[item["side"]]
        header = dict(item, old_path=row["old_path"], status=row["status"], mode=desc["mode"],
                      size=desc["bytes"], sha256=desc["sha256"], disposition="REVIEWED_RAW",
                      flags=flags.get(item["path"], []))
        yield from emit(_json_frame_parts(header, True, maximum - used))
        size = item["end"] - item["start"]
        _need(used + len(str(size)) + 2 + size <= maximum, "BINDING")
        yield from emit((str(size).encode("ascii") + b":",))
        view = memoryview(raw_blobs[item["oid"]])
        for start in range(item["start"], item["end"], _BYTE_BLOCK):
            yield from emit((view[start:min(start + _BYTE_BLOCK, item["end"])],))
        yield from emit((b",",))


def _compact_policy(plan, files, raw_blobs, flags, limits, reason):
    derived = {}
    for path, row in files.items():
        values = []
        if path.startswith(".github/") or (row["old_path"] or "").startswith(".github/"):
            values.append("WORKFLOW")
        if row["status"] in ("D", "R"):
            values.append({"D": "DELETION", "R": "RENAME"}[row["status"]])
        if row["base"] is not None and row["head"] is not None and row["base"]["mode"] != row["head"]["mode"]:
            values.append("MODE_CHANGE")
        if values:
            derived[path] = values
    _need(flags == derived, reason)
    coverage = {(path, side): [] for path, row in files.items()
                for side in ("base", "head") if row[side] is not None}
    atomic, group_for_path = [], {}
    for group in plan["inventory"]["dependencies"]["groups"]:
        if group["kind"] == "ATOMIC":
            number = len(atomic)
            atomic.append(set())
            for path in group["paths"]:
                group_for_path[path] = number
    seen, projected = set(), []
    for index, chunk in enumerate(plan["chunks"]):
        _keys(chunk, "id items request_bytes request_sha256", reason)
        _fixed(chunk, reason, id=index)
        _array(chunk["items"], reason, 1, limits["max_ranges_per_chunk"])
        ranges = []
        projected.append(ranges)
        for item in chunk["items"]:
            _keys(item, "path side oid start end", reason)
            path, side = item["path"], item["side"]
            _need(type(path) is str and type(side) is str and (path, side) in coverage, reason)
            desc = files[path][side]
            raw = raw_blobs[desc["oid"]]
            _fixed(item, reason, oid=desc["oid"])
            start, end = item["start"], item["end"]
            _int(start, reason, maximum=len(raw))
            _int(end, reason, minimum=start, maximum=len(raw))
            marker = (path, side, start, end)
            _need(marker not in seen and (start < end or not raw), reason)
            _need(all(point == len(raw) or raw[point] & 192 != 128 for point in (start, end)), reason)
            seen.add(marker)
            ranges.append(dict(item, old_path=files[path]["old_path"], blob_sha256=desc["sha256"]))
            coverage[(path, side)].append((start, end))
            if path in group_for_path:
                atomic[group_for_path[path]].add(index)
    for (path, side), spans in coverage.items():
        size = files[path][side]["bytes"]
        if size == 0:
            _need(spans == [(0, 0)], reason)
            continue
        _need(bool(spans), reason)
        covered = 0
        for index, (start, end) in enumerate(sorted(spans)):
            _need(start <= covered, reason)
            if index:
                _need(covered - start >= plan["budget"]["overlap_bytes"] and end > covered, reason)
            covered = end
        _need(covered == size, reason)
    _need(all(len(locations) == 1 for locations in atomic), reason)
    return derived, projected


def _hex_checked_parts(parts, encoded, maximum, reason):
    """Exact canonical-hex equality is byte equality after G0's hex checks.

    No retained-frame/body decode. Each compared string is <=3076 bytes for JSON
    or <=2048 for a payload block; no full frame/body or DATA is copied here.
    """
    _need(len(encoded) <= 2 * maximum, reason)
    offset = 0
    for part in parts:
        text = part.hex()
        stop = offset + len(text)
        _need(encoded[offset:stop] == text, reason)
        offset = stop
        yield part
    _need(offset == len(encoded), reason)


def _utf8_parts(text):
    for start in range(0, len(text), _TEXT_BLOCK):
        yield text[start:start + _TEXT_BLOCK].encode("utf-8")


def _same_parts(left, right, reason):
    """Exact incremental length, bytes and end-of-stream comparison."""
    left, right = iter(left), iter(right)
    a = b = memoryview(b"")
    ai = bi = 0
    adone = bdone = False
    while True:
        while not adone and ai == len(a):
            part = next(left, None)
            adone = part is None
            a, ai = memoryview(b"" if adone else part), 0
        while not bdone and bi == len(b):
            part = next(right, None)
            bdone = part is None
            b, bi = memoryview(b"" if bdone else part), 0
        if adone or bdone:
            _need(adone and bdone, reason)
            return
        count = min(len(a) - ai, len(b) - bi)
        _need(a[ai:ai + count] == b[bi:bi + count], reason)
        ai += count
        bi += count


def _compact_data_parts(binding, ranges, challenge, frame_size, frame_parts):
    yield b"C003-DIRECT-API-DATA-1\n"
    yield from _json_frame_parts(dict(binding=binding, ranges=ranges, chunk_challenge=challenge))
    yield str(frame_size).encode("ascii") + b":"
    yield from frame_parts
    yield b","


def _compact_bound_requests(requests, split, config, limits):
    reason = "BINDING"
    count = len(requests)
    _need(1 <= count <= min(limits["max_chunks"], 128), reason)
    common, acquisition, plan, identity, files, raw_blobs, flags = _artifact_metadata(
        split, config, count, limits, reason,
    )
    flags, projected = _compact_policy(plan, files, raw_blobs, flags, limits, reason)
    frame_limit = min(plan["budget"]["max_request_bytes"], limits["max_request_bytes"], _FRAME_LIMIT)
    facts = []
    # Pass one: retain only length/hash metadata, never generated frame bytes.
    for index, chunk in enumerate(plan["chunks"]):
        size, hasher = 0, hashlib.sha256()
        for part in _compact_frame_parts(identity, index, chunk, files, raw_blobs, flags, frame_limit):
            size += len(part)
            _need(size <= frame_limit, reason)
            hasher.update(part)
        frame_hash = hasher.hexdigest()
        _fixed(chunk, reason, request_bytes=size, request_sha256=frame_hash)
        facts.append((size, frame_hash))
    binding_fields, system = _artifact_binding(
        common, acquisition, plan, identity, config, count, limits, reason,
    )
    for request in requests:
        binding = request["binding"]
        _fixed(binding, reason, **binding_fields)
        index = binding["chunk_id"]
        _need(index < count, reason)
        chunk = plan["chunks"][index]
        ranges = projected[index]
        _need(request["ranges"] == ranges, reason)
        frame_size, frame_hash = facts[index]
        _fixed(request, reason, framed_request_bytes=frame_size, framed_request_sha256=frame_hash)
        challenge = _named_digest(b"C003-CHALLENGE-1\n", binding=binding, ranges=ranges,
                                  framed_request_sha256=frame_hash)
        _fixed(request, reason, chunk_challenge=challenge)
        wire = request["wire_request"]
        # Compact measurement also streams declared DATA/system strings; it must
        # not encode a whole DATA copy before the incremental comparisons.
        _measure_configured(wire, limits, limits["max_request_bytes"], reason, streamed_strings=True)
        _fixed(wire, reason, model=config["api_model_id"], system=system)
        # Pass two: one frame traversal feeds BOTH exact retained-frame and DATA
        # checks. Wire body encoding later reads caller text, not another render.
        parts = _hex_checked_parts(
            _compact_frame_parts(identity, index, chunk, files, raw_blobs, flags, frame_limit),
            request["split_artifacts"]["framed_request_hex"], min(limits["max_artifact_bytes"], _FRAME_LIMIT), reason,
        )
        _same_parts(_compact_data_parts(binding, ranges, challenge, frame_size, parts),
                    _utf8_parts(wire["messages"][0]["content"][0]["text"]), reason)
        size, hasher = 0, hashlib.sha256()
        for part in _hex_checked_parts(_canonical_parts(wire), request["body_hex"],
                                       limits["max_request_bytes"], reason):
            size += len(part)
            hasher.update(part)
        body_hash = hasher.hexdigest()
        _fixed(request, reason, body_bytes=size, body_sha256=body_hash)
        _fixed(request, reason, stable_request_id=_named_digest(
            b"C003-REQUEST-1\n", binding=binding, chunk_challenge=challenge, body_sha256=body_hash,
            public_headers=request["public_headers"],
        ))


def _association(requests, attempts, limits):
    by_chunk = {r["binding"]["chunk_id"]: r for r in requests}
    _need(len(by_chunk) == len(requests)
          and len({r["stable_request_id"] for r in requests}) == len(requests)
          and len({a["attempt_id"] for a in attempts}) == len(attempts)
          and len({(a["chunk_id"], a["provider_retry_index"]) for a in attempts}) == len(attempts),
          "DUPLICATE")
    _need(list(by_chunk) == list(range(len(requests))), "BINDING")
    groups = [[] for _ in requests]
    for receipt in attempts:
        chunk = receipt["chunk_id"]
        _need(chunk in by_chunk, "BINDING")
        request = by_chunk[chunk]
        stable = request["stable_request_id"]
        _fixed(receipt, "BINDING", body_sha256=request["body_sha256"], stable_request_id=stable,
               workflow_attempt=request["binding"]["workflow_attempt"], attempt_id=_named_digest(
                   b"C003-ATTEMPT-1\n", stable_request_id=stable,
                   provider_retry_index=receipt["provider_retry_index"],
               ))
        groups[chunk].append(receipt)
    for group in groups:
        _need(len(group) <= limits["max_attempts_per_chunk"]
              and [a["provider_retry_index"] for a in group] == list(range(len(group))),
              "RETRY_UNAUTHORIZED")
        end = None
        for start, stop in sorted(_intervals(group)):
            _need(end is None or end <= start, "RETRY_UNAUTHORIZED")
            end = stop


def _intervals(receipts):
    for receipt in receipts:
        start, stop = receipt["started_monotonic_ns"], receipt["finished_monotonic_ns"]
        if receipt["dispatch_state"] != "NOT_SENT" and start < stop:
            yield start, stop


def _coherent_capture(receipt, limits):
    reason = "TRANSPORT"
    start, stop = receipt["started_monotonic_ns"], receipt["finished_monotonic_ns"]
    capture, sent = receipt["response_capture"], receipt["dispatch_state"]
    state, framing, status = receipt["transport_state"], receipt["http_framing_complete"], receipt["http_status"]
    overflow = receipt["response_overflow_observed"]
    encoded = receipt["response_hex"]
    _need(start <= stop, reason)
    for key in ("content_type", "content_encoding", "response_retry_after_raw"):
        if receipt[key] is not None:
            _text(receipt[key], reason, maximum=limits["max_string_bytes"])
    if sent == "NOT_SENT":
        _need(status is None and state in ("ERROR", "TIMEOUT", "CANCELLED")
              and capture == "NOT_OBSERVED" and not overflow
              and receipt["response_retry_after_raw"] is None, reason)
    if state == "COMPLETE":
        _need(status is not None and framing, reason)
    if (status == 200 or sent in ("NOT_SENT", "UNKNOWN") or capture == "PREFIX_ONLY"
            or receipt["response_retry_after_raw"] is not None):
        _need(receipt["retry_not_before_monotonic_ns"] is None, reason)
    if capture == "NOT_OBSERVED":
        _need(not framing and encoded is None and receipt["response_bytes"] == 0
              and receipt["response_sha256"] is None and receipt["captured_prefix_sha256"] is None, reason)
        return None
    _need(encoded is not None, reason)
    raw = _binary(encoded, limits["max_response_bytes"], reason)
    _need(len(raw) == receipt["response_bytes"], reason)
    if capture == "PREFIX_ONLY":
        _need(not framing and receipt["response_sha256"] is None
              and receipt["captured_prefix_sha256"] == _digest(raw), reason)
    else:
        _need(not overflow and receipt["captured_prefix_sha256"] is None
              and receipt["response_sha256"] == _digest(raw), reason)
    return raw


def _complete(receipt):
    return (receipt["transport_state"] == "COMPLETE" and receipt["http_framing_complete"]
            and receipt["response_capture"] == "COMPLETE" and receipt["http_status"] is not None)


def _ambiguous(receipt):
    return (receipt["dispatch_state"] == "UNKNOWN"
            or (receipt["dispatch_state"] == "SENT" and not _complete(receipt)))


def _budget(requests, attempts, receipt, config, config_hash, limits):
    reason = "BUDGET"
    for row in [receipt, *attempts]:
        for value in row.values():
            if type(value) is int:
                _need(value <= limits["max_integer_value"] and len(str(value)) <= limits["max_integer_digits"], reason)
    for key in ("price_accounting_ref", "token_accounting_ref"):
        _fixed(receipt, reason, **{key: config[key]})
    start, deadline = receipt["run_started_monotonic_ns"], receipt["deadline_monotonic_ns"]
    _need(deadline == start + limits["max_run_duration_ns"], reason)
    for attempt in attempts:
        first, last = attempt["started_monotonic_ns"], attempt["finished_monotonic_ns"]
        _need(start <= first <= last <= min(deadline, first + limits["attempt_timeout_ns"]), reason)
    slots = limits["max_attempts_per_chunk"]
    reserve = len(requests) * slots
    dispatched = sum(a["dispatch_state"] != "NOT_SENT" for a in attempts)
    unresolved = sum(_ambiguous(a) for a in attempts)
    _need(len(attempts) <= limits["max_attempts_per_run"] and dispatched <= reserve
          and reserve <= limits["max_attempts_per_run"], reason)
    inputs = outputs = costs = 0
    for request in requests:
        bound = request["declared_input_token_bound"]
        output = request["wire_request"]["max_tokens"]
        cost = request["declared_cost_bound_units"]
        _need(bound <= limits["max_input_tokens"] and output <= limits["max_output_tokens"]
              and bound + output <= limits["max_context_tokens"], reason)
        inputs += bound * slots
        outputs += output * slots
        costs += cost * slots
    _need(inputs + outputs <= limits["max_run_reserved_tokens"] and costs <= limits["max_run_cost_units"], reason)
    _fixed(receipt, reason, reservation_state="RESERVED", config_sha256=config_hash,
           attempts_dispatched=dispatched, unresolved_attempts=unresolved, reserved_attempts=reserve,
           reserved_input_tokens=inputs, reserved_output_tokens=outputs, reserved_cost_units=costs)
    events = [(time, change) for start, stop in _intervals(attempts)
              for time, change in ((start, 1), (stop, -1))]
    parallel = 0
    for _, change in sorted(events):
        parallel += change
        _need(parallel <= limits["max_parallel_chunks"], reason)


def _provider(raw, config, limits):
    reason = "PROVIDER_SCHEMA"
    message = _parse(raw, limits, reason)
    _keys(message, "content id model role stop_reason stop_sequence type usage", reason,
          "container diagnostics stop_details")
    _fixed(message, reason, role="assistant", type="message")
    _text(message["id"], reason, maximum=limits["max_string_bytes"])
    _choice(message["model"], config["approved_reported_models"], reason)
    for key in ("container", "diagnostics", "stop_details"):
        _need(message.get(key) is None, reason)
    stop = message["stop_reason"]
    if stop is not None:
        _choice(stop, ("end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal",
                       "model_context_window_exceeded"), reason)
    if message["stop_sequence"] is not None:
        _text(message["stop_sequence"], reason, maximum=limits["max_string_bytes"])
    _array(message["content"], reason, 1, 1)
    block = message["content"][0]
    _keys(block, "type text", reason, "citations")
    _fixed(block, reason, type="text")
    _text(block["text"], reason, minimum=0, maximum=limits["max_response_bytes"])
    _need(block.get("citations") is None or block["citations"] == [], reason)
    usage = message["usage"]
    _keys(usage, _USAGE, reason,
          "cache_creation inference_geo output_tokens_details server_tool_use service_tier speed")
    for key in _USAGE.split():
        _int(usage[key], reason, maximum=limits["max_integer_value"])
    for key in ("cache_creation", "output_tokens_details", "server_tool_use"):
        _need(usage.get(key) is None, reason)
    for key, config_key in (("inference_geo", "approved_inference_geos"),
                            ("service_tier", "approved_service_tiers"), ("speed", "approved_speeds")):
        _choice(usage.get(key), config[config_key], reason)
    return message


def _terminal(message):
    stop = message["stop_reason"]
    _need(stop is not None, "TERMINAL")
    _need(stop not in ("max_tokens", "model_context_window_exceeded"), "TRUNCATED")
    _need(stop not in ("tool_use", "pause_turn", "refusal"), "TOOL_OR_REFUSAL")
    _need(stop == "end_turn" and message["stop_sequence"] is None, "TERMINAL")


def _usage(message):
    usage = message["usage"]
    return (
        usage["input_tokens"] + usage["cache_creation_input_tokens"] + usage["cache_read_input_tokens"],
        usage["output_tokens"],
    )


def _model(message, limits):
    reason = "MODEL_SCHEMA"
    result = _parse(message["content"][0]["text"].encode("utf-8"), limits, reason)
    _keys(result, "schema outcome findings limitations", reason)
    _fixed(result, reason, schema=1)
    _choice(result["outcome"], ("findings", "no_findings", "unable_to_review"), reason)
    _array(result["findings"], reason, maximum=limits["max_findings_per_chunk"])
    _array(result["limitations"], reason, maximum=limits["max_limitations"])
    for limitation in result["limitations"]:
        _text(limitation, reason, maximum=limits["max_string_bytes"])
    for finding in result["findings"]:
        _keys(finding, "path side start end severity rule message filter_reason", reason)
        _path(finding["path"], limits["max_path_bytes"], reason)
        _choice(finding["side"], ("base", "head"), reason)
        _choice(finding["severity"], ("P0", "P1", "P2", "P3"), reason)
        _int(finding["start"], reason, maximum=limits["max_artifact_bytes"])
        _int(finding["end"], reason, 1, limits["max_artifact_bytes"])
        for key in ("rule", "message"):
            _text(finding[key], reason, maximum=limits["max_string_bytes"])
        if finding["filter_reason"] is not None:
            _text(finding["filter_reason"], reason, maximum=limits["max_string_bytes"])
    return result


def _model_meaning(result, request):
    findings = result["findings"]
    _need(all(row["filter_reason"] is None for row in findings), "FILTER_UNAPPROVED")
    outcome = result["outcome"]
    _need(not result["limitations"] and (
        (outcome == "findings" and bool(findings)) or (outcome == "no_findings" and not findings)
    ), "MODEL_SCHEMA")
    for finding in findings:
        _need(any(
            item["path"] == finding["path"] and item["side"] == finding["side"]
            and item["start"] <= finding["start"] < finding["end"] <= item["end"]
            for item in request["ranges"]
        ), "MODEL_SCHEMA")


def _retry_eligible(receipt, config, limits, deadline):
    index = receipt["provider_retry_index"]
    policy = config["retry_policy"]
    if (receipt["http_status"] not in policy["allowed_http_statuses"]
            or index + 1 >= limits["max_attempts_per_chunk"]
            or receipt["response_retry_after_raw"] is not None):
        return False
    ready = receipt["finished_monotonic_ns"] + policy["backoff_ns_by_retry"][index]
    return (receipt["retry_not_before_monotonic_ns"] == ready
            and ready + limits["attempt_timeout_ns"] <= deadline)


def _evaluate_attempt(receipt, raw, request, config, limits, deadline):
    evaluation = dict(receipt=receipt, provider_message=None, model_result=None,
                      decision="REFUSED", reasons=[])
    try:
        _need(receipt["dispatch_state"] == "SENT" and _complete(receipt)
              and not receipt["response_overflow_observed"]
              and receipt["content_type"] == "application/json"
              and receipt["content_encoding"] in (None, "identity"), "TRANSPORT")
        if receipt["http_status"] != 200:
            if _retry_eligible(receipt, config, limits, deadline):
                evaluation["decision"] = _ELIGIBLE
            raise _Refusal("TRANSPORT")
        message = _provider(raw, config, limits)
        evaluation["provider_message"] = message
        _terminal(message)
        tokens_in, tokens_out = _usage(message)
        _need(tokens_in <= request["declared_input_token_bound"]
              and tokens_out <= request["wire_request"]["max_tokens"], "BUDGET")
        result = _model(message, limits)
        evaluation["model_result"] = result
        _model_meaning(result, request)
        evaluation["decision"] = "CANDIDATE"
    except _Refusal as error:
        evaluation["reasons"] = [str(error)]
    return evaluation


def _select(evaluations, count, receipt, limits):
    response_ids = [a["provider_message"]["id"] for a in evaluations if a["provider_message"] is not None]
    candidates = [a for a in evaluations if a["decision"] == "CANDIDATE"]
    chunks = [a["receipt"]["chunk_id"] for a in candidates]
    _need(len(response_ids) == len(set(response_ids)) and len(chunks) == len(set(chunks)), "DUPLICATE")
    for previous, following in zip(evaluations, evaluations[1:]):
        before, after = previous["receipt"], following["receipt"]
        if before["chunk_id"] == after["chunk_id"]:
            _need(previous["decision"] == _ELIGIBLE
                  and after["started_monotonic_ns"] >= before["retry_not_before_monotonic_ns"],
                  "RETRY_UNAUTHORIZED")
    for evaluation in evaluations:
        if evaluation["decision"] == "REFUSED":
            raise _Refusal(evaluation["reasons"][0])
    _need(chunks == list(range(count)), "MISSING_RESULT")
    dispatched = [a for a in evaluations if a["receipt"]["dispatch_state"] != "NOT_SENT"]
    if any(a["provider_message"] is None for a in dispatched):
        tokens_in = tokens_out = None
    else:
        usage = [_usage(a["provider_message"]) for a in dispatched]
        tokens_in = sum(pair[0] for pair in usage)
        tokens_out = sum(pair[1] for pair in usage)
    _fixed(receipt, "BUDGET", provider_reported_input_total=tokens_in, provider_reported_output_total=tokens_out)
    _need(sum(len(a["model_result"]["findings"]) for a in candidates) <= limits["max_findings_per_run"],
          "BUDGET")
    return candidates


def _shell():
    return dict(
        schema=1, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
        security_review_completed=False, provider_verified=False, acquisition_authenticated=False,
        config_sha256=None, budget_receipt=None, requests=[], attempts=[], selected_attempt_ids=[],
        internal_status="REFUSED", raw_findings=None, raw_finding_count=None, unique_finding_count=None,
        effective_findings_count=None, exclusions=[], reasons=[],
    )


def _evaluate_bundle(bundle, compact):
    """Shared G1 and G3-through-P4; public functions explicitly select G0/G2."""
    result = _shell()
    if compact:
        result.update(result_format=2, common_artifacts=None)
    try:
        # G0 owns the static raw shapes. Missing config is deliberately G1.
        _raw_shape(bundle, compact)
        config = bundle.get("config")
        limits = _configuration(config)
        result["config_sha256"] = _digest(_canonical(config))
        requests, budget = bundle["requests"], bundle["budget_receipt"]
        if compact:
            _compact_bound_requests(requests, bundle["common_artifacts"], config, limits)
        else:
            _bound_requests(requests, config, limits)
        for request in requests:
            _need(all(request["binding"][key] == bundle["current_identity"][key]
                      for key in _CURRENT.split()), "STALE")
        attempts = sorted(bundle["attempts"], key=lambda a: (a["chunk_id"], a["provider_retry_index"]))
        _association(requests, attempts, limits)
        captures = [_coherent_capture(receipt, limits) for receipt in attempts]
        _budget(requests, attempts, budget, config, result["config_sha256"], limits)
        # Once global validation passes, keep the whole typed trace, even if
        # one local attempt later refuses.
        evaluations = [
            _evaluate_attempt(receipt, raw, requests[receipt["chunk_id"]], config, limits,
                              budget["deadline_monotonic_ns"])
            for receipt, raw in zip(attempts, captures)
        ]
        result.update(requests=requests, budget_receipt=budget, attempts=evaluations)
        if compact:
            result["common_artifacts"] = bundle["common_artifacts"]
        selected = _select(evaluations, len(requests), budget, limits)
        trace = [
            dict(chunk_id=a["receipt"]["chunk_id"], attempt_id=a["receipt"]["attempt_id"],
                 model_finding_index=index, finding=finding)
            for a in selected for index, finding in enumerate(a["model_result"]["findings"])
        ]
        result.update(
            internal_status="INTERNALLY_BOUND_SYNTHETIC", raw_findings=trace,
            raw_finding_count=len(trace), unique_finding_count=len({_canonical(row["finding"]) for row in trace}),
            selected_attempt_ids=[a["receipt"]["attempt_id"] for a in selected],
        )
    except _Refusal as error:
        result["reasons"] = [str(error)]
    return result


def evaluate_injected_bundle(bundle):
    """Legacy r2 plus repository parity; original nineteen-key output contract."""
    return _evaluate_bundle(bundle, False)


def evaluate_common_artifact_bundle(bundle):
    """Explicit strict r3 input2/output2; common artifacts once, no I/O or wiring."""
    return _evaluate_bundle(bundle, True)
