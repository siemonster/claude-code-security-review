"""Synthetic contract tests. Run this file by path to bypass package init."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

_spec = importlib.util.spec_from_file_location(
    "provider_result_contract_under_test", Path(__file__).with_name("provider_result_contract.py")
)
contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contract)

PLANNER = "5433860d497a863f6e0c56a27e8b4f10131e1fd0"
ACQUISITION = "a739fd5901eefd055e89337ff6092559f5fca4ed"


def canonical(value, ascii_only=False):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only, allow_nan=False
    ).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def netstring(raw):
    return str(len(raw)).encode() + b":" + raw + b","


def git_oid(kind, raw):
    return hashlib.sha1(f"{kind} {len(raw)}\0".encode() + raw).hexdigest()


def attempt_id(request_id, index):
    return digest(b"C003-ATTEMPT-1\n" + canonical({
        "stable_request_id": request_id, "provider_retry_index": index,
    }))


def put_response(receipt, message):
    raw = canonical(message)
    receipt.update(response_hex=raw.hex(), response_bytes=len(raw), response_sha256=digest(raw))


def source_fixture(chunk_count, case):
    """Use the sibling tests' descriptor/file-row pattern, with in-memory bytes only."""
    blobs = {}

    def descriptor(raw, mode="100644"):
        if raw is None:
            return None
        oid = git_oid("blob", raw)
        blobs[oid] = raw.hex()
        return dict(oid=oid, bytes=len(raw), sha256=digest(raw), mode=mode)

    def row(path, status="A", before=None, after=b"abc\n", old_path=None, mode="100644"):
        return dict(path=path, old_path=old_path, status=status,
                    base=descriptor(before), head=descriptor(after, mode))

    if case == "mixed":
        files = [
            row(".github/workflows/example.yml", after=b"name: synthetic\n"),
            row("deleted.txt", "D", b"gone\n", None),
            row("empty.txt", after=b""),
            row("mode.txt", "M", b"mode\n", b"mode\n", mode="100755"),
            row("modified.txt", "M", b"old\n", b"new\n"),
            row("renamed.txt", "R", b"before\n", b"after\n", old_path="old-name.txt"),
        ]
        groups = [dict(kind="ATOMIC", paths=[files[0]["path"], files[1]["path"]])]
        groups += [dict(kind="STREAM", paths=[f["path"]]) for f in files[2:]]
    else:
        raw = "αβγδε\n".encode() if case == "split" else b"abc\n"
        if case == "stream_blocks":
            raw = ('λ😀"\\\n'*160).encode()
        files = [row(f"file-{i}-λ.txt", after=raw) for i in range(1 if case == "split" else chunk_count)]
        if case == "stream_blocks":
            files[0]["path"] = 'file-λ😀".txt'
        groups = [dict(kind="STREAM", paths=[f["path"]]) for f in files]
    items = {f["path"]: [dict(path=f["path"], side=side, oid=f[side]["oid"],
                                  start=0, end=f[side]["bytes"])
                             for side in ("base", "head") if f[side] is not None] for f in files}
    chunks = [[item for path in group["paths"] for item in items[path]] for group in groups]
    if case == "split":
        item = items[files[0]["path"]][0]
        chunks = [[dict(item, end=6)], [dict(item, start=4)]]
    flags = []
    for f in files:
        declared = []
        if f["path"].startswith(".github/") or (f["old_path"] or "").startswith(".github/"):
            declared.append("WORKFLOW")
        if f["status"] in ("D", "R"):
            declared.append({"D": "DELETION", "R": "RENAME"}[f["status"]])
        if f["base"] and f["head"] and f["base"]["mode"] != f["head"]["mode"]:
            declared.append("MODE_CHANGE")
        if declared:
            flags.append(dict(path=f["path"], old_path=f["old_path"], flags=declared))
    return files, blobs, groups, chunks, flags


def render_frame(plan, index):
    """Independent source-format framing; never calls evaluator internals."""
    chunk = plan["chunks"][index]
    envelope = dict(schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                    identity=plan["inventory"]["identity"], chunk_id=index, item_count=len(chunk["items"]))
    parts = [b"C003-INERT-BYTE-PLAN-3\n", netstring(canonical(envelope, True))]
    files = {row["path"]: row for row in plan["inventory"]["files"]}
    flags = {row["path"]: row["flags"] for row in plan["flagged_paths"]}
    for item in chunk["items"]:
        row = files[item["path"]]
        desc = row[item["side"]]
        header = dict(item, old_path=row["old_path"], status=row["status"], mode=desc["mode"],
                      size=desc["bytes"], sha256=desc["sha256"], disposition="REVIEWED_RAW",
                      flags=flags.get(row["path"], []))
        raw = bytes.fromhex(plan["blobs"][item["oid"]])[item["start"]:item["end"]]
        parts.extend([netstring(canonical(header, True)), netstring(raw)])
    return b"".join(parts)


def example(chunk_count=1, *, case=None, repository="synthetic/example", edit_plan=None,
            **limit_overrides):
    """Compose source-shaped fixtures and seal layers independently of the evaluator.

    edit_plan runs before frame/outer sealing, so tests can isolate a plan invariant
    without accidentally failing an unrelated enclosing digest first.
    """
    files, blobs, groups, item_groups, flags = source_fixture(chunk_count, case)
    chunk_count = len(item_groups)
    limits = dict(
        max_string_bytes=65536, max_path_bytes=1024, max_integer_digits=16,
        max_integer_value=9007199254740991, max_pr=100, max_workflow_attempt=4,
        max_request_bytes=65536, max_response_bytes=16384, max_artifact_bytes=131072,
        max_json_depth=24, max_json_members=20000, max_chunks=4, max_ranges_per_chunk=8,
        max_findings_per_chunk=8, max_findings_per_run=16, max_limitations=4,
        max_attempts_per_chunk=2, max_attempts_per_run=8, max_input_tokens=128,
        max_output_tokens=256, max_context_tokens=512, max_run_reserved_tokens=2048,
        attempt_timeout_ns=1000, max_run_duration_ns=10000, max_run_cost_units=20,
        max_parallel_chunks=2,
    )
    if case == "mixed":
        limits.update(max_chunks=8, max_attempts_per_run=16)
    limits.update(limit_overrides)
    model = "SYNTHETIC_MODEL"
    config = dict(
        api_model_id=model, api_version="2026-10-21", display_model_intent="Fable 5.2",
        provider_account_authorization_ref="SYNTHETIC_NO_ACCOUNT", transport_version_ref="SYNTHETIC",
        token_accounting_ref="SYNTHETIC_TOKENS", price_accounting_ref="SYNTHETIC_PRICE",
        approved_reported_models=[model], approved_service_tiers=["standard"],
        approved_speeds=["standard"], approved_inference_geos=["SYNTHETIC_REGION"],
        cost_unit="SYNTHETIC", retention_policy_ref="SYNTHETIC",
        retry_policy_ref="SYNTHETIC", closure_policy_ref="SYNTHETIC",
        retry_policy=dict(
            allowed_http_statuses=[429, 503], backoff_ns_by_retry=[10],
            allow_ambiguous_dispatch=False, max_inflight_per_chunk=1, model_fallback=False,
        ),
        evidence_mode="INJECTED_SYNTHETIC", production_ready=False, limits=limits,
    )
    prompt = "Synthetic prompt α".encode()
    policy = b"Synthetic policy"
    roots = dict(
        repository=repository, pr=1, base_tip="1"*40, merge_base="1"*40,
        comparison_base="1"*40, head="2"*40,
    )
    acquisition = dict(
        schema=1, scope="MODEL_ONLY", qualification="NOT_ADMITTED",
        acquisition_authenticated=False, gate_wired=False, identity=roots,
        trust="CALLER_SUPPLIED_UNAUTHENTICATED_UNFRESH", object_format="sha1",
        ancestry=[roots["head"], roots["base_tip"]], pages="SELF_CONSISTENT_AND_EQUAL_TO_TREE_SET",
        closure="NOT_EVALUATED", unchanged_context="NOT_ACQUIRED", declared_changed_files=len(files),
        files=files, blobs=blobs, raw_bytes=sum(len(bytes.fromhex(b)) for b in blobs.values()),
        logical_bytes=sum(f[side]["bytes"] for f in files for side in ("base", "head") if f[side]),
        limits=dict(
            max_files=128, max_total_bytes=2097152, max_objects=2048, max_commits=128,
            max_pages=128, max_depth=32, max_structural_bytes=262144,
            max_tree_entries=8192, max_object_bytes=4194304,
        ),
        verified_objects=sorted([roots["base_tip"], roots["head"], *blobs]),
    )
    caller = dict(
        scope="INJECTED_SYNTHETIC", source="CALLER_ASSERTED_UNVERIFIED",
        claimed_status="SUPPLIED_COMPLETE", groups=groups,
        acquisition_closure="NOT_EVALUATED", closure_sufficiency="UNVERIFIED",
    )
    identity = dict(
        repository=roots["repository"], pr=1, base=roots["comparison_base"], head=roots["head"],
        planner_sha=PLANNER, prompt_sha256=digest(prompt), policy_sha256=digest(policy),
        model=model, run_id="synthetic-run", attempt=1, challenge="3"*64,
    )
    plan = dict(
        schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
        inventory=dict(
            schema=3, identity=identity, compare_file_count=len(files), files=files,
            dependencies=dict(status="SUPPLIED_COMPLETE", groups=groups),
        ),
        blobs=blobs,
        budget=dict(
            max_request_bytes=65536, max_chunks=limits["max_chunks"], overlap_bytes=1,
            max_files=len(files), max_total_bytes=max(acquisition["logical_bytes"], 1),
        ),
        chunks=[dict(id=i, items=items) for i, items in enumerate(item_groups)], flagged_paths=flags,
    )
    if edit_plan is not None:
        edit_plan(plan)
    frames = [render_frame(plan, i) for i in range(chunk_count)]
    for chunk, frame in zip(plan["chunks"], frames):
        chunk.update(request_bytes=len(frame), request_sha256=digest(frame))
    plan["plan_sha256"] = digest(canonical(plan, True))
    current = dict(roots, workflow_run_id=identity["run_id"], workflow_attempt=1)
    requests, receipts, evaluations, trace = [], [], [], []
    for index, (frame, chunk) in enumerate(zip(frames, plan["chunks"])):
        binding = dict(
            current, acquisition_manifest_sha256=digest(canonical(acquisition)),
            acquisition_source_sha=ACQUISITION, planner_source_sha=PLANNER, plan_schema=3,
            plan_sha256=plan["plan_sha256"], chunk_id=index, chunk_count=chunk_count,
            run_challenge=identity["challenge"], prompt_sha256=digest(prompt), policy_sha256=digest(policy),
            config_sha256=digest(canonical(config)), roots_authenticated=False,
            acquisition_closure="NOT_EVALUATED", plan_dependency_assertion="CALLER_ASSERTED_UNVERIFIED",
            caller_dependency_assertion_sha256=digest(canonical(caller)), schema3_identity_model=model,
        )
        by_path = {f["path"]: f for f in files}
        ranges = [dict(item, old_path=by_path[item["path"]]["old_path"],
                       blob_sha256=by_path[item["path"]][item["side"]]["sha256"])
                  for item in chunk["items"]]
        frame_hash = digest(frame)
        challenge = digest(b"C003-CHALLENGE-1\n" + canonical(dict(
            binding=binding, ranges=ranges, framed_request_sha256=frame_hash,
        )))
        data = b"C003-DIRECT-API-DATA-1\n" + netstring(canonical(dict(
            binding=binding, ranges=ranges, chunk_challenge=challenge,
        ))) + netstring(frame)
        wire = dict(
            model=model, max_tokens=128, system=(prompt+b"\n"+policy).decode(), stream=False,
            messages=[dict(role="user", content=[dict(type="text", text=data.decode())])],
        )
        headers = {"content-type": "application/json", "anthropic-version": "2026-10-21"}
        body = canonical(wire)
        stable = digest(b"C003-REQUEST-1\n" + canonical(dict(
            binding=binding, chunk_challenge=challenge, body_sha256=digest(body),
            public_headers=headers,
        )))
        requests.append(dict(
            binding=binding, ranges=ranges, framed_request_sha256=frame_hash,
            framed_request_bytes=len(frame), chunk_challenge=challenge, stable_request_id=stable,
            method="POST", url="https://api.anthropic.com/v1/messages", public_headers=headers,
            body_hex=body.hex(), body_bytes=len(body), body_sha256=digest(body), wire_request=wire,
            split_artifacts=dict(
                owner_config_hex=canonical(config).hex(), acquisition_manifest_hex=canonical(acquisition).hex(),
                plan_hex=canonical(plan, True).hex(), prompt_hex=prompt.hex(), policy_hex=policy.hex(),
                caller_dependency_assertion_hex=canonical(caller).hex(), framed_request_hex=frame.hex(),
            ),
            declared_input_token_bound=64, declared_cost_bound_units=2,
        ))
        nonempty = next((r for r in ranges if r["start"] < r["end"]), None)
        findings = [] if nonempty is None else [dict(
            path=nonempty["path"], side=nonempty["side"], start=nonempty["start"],
            end=min(nonempty["end"], nonempty["start"]+3), severity="P3",
            rule="synthetic-rule", message="Injected finding", filter_reason=None,
        )]
        result = dict(schema=1, outcome="findings" if findings else "no_findings",
                      findings=findings, limitations=[])
        message = dict(
            id=f"synthetic-response-{index}", type="message", role="assistant", model=model,
            content=[dict(type="text", text=canonical(result).decode())],
            stop_reason="end_turn", stop_sequence=None,
            usage=dict(
                input_tokens=64, output_tokens=16, cache_creation_input_tokens=0,
                cache_read_input_tokens=0, inference_geo="SYNTHETIC_REGION",
                service_tier="standard", speed="standard",
            ),
        )
        aid = attempt_id(stable, 0)
        receipt = dict(
            attempt_id=aid, stable_request_id=stable, chunk_id=index, provider_retry_index=0,
            workflow_attempt=1, body_sha256=digest(body), started_monotonic_ns=1010+index*40,
            finished_monotonic_ns=1020+index*40, dispatch_state="SENT", transport_state="COMPLETE",
            http_status=200, http_framing_complete=True, content_type="application/json",
            content_encoding=None, response_capture="COMPLETE", response_overflow_observed=False,
            response_retry_after_raw=None, retry_not_before_monotonic_ns=None,
            captured_prefix_sha256=None,
        )
        put_response(receipt, message)
        receipts.append(receipt)
        evaluations.append(dict(
            receipt=receipt, provider_message=message, model_result=result, decision="CANDIDATE", reasons=[],
        ))
        trace.extend(dict(chunk_id=index, attempt_id=aid, model_finding_index=i, finding=finding)
                     for i, finding in enumerate(findings))
    budget = dict(
        run_started_monotonic_ns=1000, deadline_monotonic_ns=11000,
        config_sha256=digest(canonical(config)), token_accounting_ref="SYNTHETIC_TOKENS",
        price_accounting_ref="SYNTHETIC_PRICE", reservation_state="RESERVED",
        reserved_input_tokens=128*chunk_count, reserved_output_tokens=256*chunk_count,
        reserved_cost_units=4*chunk_count, reserved_attempts=2*chunk_count,
        attempts_dispatched=chunk_count, provider_reported_input_total=64*chunk_count,
        provider_reported_output_total=16*chunk_count, unresolved_attempts=0,
    )
    bundle = dict(config=config, current_identity=current, requests=requests, attempts=receipts, budget_receipt=budget)
    expected = output(
        config_sha256=digest(canonical(config)), budget_receipt=budget, requests=requests,
        attempts=evaluations, selected_attempt_ids=[row["attempt_id"] for row in receipts],
        internal_status="INTERNALLY_BOUND_SYNTHETIC", raw_findings=trace,
        raw_finding_count=len(trace), unique_finding_count=len(trace), reasons=[],
    )
    return copy.deepcopy(bundle), copy.deepcopy(expected)


def output(**values):
    fixed = dict(
        schema=1, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
        security_review_completed=False, provider_verified=False, acquisition_authenticated=False,
        effective_findings_count=None, exclusions=[],
    )
    fixed.update(values)
    return fixed


def reseal_request(bundle, index=0, *, render_wire=True):
    """Seal outer request/receipt layers after a deliberate inner test change.

    Does not repair a plan, frame, ranges, or (when false) wire-text defect.
    """
    request = bundle["requests"][index]
    frame = bytes.fromhex(request["split_artifacts"]["framed_request_hex"])
    request["chunk_challenge"] = digest(b"C003-CHALLENGE-1\n" + canonical(dict(
        binding=request["binding"], ranges=request["ranges"],
        framed_request_sha256=request["framed_request_sha256"],
    )))
    if render_wire:
        data = b"C003-DIRECT-API-DATA-1\n" + netstring(canonical(dict(
            binding=request["binding"], ranges=request["ranges"],
            chunk_challenge=request["chunk_challenge"],
        ))) + netstring(frame)
        request["wire_request"]["messages"][0]["content"][0]["text"] = data.decode()
    body = canonical(request["wire_request"])
    request.update(body_hex=body.hex(), body_bytes=len(body), body_sha256=digest(body))
    stable = digest(b"C003-REQUEST-1\n" + canonical(dict(
        binding=request["binding"], chunk_challenge=request["chunk_challenge"],
        body_sha256=digest(body), public_headers=request["public_headers"],
    )))
    request["stable_request_id"] = stable
    for receipt in bundle["attempts"]:
        if receipt["chunk_id"] == index:
            receipt.update(stable_request_id=stable, body_sha256=digest(body),
                           attempt_id=attempt_id(stable, receipt["provider_retry_index"]))


class ProviderResultContractTests(unittest.TestCase):
    def test_injected_finding_has_complete_nonadmitted_trace(self):
        bundle, expected = example()
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_repository_dot_components_refuse_with_complete_binding_shell(self):
        for repository in ("../..", "./project", "owner/..", "owner/."):
            with self.subTest(repository=repository):
                bundle, _ = example(repository=repository)
                self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_repository_punctuation_components_are_valid(self):
        bundle, expected = example(repository="owner-name/repo.name_2")
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_repository_length_boundary_matches_acquisition(self):
        for length in (255, 256, 257, 1024):
            with self.subTest(length=length):
                bundle, expected = example(repository="o/" + "r"*(length-2))
                if length > 256:
                    expected = early("BINDING", bundle)
                self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_repository_length_also_obeys_lower_configured_path_bound(self):
        bundle, _ = example(repository="o/" + "r"*254, max_path_bytes=128)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_supported_changes_flags_empty_side_and_atomic_group(self):
        bundle, expected = example(case="mixed")
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_overlapping_utf8_stream_has_complete_trace(self):
        bundle, expected = example(case="split")
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_plan_self_hash_is_checked_after_outer_resealing(self):
        bundle, _ = example()
        request = bundle["requests"][0]
        plan = json.loads(bytes.fromhex(request["split_artifacts"]["plan_hex"]))
        plan["plan_sha256"] = "0"*64
        request["split_artifacts"]["plan_hex"] = canonical(plan, True).hex()
        request["binding"]["plan_sha256"] = plan["plan_sha256"]
        reseal_request(bundle)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_full_side_coverage_is_checked_with_consistent_frames(self):
        def omit_last_byte(plan):
            plan["chunks"][0]["items"][0]["end"] -= 1
        bundle, _ = example(edit_plan=omit_last_byte)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_request_ranges_must_match_plan_with_valid_frame_preimages(self):
        bundle, _ = example()
        bundle["requests"][0]["ranges"][0]["end"] -= 1
        # Keep the original plan-projected challenge/DATA/body. Only the
        # redundant RequestRecord projection differs from those valid bytes.
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_retained_frame_must_match_plan_with_valid_wire_preimages(self):
        bundle, _ = example()
        split = bundle["requests"][0]["split_artifacts"]
        frame = bytes.fromhex(split["framed_request_hex"])
        split["framed_request_hex"] = frame.replace(b"abc\n", b"xyz\n").hex()
        # Plan/frame hash and wire bytes remain valid; retained frame differs.
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_wire_text_must_contain_exact_frame_after_body_resealing(self):
        bundle, _ = example()
        request = bundle["requests"][0]
        request["wire_request"]["messages"][0]["content"][0]["text"] += "changed"
        reseal_request(bundle, render_wire=False)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BINDING", bundle))

    def test_finding_same_blob_must_be_in_its_own_chunk_range(self):
        bundle, expected = example(case="split")
        evaluation = expected["attempts"][0]
        evaluation["model_result"]["findings"][0].update(start=6, end=8)
        replace_model(bundle, evaluation)
        evaluation.update(decision="REFUSED", reasons=["MODEL_SCHEMA"])
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "MODEL_SCHEMA"))

    def test_duplicate_keys_refuse_at_provider_and_model_json_layers(self):
        for layer in ("provider", "model"):
            with self.subTest(layer=layer):
                bundle, expected = example()
                evaluation = expected["attempts"][0]
                message = evaluation["provider_message"]
                if layer == "provider":
                    raw = canonical(message).replace(b'"role":"assistant"',
                                                     b'"role":"assistant","role":"assistant"')
                    evaluation["provider_message"] = None
                    reason = "PROVIDER_SCHEMA"
                else:
                    message["content"][0]["text"] = message["content"][0]["text"].replace(
                        '"schema":1', '"schema":1,"schema":1')
                    raw = canonical(message)
                    reason = "MODEL_SCHEMA"
                receipt = bundle["attempts"][0]
                receipt.update(response_hex=raw.hex(), response_bytes=len(raw), response_sha256=digest(raw))
                evaluation.update(receipt=receipt, model_result=None, decision="REFUSED", reasons=[reason])
                self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, reason))


    def test_raw_shape_precedes_missing_config(self):
        bundle, _ = example()
        bundle.pop("config")
        bundle["requests"][0]["wire_request"]["stream"] = True
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("INPUT_SHAPE"))

    def test_absent_null_and_unavailable_config_have_same_shell(self):
        for case in ("absent", "null", "limit"):
            with self.subTest(case=case):
                bundle, _ = example()
                if case == "absent":
                    bundle.pop("config")
                elif case == "null":
                    bundle["config"] = None
                else:
                    bundle["config"]["limits"]["max_response_bytes"] = None
                self.assertEqual(contract.evaluate_injected_bundle(bundle), early("CONFIG_UNQUALIFIED"))

    def test_static_binding_hash_pattern_is_raw_shape(self):
        bundle, _ = example()
        bundle["requests"][0]["binding"]["head"] = "G"*40
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("INPUT_SHAPE"))

    def test_raw_surrogate_returns_shape_refusal(self):
        bundle, _ = example()
        bundle["requests"][0]["wire_request"]["system"] = "\ud800"
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("INPUT_SHAPE"))

    def test_preimage_and_association_failures_keep_only_config_digest(self):
        for fault, reason in (
            ("wrong_model", "BINDING"), ("changed_prompt", "BINDING"), ("changed_head", "STALE"),
            ("wrong_workflow_attempt", "BINDING"), ("wrong_body_hash", "BINDING"),
        ):
            with self.subTest(fault=fault):
                bundle, _ = example()
                if fault == "wrong_model":
                    bundle["requests"][0]["wire_request"]["model"] = "OTHER_SYNTHETIC"
                elif fault == "changed_prompt":
                    bundle["requests"][0]["split_artifacts"]["prompt_hex"] = b"other prompt".hex()
                elif fault == "changed_head":
                    bundle["current_identity"]["head"] = "4"*40
                elif fault == "wrong_workflow_attempt":
                    bundle["attempts"][0]["workflow_attempt"] = 2
                else:
                    bundle["requests"][0]["body_sha256"] = "0"*64
                self.assertEqual(contract.evaluate_injected_bundle(bundle), early(reason, bundle))

    def test_budget_upper_bound_is_not_a_raw_wire_shape_failure(self):
        bundle, _ = example(max_output_tokens=64)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BUDGET", bundle))

    def test_configuration_cross_limits_are_only_the_written_relations(self):
        bundle, expected = example(attempt_timeout_ns=20000, max_input_tokens=1024)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)
        bundle, _ = example(max_attempts_per_run=1)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("BUDGET", bundle))

    def test_truncated_reply_with_findings_is_never_zero(self):
        bundle, expected = example()
        evaluation = expected["attempts"][0]
        evaluation["provider_message"]["stop_reason"] = "max_tokens"
        put_response(bundle["attempts"][0], evaluation["provider_message"])
        evaluation.update(receipt=bundle["attempts"][0], model_result=None,
                          decision="REFUSED", reasons=["TRUNCATED"])
        actual = contract.evaluate_injected_bundle(bundle)
        self.assertEqual(actual["reasons"], ["TRUNCATED"])
        self.assertEqual(actual, refused(expected, "TRUNCATED"))

    def test_known_stop_and_provider_schema_have_ordered_reasons(self):
        for fault, reason, keep_message in (
            ("unknown_stop", "PROVIDER_SCHEMA", False),
            ("missing_stop", "PROVIDER_SCHEMA", False),
            ("null_stop", "TERMINAL", True),
            ("tool_block", "PROVIDER_SCHEMA", False),
            ("tool_stop", "TOOL_OR_REFUSAL", True),
            ("empty_text", "MODEL_SCHEMA", True),
        ):
            with self.subTest(fault=fault):
                bundle, expected = example()
                evaluation = expected["attempts"][0]
                message = evaluation["provider_message"]
                if fault == "unknown_stop":
                    message["stop_reason"] = "new_stop"
                elif fault == "missing_stop":
                    message.pop("stop_reason")
                elif fault == "null_stop":
                    message["stop_reason"] = None
                elif fault == "tool_block":
                    message["stop_reason"] = "tool_use"
                    message["content"][0]["type"] = "tool_use"
                elif fault == "tool_stop":
                    message["stop_reason"] = "tool_use"
                else:
                    message["content"][0]["text"] = ""
                put_response(bundle["attempts"][0], message)
                evaluation.update(receipt=bundle["attempts"][0], model_result=None,
                                  provider_message=message if keep_message else None,
                                  decision="REFUSED", reasons=[reason])
                self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, reason))

    def test_model_outcome_requires_correct_findings_cardinality(self):
        for outcome, keep_findings in (
            ("findings", False), ("no_findings", True), ("unable_to_review", False),
            ("unable_to_review", True),
        ):
            with self.subTest(outcome=outcome, keep_findings=keep_findings):
                bundle, expected = example()
                evaluation = expected["attempts"][0]
                result = evaluation["model_result"]
                result["outcome"] = outcome
                if not keep_findings:
                    result["findings"] = []
                replace_model(bundle, evaluation)
                evaluation.update(decision="REFUSED", reasons=["MODEL_SCHEMA"])
                self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "MODEL_SCHEMA"))
        bundle, expected = example()
        evaluation = expected["attempts"][0]
        evaluation["model_result"].update(outcome="no_findings", findings=[])
        replace_model(bundle, evaluation)
        expected.update(raw_findings=[], raw_finding_count=0, unique_finding_count=0)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_finding_must_be_inside_own_chunk(self):
        bundle, expected = example(2)
        evaluation = expected["attempts"][0]
        evaluation["model_result"]["findings"][0]["path"] = bundle["requests"][1]["ranges"][0]["path"]
        replace_model(bundle, evaluation)
        evaluation.update(decision="REFUSED", reasons=["MODEL_SCHEMA"])
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "MODEL_SCHEMA"))

    def test_unapproved_filter_preserves_parsed_refused_evidence(self):
        bundle, expected = example()
        evaluation = expected["attempts"][0]
        evaluation["model_result"]["findings"][0]["filter_reason"] = "unapproved"
        replace_model(bundle, evaluation)
        evaluation.update(decision="REFUSED", reasons=["FILTER_UNAPPROVED"])
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "FILTER_UNAPPROVED"))

    def test_attempts_and_trace_follow_chunk_order(self):
        bundle, expected = example(2)
        bundle["attempts"].reverse()
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)

    def test_partial_capture_keeps_prefix_evidence_after_global_checks(self):
        bundle, expected = example()
        receipt = bundle["attempts"][0]
        raw = bytes.fromhex(receipt["response_hex"])
        receipt.update(
            response_capture="PREFIX_ONLY", transport_state="TIMEOUT", http_framing_complete=False,
            http_status=503,
            captured_prefix_sha256=digest(raw), response_sha256=None,
        )
        budget = bundle["budget_receipt"]
        budget.update(unresolved_attempts=1, provider_reported_input_total=None, provider_reported_output_total=None)
        expected.update(budget_receipt=budget, attempts=[dict(
            receipt=receipt, decision="REFUSED", provider_message=None, model_result=None, reasons=["TRANSPORT"],
        )])
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "TRANSPORT"))
        receipt["retry_not_before_monotonic_ns"] = 1030
        actual = contract.evaluate_injected_bundle(bundle)
        self.assertIsNone(actual["budget_receipt"])
        self.assertEqual(actual, early("TRANSPORT", bundle))

    def test_full_response_requires_its_own_hash(self):
        bundle, _ = example()
        bundle["attempts"][0]["response_sha256"] = "0"*64
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("TRANSPORT", bundle))

    def test_complete_503_retry_uses_original_bytes_and_sorted_attempts(self):
        bundle, expected = example()
        first = copy.deepcopy(bundle["attempts"][0])
        first.update(http_status=503, retry_not_before_monotonic_ns=1030)
        put_response(first, {"synthetic_error": "service unavailable"})
        second = bundle["attempts"][0]
        second.update(provider_retry_index=1, attempt_id=attempt_id(second["stable_request_id"], 1),
                      started_monotonic_ns=1030, finished_monotonic_ns=1040)
        bundle["attempts"] = [second, first]
        budget = bundle["budget_receipt"]
        budget.update(attempts_dispatched=2, provider_reported_input_total=None, provider_reported_output_total=None)
        expected["budget_receipt"] = budget
        expected["attempts"][0]["receipt"] = second
        expected["attempts"].insert(0, dict(
            receipt=first, provider_message=None, model_result=None,
            decision="RETRY_ELIGIBLE_UNDER_INJECTED_POLICY", reasons=["TRANSPORT"],
        ))
        expected["selected_attempt_ids"] = [second["attempt_id"]]
        expected["raw_findings"][0]["attempt_id"] = second["attempt_id"]
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)
        second["started_monotonic_ns"] = 1025
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "RETRY_UNAUTHORIZED"))

    def test_duplicate_receipt_and_provider_id_have_distinct_shells(self):
        bundle, _ = example()
        bundle["attempts"].append(copy.deepcopy(bundle["attempts"][0]))
        self.assertEqual(contract.evaluate_injected_bundle(bundle), early("DUPLICATE", bundle))
        bundle, expected = example(2)
        first, second = expected["attempts"]
        second["provider_message"]["id"] = first["provider_message"]["id"]
        put_response(bundle["attempts"][1], second["provider_message"])
        second["receipt"] = bundle["attempts"][1]
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "DUPLICATE"))

    def test_missing_result_keeps_typed_budget_with_null_findings(self):
        bundle, expected = example()
        bundle["attempts"] = []
        budget = bundle["budget_receipt"]
        budget.update(attempts_dispatched=0, provider_reported_input_total=0, provider_reported_output_total=0)
        expected.update(attempts=[], budget_receipt=budget)
        self.assertEqual(contract.evaluate_injected_bundle(bundle), refused(expected, "MISSING_RESULT"))


def early(reason, bundle=None):
    return output(
        config_sha256=None if bundle is None else digest(canonical(bundle["config"])),
        budget_receipt=None, requests=[], attempts=[], selected_attempt_ids=[],
        internal_status="REFUSED", raw_findings=None, raw_finding_count=None,
        unique_finding_count=None, reasons=[reason],
    )


def refused(expected, reason):
    return dict(
        expected, internal_status="REFUSED", selected_attempt_ids=[], raw_findings=None,
        raw_finding_count=None, unique_finding_count=None, reasons=[reason],
    )


def replace_model(bundle, evaluation):
    message = evaluation["provider_message"]
    message["content"][0]["text"] = canonical(evaluation["model_result"]).decode()
    put_response(bundle["attempts"][0], message)
    evaluation["receipt"] = bundle["attempts"][0]


def compact_layout(bundle, expected):
    """Explicit fixture storage transition; all body/attempt bytes stay intact."""
    bundle, expected = copy.deepcopy((bundle, expected))
    keys = ("owner_config_hex", "acquisition_manifest_hex", "plan_hex", "prompt_hex",
            "policy_hex", "caller_dependency_assertion_hex")
    common = {key: bundle["requests"][0]["split_artifacts"][key] for key in keys}
    bundle.update(bundle_format=2, common_artifacts=common)
    for request in bundle["requests"]:
        assert all(request["split_artifacts"][key] == common[key] for key in keys)
        request["split_artifacts"] = {"framed_request_hex": request["split_artifacts"]["framed_request_hex"]}
    expected.update(result_format=2, common_artifacts=copy.deepcopy(common),
                    requests=copy.deepcopy(bundle["requests"]))
    return bundle, expected


def compact_example(*args, **kwargs):
    return compact_layout(*example(*args, **kwargs))


def compact_early(reason, bundle=None):
    return dict(early(reason, bundle), result_format=2, common_artifacts=None)


class CompactContractTests(unittest.TestCase):
    def test_compact_positive_has_complete_twenty_one_key_trace(self):
        bundle, expected = compact_example()
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), expected)

    def test_supported_flags_atomic_empty_sides_and_utf8_stream(self):
        for case in ("mixed", "split", "stream_blocks"):
            with self.subTest(case=case):
                bundle, expected = compact_example(case=case)
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), expected)

    def test_legacy_false_flag_result_is_preserved_but_compact_refuses(self):
        def false_flag(plan):
            f = plan["inventory"]["files"][0]
            plan["flagged_paths"] = [dict(path=f["path"], old_path=None, flags=["DELETION"])]
        legacy, expected = example(edit_plan=false_flag)
        self.assertEqual(contract.evaluate_injected_bundle(legacy), expected)
        compact, _ = compact_layout(legacy, expected)
        self.assertEqual(contract.evaluate_common_artifact_bundle(compact), compact_early("BINDING", compact))

    def test_atomic_group_split_is_refused_with_full_coverage(self):
        def split_atomic(plan):
            groups = plan["inventory"]["dependencies"]["groups"]
            groups[:] = [dict(kind="ATOMIC", paths=[f["path"] for f in plan["inventory"]["files"]])]
        bundle, _ = compact_example(2, edit_plan=split_atomic)
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_dropped_declared_flags_cannot_hide_workflow_or_deletion(self):
        def drop_flags(plan):
            plan["flagged_paths"] = []
        bundle, _ = compact_example(case="mixed", edit_plan=drop_flags)
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_minimum_overlap_and_progress_are_required(self):
        for fault in ("no_overlap", "nested"):
            def edit(plan):
                first, second = plan["chunks"]
                if fault == "no_overlap":
                    second["items"][0]["start"] = first["items"][0]["end"]
                else:
                    first["items"][0]["end"] = second["items"][0]["end"]
                    second["items"][0]["end"] = 6
            with self.subTest(fault=fault):
                bundle, _ = compact_example(case="split", edit_plan=edit)
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_format_literals_missing_common_and_mixed_fields_are_g0(self):
        for fault in ("absent", "unknown", "boolean", "null", "missing_common", "mixed", "bad_hex", "null_common"):
            with self.subTest(fault=fault):
                bundle, _ = compact_example()
                if fault == "absent":
                    bundle.pop("bundle_format")
                elif fault in ("unknown", "boolean", "null"):
                    bundle["bundle_format"] = {"unknown": 3, "boolean": True, "null": None}[fault]
                elif fault == "missing_common":
                    bundle.pop("common_artifacts")
                elif fault == "mixed":
                    bundle["requests"][0]["split_artifacts"]["plan_hex"] = bundle["common_artifacts"]["plan_hex"]
                elif fault == "bad_hex":
                    bundle["common_artifacts"]["plan_hex"] = "gg"
                else:
                    bundle["common_artifacts"] = None
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("INPUT_SHAPE"))
        self.assertEqual(contract.evaluate_common_artifact_bundle([]), compact_early("INPUT_SHAPE"))

    def test_entry_points_never_auto_detect_or_fallback(self):
        legacy, expected = example()
        compact, _ = compact_layout(legacy, expected)
        self.assertEqual(contract.evaluate_common_artifact_bundle(legacy), compact_early("INPUT_SHAPE"))
        self.assertEqual(contract.evaluate_injected_bundle(compact), early("INPUT_SHAPE"))

    def test_missing_null_config_is_g1_and_raw_failure_precedes_it(self):
        for absent in (True, False):
            bundle, _ = compact_example()
            if absent:
                bundle.pop("config")
            else:
                bundle["config"] = None
            self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("CONFIG_UNQUALIFIED"))
            bundle["requests"][0]["wire_request"]["stream"] = True
            self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("INPUT_SHAPE"))

    def test_streamed_raw_unicode_failure_stays_g0_before_missing_config(self):
        bundle, _ = compact_example()
        bundle.pop("config")
        bundle["requests"][0]["wire_request"]["messages"][0]["content"][0]["text"] = "\ud800"
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("INPUT_SHAPE"))

    def test_common_or_frame_wire_body_binding_failures_have_safe_shell(self):
        for fault in ("common", "frame", "wire", "body"):
            with self.subTest(fault=fault):
                bundle, _ = compact_example(case="stream_blocks")
                request = bundle["requests"][0]
                if fault == "common":
                    bundle["common_artifacts"]["prompt_hex"] = b"other prompt".hex()
                elif fault == "frame":
                    value = request["split_artifacts"]["framed_request_hex"]
                    request["split_artifacts"]["framed_request_hex"] = value[:-2] + "00"
                elif fault == "wire":
                    request["wire_request"]["messages"][0]["content"][0]["text"] += "x"
                    reseal_request(bundle, render_wire=False)
                else:
                    request["body_hex"] += "0a"
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_request_ranges_projection_stays_exact(self):
        bundle, _ = compact_example()
        bundle["requests"][0]["ranges"][0]["end"] -= 1
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_plan_self_hash_and_coverage_stay_required(self):
        bundle, _ = compact_example()
        plan = json.loads(bytes.fromhex(bundle["common_artifacts"]["plan_hex"]))
        plan["plan_sha256"] = "0"*64
        bundle["common_artifacts"]["plan_hex"] = canonical(plan, True).hex()
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))
        def omit(plan):
            plan["chunks"][0]["items"][0]["end"] -= 1
        bundle, _ = compact_example(edit_plan=omit)
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_global_identity_association_transport_and_budget_keep_common_null(self):
        for fault, reason in (("stale", "STALE"), ("attempt", "BINDING"),
                              ("duplicate", "DUPLICATE"), ("capture", "TRANSPORT"), ("budget", "BUDGET")):
            with self.subTest(fault=fault):
                bundle, _ = compact_example()
                if fault == "stale":
                    bundle["current_identity"]["head"] = "4"*40
                elif fault == "attempt":
                    bundle["attempts"][0]["attempt_id"] = "0"*64
                elif fault == "duplicate":
                    bundle["attempts"].append(copy.deepcopy(bundle["attempts"][0]))
                elif fault == "capture":
                    bundle["attempts"][0]["response_sha256"] = "0"*64
                else:
                    bundle["budget_receipt"]["reserved_attempts"] += 1
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early(reason, bundle))

    def test_wire_size_boundary_is_preserved_without_an_extra_cap(self):
        initial, _ = example(case="stream_blocks")
        size = initial["requests"][0]["body_bytes"]
        bundle, expected = compact_example(case="stream_blocks", max_request_bytes=size)
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), expected)
        bundle, _ = compact_example(case="stream_blocks", max_request_bytes=size-1)
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), compact_early("BINDING", bundle))

    def test_tiny_plan_frame_budget_and_exact_frame_boundary(self):
        for target in ("exact", "one_short", "small_header_budget"):
            def budget(plan):
                size = len(render_frame(plan, 0))
                plan["budget"]["max_request_bytes"] = (
                    size if target == "exact" else size-1 if target == "one_short" else 42)
            with self.subTest(target=target):
                bundle, expected = compact_example(edit_plan=budget)
                if target != "exact":
                    expected = compact_early("BINDING", bundle)
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), expected)

    def test_truncation_and_malformed_provider_or_model_retain_common_once(self):
        for fault, reason in (("truncated", "TRUNCATED"), ("provider", "PROVIDER_SCHEMA"), ("model", "MODEL_SCHEMA")):
            with self.subTest(fault=fault):
                bundle, expected = compact_example()
                evaluation = expected["attempts"][0]
                message = evaluation["provider_message"]
                if fault == "truncated":
                    message["stop_reason"] = "max_tokens"
                    put_response(bundle["attempts"][0], message)
                elif fault == "provider":
                    raw = b"{"
                    bundle["attempts"][0].update(response_hex=raw.hex(), response_bytes=len(raw), response_sha256=digest(raw))
                    evaluation["provider_message"] = None
                else:
                    message["content"][0]["text"] = "{"
                    put_response(bundle["attempts"][0], message)
                evaluation.update(receipt=bundle["attempts"][0], model_result=None, decision="REFUSED", reasons=[reason])
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), refused(expected, reason))

    def test_late_finding_refusal_keeps_typed_evidence_and_no_aggregate_findings(self):
        bundle, expected = compact_example(case="split")
        evaluation = expected["attempts"][0]
        evaluation["model_result"]["findings"][0].update(start=6, end=8)
        replace_model(bundle, evaluation)
        evaluation.update(decision="REFUSED", reasons=["MODEL_SCHEMA"])
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), refused(expected, "MODEL_SCHEMA"))

    def test_duplicate_json_keys_refuse_in_both_reply_layers(self):
        for layer, reason in (("provider", "PROVIDER_SCHEMA"), ("model", "MODEL_SCHEMA")):
            with self.subTest(layer=layer):
                bundle, expected = compact_example()
                evaluation = expected["attempts"][0]
                message = evaluation["provider_message"]
                if layer == "provider":
                    raw = canonical(message).replace(b'"role":"assistant"',
                                                     b'"role":"assistant","role":"assistant"')
                    evaluation["provider_message"] = None
                else:
                    message["content"][0]["text"] = message["content"][0]["text"].replace(
                        '"schema":1', '"schema":1,"schema":1')
                    raw = canonical(message)
                receipt = bundle["attempts"][0]
                receipt.update(response_hex=raw.hex(), response_bytes=len(raw), response_sha256=digest(raw))
                evaluation.update(receipt=receipt, model_result=None, decision="REFUSED", reasons=[reason])
                self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), refused(expected, reason))

    def test_valid_no_findings_keeps_zero_counts_and_effective_null(self):
        bundle, expected = compact_example()
        evaluation = expected["attempts"][0]
        evaluation["model_result"].update(outcome="no_findings", findings=[])
        replace_model(bundle, evaluation)
        expected.update(raw_findings=[], raw_finding_count=0, unique_finding_count=0)
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), expected)

    def test_prefix_error_receipt_retains_common_and_is_not_salvaged(self):
        bundle, expected = compact_example()
        receipt = bundle["attempts"][0]
        raw = bytes.fromhex(receipt["response_hex"])
        receipt.update(response_capture="PREFIX_ONLY", transport_state="TIMEOUT", http_framing_complete=False,
                       http_status=503, captured_prefix_sha256=digest(raw), response_sha256=None)
        bundle["budget_receipt"].update(unresolved_attempts=1, provider_reported_input_total=None,
                                        provider_reported_output_total=None)
        expected.update(budget_receipt=bundle["budget_receipt"], attempts=[dict(
            receipt=receipt, provider_message=None, model_result=None, decision="REFUSED", reasons=["TRANSPORT"])])
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), refused(expected, "TRANSPORT"))

    def test_complete_503_retry_preserves_compact_request_identity(self):
        bundle, expected = compact_example()
        first = copy.deepcopy(bundle["attempts"][0])
        first.update(http_status=503, retry_not_before_monotonic_ns=1030)
        put_response(first, {"synthetic_error": "service unavailable"})
        second = bundle["attempts"][0]
        second.update(provider_retry_index=1, attempt_id=attempt_id(second["stable_request_id"], 1),
                      started_monotonic_ns=1030, finished_monotonic_ns=1040)
        bundle["attempts"] = [second, first]
        bundle["budget_receipt"].update(attempts_dispatched=2, provider_reported_input_total=None,
                                        provider_reported_output_total=None)
        expected["budget_receipt"] = bundle["budget_receipt"]
        expected["attempts"][0]["receipt"] = second
        expected["attempts"].insert(0, dict(receipt=first, provider_message=None, model_result=None,
                                          decision="RETRY_ELIGIBLE_UNDER_INJECTED_POLICY", reasons=["TRANSPORT"]))
        expected["selected_attempt_ids"] = [second["attempt_id"]]
        expected["raw_findings"][0]["attempt_id"] = second["attempt_id"]
        self.assertEqual(contract.evaluate_common_artifact_bundle(bundle), expected)


if __name__ == "__main__":
    unittest.main()
