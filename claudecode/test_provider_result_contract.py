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


def example(chunk_count=1, **limit_overrides):
    """Manually compose source-format data without calling either parent module."""
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
    raw = b"abc\n"
    oid = git_oid("blob", raw)
    desc = dict(oid=oid, bytes=len(raw), sha256=digest(raw), mode="100644")
    paths = [f"file-{index}-λ.txt" for index in range(chunk_count)]
    files = [dict(path=path, old_path=None, status="A", base=None, head=desc) for path in paths]
    blobs = {oid: raw.hex()}
    prompt = "Synthetic prompt α".encode()
    policy = b"Synthetic policy"
    roots = dict(
        repository="synthetic/example", pr=1, base_tip="1"*40, merge_base="1"*40,
        comparison_base="1"*40, head="2"*40,
    )
    acquisition = dict(
        schema=1, scope="MODEL_ONLY", qualification="NOT_ADMITTED",
        acquisition_authenticated=False, gate_wired=False, identity=roots,
        trust="CALLER_SUPPLIED_UNAUTHENTICATED_UNFRESH", object_format="sha1",
        ancestry=[roots["head"], roots["base_tip"]], pages="SELF_CONSISTENT_AND_EQUAL_TO_TREE_SET",
        closure="NOT_EVALUATED", unchanged_context="NOT_ACQUIRED", declared_changed_files=chunk_count,
        files=files, blobs=blobs, raw_bytes=len(raw), logical_bytes=len(raw)*chunk_count,
        limits=dict(
            max_files=128, max_total_bytes=2097152, max_objects=2048, max_commits=128,
            max_pages=128, max_depth=32, max_structural_bytes=262144,
            max_tree_entries=8192, max_object_bytes=4194304,
        ),
        verified_objects=sorted([roots["base_tip"], roots["head"], oid]),
    )
    groups = [dict(kind="STREAM", paths=[path]) for path in paths]
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
    frames, chunks = [], []
    for index, path in enumerate(paths):
        item = dict(path=path, side="head", oid=oid, start=0, end=4)
        envelope = dict(
            schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
            identity=identity, chunk_id=index, item_count=1,
        )
        header = dict(
            item, old_path=None, status="A", mode="100644", size=4, sha256=digest(raw),
            disposition="REVIEWED_RAW", flags=[],
        )
        frame = (
            b"C003-INERT-BYTE-PLAN-3\n" + netstring(canonical(envelope, True))
            + netstring(canonical(header, True)) + netstring(raw)
        )
        frames.append(frame)
        chunks.append(dict(id=index, items=[item], request_bytes=len(frame), request_sha256=digest(frame)))
    plan = dict(
        schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
        inventory=dict(
            schema=3, identity=identity, compare_file_count=chunk_count, files=files,
            dependencies=dict(status="SUPPLIED_COMPLETE", groups=groups),
        ),
        blobs=blobs,
        budget=dict(
            max_request_bytes=max(map(len, frames)), max_chunks=4, overlap_bytes=1,
            max_files=chunk_count, max_total_bytes=chunk_count*len(raw),
        ),
        chunks=chunks, flagged_paths=[],
    )
    plan["plan_sha256"] = digest(canonical(plan, True))
    current = dict(roots, workflow_run_id=identity["run_id"], workflow_attempt=1)
    requests, receipts, evaluations, trace = [], [], [], []
    for index, (frame, chunk) in enumerate(zip(frames, chunks)):
        binding = dict(
            current, acquisition_manifest_sha256=digest(canonical(acquisition)),
            acquisition_source_sha=ACQUISITION, planner_source_sha=PLANNER, plan_schema=3,
            plan_sha256=plan["plan_sha256"], chunk_id=index, chunk_count=chunk_count,
            run_challenge=identity["challenge"], prompt_sha256=digest(prompt), policy_sha256=digest(policy),
            config_sha256=digest(canonical(config)), roots_authenticated=False,
            acquisition_closure="NOT_EVALUATED", plan_dependency_assertion="CALLER_ASSERTED_UNVERIFIED",
            caller_dependency_assertion_sha256=digest(canonical(caller)), schema3_identity_model=model,
        )
        ranges = [dict(chunk["items"][0], old_path=None, blob_sha256=digest(raw))]
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
        finding = dict(
            path=paths[index], side="head", start=0, end=3, severity="P3",
            rule="synthetic-rule", message="Injected finding", filter_reason=None,
        )
        result = dict(schema=1, outcome="findings", findings=[finding], limitations=[])
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
        trace.append(dict(chunk_id=index, attempt_id=aid, model_finding_index=0, finding=finding))
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
        raw_finding_count=chunk_count, unique_finding_count=chunk_count, reasons=[],
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


class ProviderResultContractTests(unittest.TestCase):
    def test_injected_finding_has_complete_nonadmitted_trace(self):
        bundle, expected = example()
        self.assertEqual(contract.evaluate_injected_bundle(bundle), expected)


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


if __name__ == "__main__":
    unittest.main()
