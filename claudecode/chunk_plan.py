"""Disconnected MODEL_ONLY planner: synthetic byte coverage, never a security gate.

Only plan(inventory, blobs, budget), serialize(plan, chunk_id), and
verify(ledger, inventory) are public. All inputs are explicit in-memory values.
No Git/compare discovery, filesystem, environment, provider, tokenizer or model
access is performed. Caller-supplied dependency closure is an assertion, not
inferred or authenticated. Byte budgets bound framed DATA ONLY, excluding any later instructions, and do
not establish token or cost budgets. compare_file_count is self-asserted; the
challenge is run-level only, not a per-chunk instruction-retention proof.

Synthetic hard ceilings:128 files,2MiB total raw AND logical base/head referenced
bytes,1MiB framed-data bytes/request,128 chunks. Required max_files/max_total_bytes
caller limits may be smaller. Shared blobs count once for raw storage and once
PER reference for logical work. Encoded plan hex is capped before decoding;
group/item counts are bounded. These are local refusal limits, not real service
budgets; Python/JSON allocation multipliers, caller preallocation and every CPU
or memory effect are not solved. Existing packing/rebuild costs remain bounded
only within this intentionally small synthetic domain.

Schema 3 (incompatible with schema1/2 inventory/plans/ledgers) supports A/M/D/R, regular UTF-8 blobs, and 100644/100755 modes. Modified
and renamed entries cover FULL base and head, deletions cover base, additions
cover head (including zero-byte blobs). Symlinks/submodules/non-UTF8 refuse.
Every byte is REVIEWED_RAW; no equivalence, exclusions or content markers apply.
ATOMIC groups are indivisible caller-supplied closures; singleton STREAM groups
may split with a caller-supplied UTF-8-safe overlap. No implicit code grouping.

Plans carry raw blobs as hex for canonical JSON data transport, not summaries.
Serialized requests use length-framed canonical headers and exact payload bytes.
Hostile headers/delimiters/instructions in payload remain data; framing proves
neither model comprehension nor resistance to prompt injection. STUB_COMPLETED
results and verify.ok mean synthetic ledger consistency only. No caller/gate is
wired, and no authenticity, signing, runtime or production admission is claimed.
"""

import hashlib
import json
import re


class Refused(ValueError):
    """A closed, value-free unsupported or inconsistent input reason."""


def _need(condition, reason):
    if not condition:
        raise Refused(reason)


def _keys(value, names):
    _need(type(value) is dict and set(value) == set(names.split()), "schema refused")


def _integer(value, minimum=0):
    _need(type(value) is int and value >= minimum, "integer refused")


def _text(value):
    _need(type(value) is str and 0 < len(value) <= 1024, "text refused")
    _need(not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value), "text refused")


def _hex(value, length):
    _need(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None,
          "digest refused")


def _path(value):
    _text(value)
    _need(not value.startswith("/") and "\\" not in value and
          all(p not in ("", ".", "..") for p in value.split("/")), "path refused")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _frame(raw):
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def _identity(identity):
    _keys(identity, "repository pr base head planner_sha prompt_sha256 policy_sha256 model run_id attempt challenge")
    _text(identity["repository"])
    _need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", identity["repository"]) is not None,
          "repository refused")
    _integer(identity["pr"], 1)
    _integer(identity["attempt"], 1)
    for k in ("base", "head", "planner_sha"):
        _hex(identity[k], 40)
    _need(identity["base"] != identity["head"], "compare refused")
    for k in ("prompt_sha256", "policy_sha256", "challenge"):
        _hex(identity[k], 64)
    for k in ("model", "run_id"):
        _text(identity[k])


def _descriptor(descriptor, blobs):
    _keys(descriptor, "oid bytes sha256 mode")
    _hex(descriptor["oid"], 40)
    _hex(descriptor["sha256"], 64)
    _integer(descriptor["bytes"])
    _need(descriptor["mode"] in ("100644", "100755"), "unsupported mode")
    _need(descriptor["oid"] in blobs, "missing blob")
    raw = blobs[descriptor["oid"]]
    _need(type(raw) is bytes, "blob type refused")
    _need(len(raw) == descriptor["bytes"] and _sha(raw) == descriptor["sha256"], "blob pin refused")
    oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    _need(oid == descriptor["oid"], "blob oid refused")
    valid = True
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        valid = False
    _need(valid and b"\0" not in raw, "unsupported encoding")



def _budget(budget):
    _keys(budget, "max_request_bytes max_chunks overlap_bytes max_files max_total_bytes")
    for name in budget:
        _integer(budget[name], 1)
    _need(budget["overlap_bytes"] < budget["max_request_bytes"], "budget refused")
    _need(budget["max_files"] <= 128 and budget["max_total_bytes"] <= 2097152 and
          budget["max_request_bytes"] <= 1048576 and budget["max_chunks"] <= 128,
          "resource budget refused")


def _resource_bounds(inventory, blobs, budget):
    # Refuse before hashing, JSON/hex duplication, UTF8 boundary arrays or packing.
    _need(len(inventory["files"]) <= budget["max_files"] and len(blobs) <= 2 * budget["max_files"],
          "resource files refused")
    total_raw = 0
    for raw in blobs.values():
        _need(type(raw) is bytes, "blob type refused")
        total_raw += len(raw)
        _need(total_raw <= budget["max_total_bytes"], "resource bytes refused")
    # Logical base/head bytes count EACH reference, even shared OIDs, to bound work.
    logical = 0
    for f in inventory["files"]:
        _keys(f, "path old_path status base head")
        for side in ("base", "head"):
            if f[side] is not None:
                _keys(f[side], "oid bytes sha256 mode")
                _integer(f[side]["bytes"])
                logical += f[side]["bytes"]
                _need(logical <= budget["max_total_bytes"], "resource bytes refused")


def _validate(inventory, blobs, budget):
    _keys(inventory, "schema identity compare_file_count files dependencies")
    _need(type(inventory["schema"]) is int and inventory["schema"] == 3, "schema refused")
    _identity(inventory["identity"])
    _budget(budget)
    _need(type(blobs) is dict, "blob map refused")
    _need(type(inventory["files"]) is list and inventory["files"], "empty inventory refused")
    _resource_bounds(inventory, blobs, budget)
    _integer(inventory["compare_file_count"], 1)
    _need(inventory["compare_file_count"] == len(inventory["files"]), "self-asserted count mismatch")
    paths, used, old_paths = set(), set(), set()
    for f in inventory["files"]:
        _keys(f, "path old_path status base head")
        _path(f["path"])
        _need(f["path"] not in paths, "duplicate path")
        paths.add(f["path"])
        _need(f["status"] in ("A", "M", "D", "R"), "unsupported status")
        if f["status"] == "R":
            _path(f["old_path"])
            _need(f["old_path"] != f["path"] and f["old_path"] not in old_paths, "rename refused")
            old_paths.add(f["old_path"])
        else:
            _need(f["old_path"] is None, "rename refused")
        for side in ("base", "head"):
            required = (side == "base" and f["status"] != "A") or (side == "head" and f["status"] != "D")
            if required:
                _descriptor(f[side], blobs)
                used.add(f[side]["oid"])
            else:
                _need(f[side] is None, "side refused")
    _need(not (old_paths & paths), "rename collision")
    _need(set(blobs) == used, "foreign blob")
    deps = inventory["dependencies"]
    _keys(deps, "status groups")
    _need(deps["status"] == "SUPPLIED_COMPLETE", "unresolved dependencies")
    _need(type(deps["groups"]) is list, "groups refused")
    _need(len(deps["groups"]) <= budget["max_files"], "resource groups refused")
    grouped = []
    for group in deps["groups"]:
        _keys(group, "kind paths")
        _need(group["kind"] in ("ATOMIC", "STREAM"), "group kind refused")
        _need(type(group["paths"]) is list and group["paths"], "groups refused")
        _need(len(grouped) + len(group["paths"]) <= budget["max_files"], "resource groups refused")
        for path in group["paths"]:
            _path(path)
        _need(group["kind"] != "STREAM" or len(group["paths"]) == 1, "stream closure refused")
        grouped.extend(group["paths"])
    _need(len(grouped) == len(paths) and len(set(grouped)) == len(grouped) and set(grouped) == paths,
          "group coverage refused")


def _items(files, paths):
    items = []
    for path in sorted(paths):
        f = files[path]
        for side in ("base", "head"):
            if f[side] is not None:
                items.append(dict(path=path, side=side, oid=f[side]["oid"], start=0, end=f[side]["bytes"]))
    return items



def _file_flags(f):
    flags = []
    if f["path"].startswith(".github/") or (f["old_path"] or "").startswith(".github/"):
        flags.append("WORKFLOW")
    if f["status"] in ("D", "R"):
        flags.append({"D": "DELETION", "R": "RENAME"}[f["status"]])
    if f["base"] is not None and f["head"] is not None and f["base"]["mode"] != f["head"]["mode"]:
        flags.append("MODE_CHANGE")
    return flags


def _flagged_paths(inventory):
    return [dict(path=f["path"], old_path=f["old_path"], flags=_file_flags(f)) for f in sorted(inventory["files"], key=lambda f: f["path"]) if _file_flags(f)]


def _request(inventory, blobs, chunk_id, items):
    envelope = dict(schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                    identity=inventory["identity"], chunk_id=chunk_id, item_count=len(items))
    parts = [b"C003-INERT-BYTE-PLAN-3\n", _frame(_json(envelope))]
    files = {f["path"]: f for f in inventory["files"]}
    for item in items:
        f = files[item["path"]]
        desc = f[item["side"]]
        flags = _file_flags(f)
        header = dict(item, old_path=f["old_path"], status=f["status"], mode=desc["mode"],
                      size=desc["bytes"], sha256=desc["sha256"], disposition="REVIEWED_RAW", flags=flags)
        parts.extend([_frame(_json(header)), _frame(blobs[item["oid"]][item["start"]:item["end"]])])
    return b"".join(parts)


def _build(inventory, blobs, budget):
    _validate(inventory, blobs, budget)
    # Canonical ordering is independent of supplied list/dict insertion order.
    inventory = json.loads(_json(inventory))
    inventory["files"].sort(key=lambda f: f["path"])
    groups = inventory["dependencies"]["groups"]
    for group in groups:
        group["paths"].sort()
    groups.sort(key=lambda g: g["paths"])
    files = {f["path"]: f for f in inventory["files"]}
    chunks, pending = [], []
    cap = budget["max_request_bytes"]

    def fits(items):
        return len(_request(inventory, blobs, len(chunks), items)) <= cap

    def flush():
        if pending:
            _need(len(chunks) < budget["max_chunks"], "chunk count exceeded")
            request = _request(inventory, blobs, len(chunks), pending)
            _need(len(request) <= cap, "flush byte cap refused")
            chunks.append(dict(id=len(chunks), items=list(pending), request_bytes=len(request),
                               request_sha256=_sha(request)))
            pending.clear()

    for group in groups:
        items = _items(files, group["paths"])
        if fits(pending + items):
            pending.extend(items)
            continue
        flush()
        if fits(items):
            pending.extend(items)
            continue
        _need(group["kind"] == "STREAM", "atomic group over budget")
        for item in items:
            raw = blobs[item["oid"]]
            # Boundary list includes zero and all complete UTF-8 codepoints.
            boundaries = [0]
            for char in raw.decode("utf-8"):
                boundaries.append(boundaries[-1] + len(char.encode("utf-8")))
            start = 0
            while True:
                low, high, best = 0, len(boundaries) - 1, None
                while low <= high:
                    middle = (low + high) // 2
                    end = boundaries[middle]
                    candidate = dict(item, start=start, end=end)
                    if end >= start and fits([candidate]):
                        best = end
                        low = middle + 1
                    elif end < start:
                        low = middle + 1
                    else:
                        high = middle - 1
                _need(best is not None and (best > start or len(raw) == 0), "request over budget")
                pending.append(dict(item, start=start, end=best))
                flush()
                if best == len(raw):
                    break
                # Start at/before the requested overlap, on a UTF-8 boundary.
                target = best - budget["overlap_bytes"]
                next_start = max((b for b in boundaries if b <= target), default=0)
                _need(next_start > start, "overlap prevents progress")
                start = next_start
    flush()
    planned = dict(schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                   inventory=inventory, blobs={oid: raw.hex() for oid, raw in blobs.items()},
                   budget=dict(budget), chunks=chunks, flagged_paths=_flagged_paths(inventory))
    planned["plan_sha256"] = _sha(_json(planned))
    return planned


def plan(inventory, blobs, budget):
    """Plan explicit synthetic inventory and full blob bytes under a byte cap.

    Raises Refused on unsupported/invalid input. Identity and compare inventory
    are caller assertions, not live-GitHub/Git verification or authentication.
    """
    return _guarded(_build, inventory, blobs, budget)


def _guarded(function, *args):
    reason = None
    try:
        return function(*args)
    except Refused as error:
        reason = str(error)
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
        reason = "malformed input"
    # Do not return parser/type exceptions or their value-carrying context.
    raise Refused(reason)


def _check_plan(planned):
    _keys(planned, "schema scope qualification gate_wired inventory blobs budget chunks flagged_paths plan_sha256")
    _need(type(planned["schema"]) is int and planned["schema"] == 3, "schema refused")
    _need(planned["scope"] == "MODEL_ONLY" and planned["qualification"] == "NOT_ADMITTED" and
          planned["gate_wired"] is False, "qualification refused")
    _hex(planned["plan_sha256"], 64)
    _need(type(planned["flagged_paths"]) is list and len(planned["flagged_paths"]) <= 128, "resource flags refused")
    for row in planned["flagged_paths"]:
        _keys(row, "path old_path flags"); _path(row["path"])
        if row["old_path"] is not None: _path(row["old_path"])
        _need(type(row["flags"]) is list and len(row["flags"]) <= 4 and
              all(flag in ("WORKFLOW", "DELETION", "RENAME", "MODE_CHANGE") for flag in row["flags"]), "flags refused")
    _budget(planned["budget"])
    _need(type(planned["blobs"]) is dict, "blob map refused")
    _need(len(planned["blobs"]) <= 2 * planned["budget"]["max_files"], "resource files refused")
    _need(type(planned["chunks"]) in (list, tuple) and len(planned["chunks"]) <= planned["budget"]["max_chunks"],
          "resource chunks refused")
    for chunk in planned["chunks"]:
        _keys(chunk, "id items request_bytes request_sha256")
        _need(type(chunk["items"]) in (list, tuple) and len(chunk["items"]) <= 2 * planned["budget"]["max_files"],
              "resource items refused")
        _integer(chunk["id"]); _integer(chunk["request_bytes"]); _hex(chunk["request_sha256"], 64)
        _need(chunk["id"] < 128 and chunk["request_bytes"] <= 1048576, "resource chunk fields refused")
        for item in chunk["items"]:
            _keys(item, "path side oid start end"); _path(item["path"]); _hex(item["oid"], 40)
            _need(item["side"] in ("base", "head"), "side refused")
            _integer(item["start"]); _integer(item["end"])
            _need(item["start"] <= 2097152 and item["end"] <= 2097152, "resource range refused")
    hex_total = 0
    blobs = {}
    for oid, value in planned["blobs"].items():
        _hex(oid, 40)
        _need(type(value) is str and len(value) % 2 == 0, "blob hex refused")
        hex_total += len(value)
        _need(hex_total <= 2 * planned["budget"]["max_total_bytes"], "resource bytes refused")
        _need(re.fullmatch("[0-9a-f]*", value) is not None, "blob hex refused")
        blobs[oid] = bytes.fromhex(value)
    expected = _build(planned["inventory"], blobs, planned["budget"])
    _need(_json(expected) == _json(planned), "plan binding refused")
    return expected, blobs


def _serialize(planned, chunk_id):
    planned, blobs = _check_plan(planned)
    _integer(chunk_id)
    _need(chunk_id < len(planned["chunks"]), "chunk refused")
    return _request(planned["inventory"], blobs, chunk_id, planned["chunks"][chunk_id]["items"])


def serialize(planned, chunk_id):
    """Return one exact length-framed request after rederiving the entire plan."""
    return _guarded(_serialize, planned, chunk_id)



def _coverage_proof(p, blobs, inventory):
    """Independent interval/request proof: deliberately never calls _build/_request.

    Equality with a second planner invocation is NOT this proof. Required sides,
    raw-range bytes, framing, caps and intervals are derived independently here.
    The JSON/digest/type helpers are shared, not builder validation/control flow.
    Explicit inventory descriptors are independently bound to decoded raw bytes.
    """
    inv = inventory  # Explicit verify input, never the builder's inventory echo.
    _keys(inv, "schema identity compare_file_count files dependencies")
    _need(type(inv["schema"]) is int and inv["schema"] == 3, "schema refused")
    _identity(inv["identity"])
    _need(_json(p["inventory"]["identity"]) == _json(inv["identity"]), "independent identity refused")
    _budget(p["budget"])
    _need(type(inv["files"]) is list and 0 < len(inv["files"]) <= p["budget"]["max_files"],
          "independent input files refused")
    _integer(inv["compare_file_count"], 1)
    _need(inv["compare_file_count"] == len(inv["files"]), "independent input count refused")
    _need(type(blobs) is dict and len(blobs) <= 2 * p["budget"]["max_files"], "independent input blobs refused")
    raw_total = 0
    for raw in blobs.values():
        _need(type(raw) is bytes, "independent input blob type refused")
        raw_total += len(raw)
        _need(raw_total <= p["budget"]["max_total_bytes"], "independent input bytes refused")
    required, ranges, locations, files, used, old_paths = {}, {}, {}, {}, set(), set()
    logical = 0
    derived_flags, file_flags = [], {}
    for f in inv["files"]:
        _keys(f, "path old_path status base head")
        _path(f["path"])
        _need(f["path"] not in files, "independent input path refused")
        files[f["path"]] = f
        _need(f["status"] in ("A", "M", "D", "R"), "independent input status refused")
        if f["status"] == "R":
            _path(f["old_path"])
            _need(f["old_path"] != f["path"] and f["old_path"] not in old_paths, "independent input rename refused")
            old_paths.add(f["old_path"])
        else:
            _need(f["old_path"] is None, "independent input rename refused")
        sides = {"A": ("head",), "D": ("base",), "M": ("base", "head"), "R": ("base", "head")}[f["status"]]
        for side in ("base", "head"):
            desc = f[side]
            if side not in sides:
                _need(desc is None, "independent input sides refused")
                continue
            _need(type(desc) is dict and set(desc) == {"oid", "bytes", "sha256", "mode"},
                  "independent input descriptor refused")
            _hex(desc["oid"], 40); _hex(desc["sha256"], 64); _integer(desc["bytes"])
            _need(desc["mode"] in ("100644", "100755"), "independent input descriptor refused")
            logical += desc["bytes"]
            _need(logical <= p["budget"]["max_total_bytes"], "independent input bytes refused")
            _need(desc["oid"] in blobs, "independent input blob missing")
            raw = blobs[desc["oid"]]
            _need(len(raw) == desc["bytes"] and _sha(raw) == desc["sha256"], "independent input blob pin refused")
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            _need(oid == desc["oid"], "independent input blob oid refused")
            utf8 = True
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                utf8 = False
            _need(utf8 and b"\0" not in raw, "independent input encoding refused")
            used.add(desc["oid"])
            key = (f["path"], side)
            required[key] = desc
            ranges[key], locations[key] = [], set()
        flags = []
        if f["path"].startswith(".github/") or (f["old_path"] or "").startswith(".github/"):
            flags.append("WORKFLOW")
        if f["status"] in ("D", "R"):
            flags.append({"D": "DELETION", "R": "RENAME"}[f["status"]])
        if f["base"] is not None and f["head"] is not None and f["base"]["mode"] != f["head"]["mode"]:
            flags.append("MODE_CHANGE")
        file_flags[f["path"]] = flags
        if flags:
            derived_flags.append(dict(path=f["path"], old_path=f["old_path"], flags=flags))
    derived_flags.sort(key=lambda row: row["path"])
    _need(_json(p["flagged_paths"]) == _json(derived_flags), "independent flags refused")
    _need(not (old_paths & set(files)), "independent input rename refused")
    _need(set(blobs) == used, "independent input blob set refused")
    deps = inv["dependencies"]
    _keys(deps, "status groups")
    _need(deps["status"] == "SUPPLIED_COMPLETE" and type(deps["groups"]) is list and
          len(deps["groups"]) <= p["budget"]["max_files"], "independent input groups refused")
    grouped = []
    for group in deps["groups"]:
        _keys(group, "kind paths")
        _need(group["kind"] in ("ATOMIC", "STREAM") and type(group["paths"]) is list and
              0 < len(group["paths"]) <= p["budget"]["max_files"] - len(grouped), "independent input groups refused")
        _need(group["kind"] != "STREAM" or len(group["paths"]) == 1, "independent input groups refused")
        for path in group["paths"]:
            _path(path)
        grouped.extend(group["paths"])
    _need(len(grouped) == len(files) and len(set(grouped)) == len(grouped) and set(grouped) == set(files),
          "independent input groups refused")
    _need(type(p["chunks"]) is list and 0 < len(p["chunks"]) <= p["budget"]["max_chunks"],
          "independent chunks refused")
    seen = set()
    def frame(value):
        return str(len(value)).encode("ascii") + b":" + value + b","
    for ordinal, chunk in enumerate(p["chunks"]):
        _keys(chunk, "id items request_bytes request_sha256")
        _integer(chunk["id"])
        _need(chunk["id"] == ordinal, "independent chunk order refused")
        _need(type(chunk["items"]) is list and chunk["items"], "independent items refused")
        envelope = dict(schema=3, scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                        identity=inv["identity"], chunk_id=ordinal, item_count=len(chunk["items"]))
        parts = [b"C003-INERT-BYTE-PLAN-3\n", frame(_json(envelope))]
        for item in chunk["items"]:
            _keys(item, "path side oid start end")
            _path(item["path"])
            _need(type(item["side"]) is str, "independent side refused")
            key = (item["path"], item["side"])
            _need(key in required, "independent foreign item refused")
            desc = required[key]
            _need(item["oid"] == desc["oid"], "independent blob refused")
            _integer(item["start"]); _integer(item["end"])
            start, end, size = item["start"], item["end"], desc["bytes"]
            _need(0 <= start <= end <= size and (start < end or size == 0), "independent range refused")
            marker = (key, start, end)
            _need(marker not in seen, "independent duplicate range refused")
            seen.add(marker); ranges[key].append((start, end)); locations[key].add(ordinal)
            value = blobs[desc["oid"]][start:end]
            utf8 = True
            try:
                value.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                utf8 = False
            _need(utf8, "independent utf8 range refused")
            f = files[item["path"]]
            flags = file_flags[item["path"]]
            header = dict(item, old_path=f["old_path"], status=f["status"], mode=desc["mode"],
                          size=size, sha256=desc["sha256"], disposition="REVIEWED_RAW", flags=flags)
            parts.extend((frame(_json(header)), frame(value)))
        request = b"".join(parts)
        _need(len(request) <= p["budget"]["max_request_bytes"], "independent byte cap refused")
        _integer(chunk["request_bytes"])
        _hex(chunk["request_sha256"], 64)
        _need(chunk["request_bytes"] == len(request) and chunk["request_sha256"] == _sha(request),
              "independent request pin refused")
    _need(all(ranges.values()), "independent side coverage refused")
    for key, intervals in ranges.items():
        size = required[key]["bytes"]
        if size == 0:
            _need(intervals == [(0, 0)], "independent empty coverage refused")
            continue
        covered = 0
        for index, (start, end) in enumerate(sorted(intervals)):
            _need(start <= covered, "independent interval coverage refused")
            if index:
                _need(covered - start >= p["budget"]["overlap_bytes"] and end > covered,
                      "independent overlap refused")
            covered = end
        _need(covered == size, "independent interval coverage refused")
    for group in inv["dependencies"]["groups"]:
        if group["kind"] == "ATOMIC":
            chunks = {n for key in required if key[0] in group["paths"] for n in locations[key]}
            _need(len(chunks) == 1, "independent atomic closure refused")
    return derived_flags


def verify(ledger, inventory):
    """Validate an ordered STUB ledger, never an actual security-review result.

    A match binds supplied bytes/identities/ranges, not their authority or model
    comprehension. Malformed or failed stub results cannot become zero findings.
    Budget is the ledger plan's own assertion within synthetic ceilings, not an
    independently supplied verifying-caller budget or approved service limit.
    """
    reason = None
    findings = []
    flagged_paths = None
    try:
        _keys(ledger, "schema plan results current_head")
        _need(type(ledger["schema"]) is int and ledger["schema"] == 3, "schema refused")
        p = ledger["plan"]
        p, blobs = _check_plan(p)
        expected = _build(inventory, blobs, p["budget"])
        _need(_json(expected) == _json(p), "inventory binding refused")
        p = expected
        flagged_paths = _coverage_proof(p, blobs, inventory)
        _need(ledger["current_head"] == inventory["identity"]["head"], "head moved")
        _need(type(ledger["results"]) is list and len(ledger["results"]) == len(p["chunks"]),
              "result count refused")
        response_ids = set()
        union = {}
        for chunk, result in zip(p["chunks"], ledger["results"]):
            _keys(result, "chunk_id plan_sha256 request_sha256 status identity response_id findings")
            _integer(result["chunk_id"])
            _need(result["chunk_id"] == chunk["id"], "result order refused")
            _need(result["plan_sha256"] == p["plan_sha256"] and
                  result["request_sha256"] == chunk["request_sha256"], "result binding refused")
            _need(result["status"] == "STUB_COMPLETED", "stub failed")
            _identity(result["identity"])
            _need(_json(result["identity"]) == _json(inventory["identity"]), "result identity refused")
            _text(result["response_id"])
            _need(result["response_id"] not in response_ids, "duplicate response")
            response_ids.add(result["response_id"])
            _need(type(result["findings"]) is list, "findings refused")
            for finding in result["findings"]:
                _keys(finding, "path side start end severity rule message filter_reason")
                _path(finding["path"])
                _need(finding["side"] in ("base", "head"), "finding side refused")
                _integer(finding["start"])
                _integer(finding["end"])
                _need(finding["start"] < finding["end"], "finding range refused")
                _need(any(i["path"] == finding["path"] and i["side"] == finding["side"] and
                          i["start"] <= finding["start"] < finding["end"] <= i["end"]
                          for i in chunk["items"]), "foreign finding")
                _need(finding["severity"] in ("P0", "P1", "P2", "P3"), "finding severity refused")
                _text(finding["rule"])
                _text(finding["message"])
                if finding["filter_reason"] is not None:
                    _text(finding["filter_reason"])
                # Filtered findings remain visible; the prototype has no filter.
                union[_json(finding)] = finding
        findings = [union[k] for k in sorted(union)]
    except Refused as error:
        reason = str(error)
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
        reason = "malformed ledger"
    return dict(schema=3, ok=reason is None, reasons=[] if reason is None else [reason],
                scope="MODEL_ONLY", qualification="NOT_ADMITTED", gate_wired=False,
                security_review_completed=False, provider_verified=False,
                coverage="SYNTHETIC_BYTES_ONLY", stub_findings=findings if reason is None else None,
                flagged_paths=flagged_paths if reason is None else None)
