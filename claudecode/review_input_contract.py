"""Pure disconnected SHA-1 Git-object consistency model, never acquisition proof.

Public seam: validate_acquisition(trust_root, objects, ancestry, pages,
declared_changed_files, limits), plus Refused. All inputs are explicit exact
built-ins. Roots repository/pr/base_tip/head are caller-supplied, unauthenticated
and unfresh. A consistent forged world verifies against those roots only.
Fixed MODEL_ONLY/NOT_ADMITTED labels cannot become authentication or gate output.

Objects map lowercase SHA-1 -> {type: commit|tree|blob, body: bytes}. Every
supplied object is hash-checked before use; unused objects refuse. SHA-1 is the
strength of this chain, not a signature. SHA-256 Git repositories are unsupported.
Commits support exactly tree, zero or more distinct parent lines (at most 32),
author, committer, blank line, UTF-8 message; no NUL, encoding, signature or extra
headers. Identities use printable ASCII name/email, decimal timestamp <=12 digits,
and numeric timezone. Trees use canonical Git ordering, octal modes, UTF-8
single-component names (not empty, dot, dotdot, slash or NUL), and 20-byte OIDs.
Only regular 100644/100755 files and 40000 directories can change; other changed
modes refuse the entire input. No path/extension/content-marker pruning occurs.

An explicit verified parent-link witness goes head first, base_tip last. Only
this ancestor domain is supported: base_tip=merge_base=comparison_base, recorded
as distinct fields. Equal-OID subtrees are skipped, including their objects;
unchanged context is NOT_ACQUIRED, closure NOT_EVALUATED. Changed A/M/D sides
are complete UTF-8/no-NUL blobs. Renames require one tree D(old)+A(new); pages
consume each expanded path once. File/directory replacements are D+As or Ds+A.
Pages are normalized synthetic REST-shaped data, NOT captured GitHub provenance.
No closure/policy parameter, dependency sufficiency or provider contract exists.

Manifest files literally match schema3 {path,old_path,status,base,head}; each
side is {oid,bytes,sha256,mode}, bytes meaning byte length. blobs maps OID to
FULL hex derived from verified changed objects. A future schema3 identity.base
would map comparison_base by documentation only; no planner import/conversion.

Required limits have exactly the keys in _CEILINGS, each 1..that ceiling. Bounds
are synthetic assertions, NOT production budgets or resource containment. Raw
changed blob bytes count each OID once; logical bytes count every side reference.
Both have 2MiB ceilings; normalized files <=128 (rename D+A footprints <=256).
Other ceilings bound object bytes/count, witness commits, pages, parsed AND
expanded tree entries/visits and depth. Paths <=1024 UTF-8 bytes, repository <=256,
PR <=2**31-1, page size <=100, tree mode width <=6; none is a real service limit.
Python allocation/CPU multipliers and caller preallocation are not controlled.

No IO, environment, time, randomness, process or provider access. Arbitrary or
hostile Python objects/execution and prompt-injection containment are outside
this model. Syntactic import checks are not a sandbox. Actual trusted event roots,
fetch, freshness and wiring require separately approved future runner code.
"""
import hashlib
import json
import re

_CEILINGS = dict(max_files=128, max_total_bytes=2097152, max_objects=2048,
                 max_commits=128, max_pages=128, max_depth=32,
                 max_structural_bytes=262144, max_tree_entries=8192,
                 max_object_bytes=4194304)
_OID = re.compile(r'[0-9a-f]{40}')
_PERSON = re.compile(r'(author|committer) [\x20-\x3b\x3d\x3f-\x7e]+ <[\x21-\x3b\x3d\x3f-\x7e]+> [0-9]{1,12} [+-](?:[01][0-9]|2[0-3])[0-5][0-9]')


class Refused(ValueError):
    """A closed value-free reason; no input content is echoed."""


def _need(condition, reason):
    if not condition:
        raise Refused(reason)


def _keys(value, names):
    _need(type(value) is dict and all(type(k) is str for k in value)
          and set(value) == set(names.split()), 'shape refused')


def _integer(value, lower, upper, reason):
    _need(type(value) is int and lower <= value <= upper, reason)


def _oid(value):
    _need(type(value) is str and _OID.fullmatch(value) is not None, 'oid refused')


def _path(value):
    _need(type(value) is str, 'path refused')
    try:
        raw = value.encode('utf-8')
    except UnicodeError:
        raise Refused('path refused') from None
    _need(0 < len(raw) <= 1024 and '\0' not in value
          and all(part not in ('', '.', '..') for part in value.split('/')), 'path refused')


def validate_acquisition(trust_root, objects, ancestry, pages, declared_changed_files, limits):
    """Return complete MODEL_ONLY manifest or raise closed Refused; never do IO.

    Deterministic order: shape/limits, all-object hashes, witness, complete tree
    walk/blobs, page structure, expanded-set reconciliation, unused objects.
    Thus a joint pages/blob omission fails missing-object before page equality.
    All size/count limits apply before the corresponding work/expansion.
    """
    _keys(limits, ' '.join(_CEILINGS))
    for name, ceiling in _CEILINGS.items():
        _integer(limits[name], 1, ceiling, 'limits refused')
    _keys(trust_root, 'repository pr base_tip head')
    repo = trust_root['repository']
    _need(type(repo) is str and len(repo) <= 256
          and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) is not None
          and all(part not in ('.', '..') for part in repo.split('/')), 'identity refused')
    _integer(trust_root['pr'], 1, 2147483647, 'identity refused')
    base, head = trust_root['base_tip'], trust_root['head']
    _oid(base)
    _oid(head)
    _need(type(objects) is dict and 0 < len(objects) <= limits['max_objects'], 'object count refused')
    total_object_bytes = structural_bytes = 0
    for oid, obj in objects.items():
        _oid(oid)
        _keys(obj, 'type body')
        kind, body = obj['type'], obj['body']
        _need(type(kind) is str and kind in ('commit', 'tree', 'blob') and type(body) is bytes, 'object shape refused')
        total_object_bytes += len(body)
        _need(total_object_bytes <= limits['max_object_bytes'], 'object bytes refused')
        if kind != 'blob':
            structural_bytes += len(body)
            _need(structural_bytes <= limits['max_structural_bytes'], 'structural bytes refused')
        actual = hashlib.sha1(kind.encode('ascii') + b' ' + str(len(body)).encode('ascii') + b'\0' + body).hexdigest()
        _need(actual == oid, 'object hash refused')
    used = set()

    def get(oid, kind):
        _need(oid in objects, 'missing object refused')
        obj = objects[oid]
        _need(obj['type'] == kind, 'object type refused')
        used.add(oid)
        return obj['body']

    def parse_commit(oid):
        body = get(oid, 'commit')
        try:
            text = body.decode('utf-8')
        except UnicodeError:
            raise Refused('commit grammar refused') from None
        _need('\0' not in text and '\n\n' in text, 'commit grammar refused')
        headers, _ = text.split('\n\n', 1)
        lines = headers.split('\n')
        _need(3 <= len(lines) <= 35 and re.fullmatch(r'tree [0-9a-f]{40}', lines[0]) is not None, 'commit grammar refused')
        _need(lines[-2].startswith('author ') and lines[-1].startswith('committer ')
              and _PERSON.fullmatch(lines[-2]) is not None and _PERSON.fullmatch(lines[-1]) is not None, 'commit grammar refused')
        parents = []
        for line in lines[1:-2]:
            _need(re.fullmatch(r'parent [0-9a-f]{40}', line) is not None, 'commit grammar refused')
            parents.append(line[7:])
        _need(len(set(parents)) == len(parents), 'commit grammar refused')
        return lines[0][5:], parents

    _need(type(ancestry) is list and 1 <= len(ancestry) <= limits['max_commits'], 'ancestry shape refused')
    for oid in ancestry:
        _oid(oid)
    _need(len(set(ancestry)) == len(ancestry) and ancestry[0] == head and ancestry[-1] == base, 'ancestry refused')
    commits = [parse_commit(oid) for oid in ancestry]
    for index in range(len(ancestry) - 1):
        _need(ancestry[index + 1] in commits[index][1], 'ancestry link refused')
    base_tree, head_tree = commits[-1][0], commits[0][0]
    parsed = {}
    structural_entries = expanded_entries = visits = 0

    def parse_tree(oid):
        nonlocal structural_entries
        if oid in parsed:
            return parsed[oid]
        body = get(oid, 'tree')
        entries = {}
        pos = 0
        previous = None
        while pos < len(body):
            structural_entries += 1
            _need(structural_entries <= limits['max_tree_entries'], 'tree entries refused')
            space = body.find(b' ', pos, pos + 7)
            _need(space != -1, 'tree grammar refused')
            mode_raw = body[pos:space]
            _need(re.fullmatch(b'[0-7]{5,6}', mode_raw) is not None, 'tree grammar refused')
            end = body.find(b'\0', space + 1, space + 1026)
            _need(end != -1 and end + 21 <= len(body), 'tree grammar refused')
            try:
                name = body[space + 1:end].decode('utf-8')
            except UnicodeError:
                raise Refused('tree grammar refused') from None
            _path(name)
            _need('/' not in name and name not in entries, 'tree grammar refused')
            mode = mode_raw.decode('ascii')
            key = name.encode('utf-8') + (b'/' if mode == '40000' else b'')
            _need(previous is None or previous < key, 'tree order refused')
            previous = key
            entries[name] = (mode, body[end + 1:end + 21].hex())
            pos = end + 21
        parsed[oid] = entries
        return entries

    changed = {}
    raw = {}
    raw_bytes = logical_bytes = 0

    def descriptor(entry):
        nonlocal raw_bytes, logical_bytes
        mode, oid = entry
        _need(mode in ('100644', '100755'), 'changed mode refused')
        body = get(oid, 'blob')
        logical_bytes += len(body)
        _need(logical_bytes <= limits['max_total_bytes'], 'logical bytes refused')
        if oid not in raw:
            raw_bytes += len(body)
            _need(raw_bytes <= limits['max_total_bytes'], 'raw bytes refused')
            try:
                body.decode('utf-8')
            except UnicodeError:
                raise Refused('blob encoding refused') from None
            _need(b'\0' not in body, 'blob encoding refused')
            raw[oid] = body.hex()
        return dict(oid=oid, bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), mode=mode)

    def emit(path, before, after):
        _need(len(changed) < 2 * limits['max_files'], 'changed footprint refused')
        _need(path not in changed, 'changed footprint refused')
        changed[path] = dict(path=path, old_path=None,
                             status='M' if before and after else ('D' if before else 'A'),
                             base=descriptor(before) if before else None,
                             head=descriptor(after) if after else None)

    def walk(before_oid, after_oid, prefix, depth):
        nonlocal visits, expanded_entries
        visits += 1
        _need(visits <= limits['max_tree_entries'] and depth <= limits['max_depth'], 'tree depth refused')
        if before_oid == after_oid:
            return
        before = parse_tree(before_oid) if before_oid is not None else {}
        after = parse_tree(after_oid) if after_oid is not None else {}
        for name in sorted(set(before) | set(after)):
            expanded_entries += 1
            _need(expanded_entries <= limits['max_tree_entries'], 'tree expansion refused')
            path = prefix + name
            _path(path)
            left, right = before.get(name), after.get(name)
            if left == right:
                continue
            left_dir = left is not None and left[0] == '40000'
            right_dir = right is not None and right[0] == '40000'
            if left_dir or right_dir:
                if left is not None and not left_dir:
                    emit(path, left, None)
                if right is not None and not right_dir:
                    emit(path, None, right)
                walk(left[1] if left_dir else None, right[1] if right_dir else None, path + '/', depth + 1)
            else:
                emit(path, left, right)

    walk(base_tree, head_tree, '', 0)
    _need(bool(changed), 'empty diff refused')
    _integer(declared_changed_files, 1, limits['max_files'], 'declared count refused')
    _need(type(pages) is list and 1 <= len(pages) <= limits['max_pages'], 'pages refused')
    footprint = set()
    rows = []
    page_size = None
    for index, supplied in enumerate(pages):
        _keys(supplied, 'page per_page next_page items')
        _integer(supplied['page'], 1, limits['max_pages'], 'page sequence refused')
        _need(supplied['page'] == index + 1, 'page sequence refused')
        _integer(supplied['per_page'], 1, 100, 'page size refused')
        if page_size is None:
            page_size = supplied['per_page']
        _need(supplied['per_page'] == page_size, 'page size refused')
        items = supplied['items']
        _need(type(items) is list and 1 <= len(items) <= page_size, 'page items refused')
        if index < len(pages) - 1:
            _need(len(items) == page_size, 'short page refused')
            _integer(supplied['next_page'], 1, limits['max_pages'], 'next page refused')
            _need(supplied['next_page'] == index + 2, 'next page refused')
        else:
            _need(supplied['next_page'] is None, 'next page refused')
        for item in items:
            _need(len(rows) < limits['max_files'], 'file count refused')
            _keys(item, 'filename previous_filename status')
            path, old, status = item['filename'], item['previous_filename'], item['status']
            _path(path)
            _need(type(status) is str and status in ('added', 'removed', 'modified', 'renamed'), 'page status refused')
            if status == 'renamed':
                _path(old)
                _need(old != path, 'rename refused')
                consumed = {old, path}
            else:
                _need(old is None, 'rename refused')
                consumed = {path}
            _need(not footprint.intersection(consumed), 'page overlap refused')
            footprint.update(consumed)
            rows.append((path, old, status))
    _need(len(rows) == declared_changed_files, 'page total refused')
    _need(footprint == set(changed), 'changed set refused')
    files = []
    for path, old, status in rows:
        if status == 'renamed':
            _need(changed[old]['status'] == 'D' and changed[path]['status'] == 'A', 'rename support refused')
            files.append(dict(path=path, old_path=old, status='R', base=changed[old]['base'], head=changed[path]['head']))
        else:
            _need(changed[path]['status'] == {'added':'A', 'removed':'D', 'modified':'M'}[status], 'page status mismatch refused')
            files.append(changed[path])
    _need(used == set(objects), 'foreign object refused')
    return dict(schema=1, scope='MODEL_ONLY', qualification='NOT_ADMITTED',
                acquisition_authenticated=False, gate_wired=False,
                identity=dict(repository=repo, pr=trust_root['pr'], base_tip=base,
                              merge_base=base, comparison_base=base, head=head),
                trust='CALLER_SUPPLIED_UNAUTHENTICATED_UNFRESH', object_format='sha1',
                ancestry=list(ancestry), pages='SELF_CONSISTENT_AND_EQUAL_TO_TREE_SET',
                closure='NOT_EVALUATED', unchanged_context='NOT_ACQUIRED',
                declared_changed_files=declared_changed_files,
                files=sorted(files, key=lambda value:value['path']),
                blobs={oid:raw[oid] for oid in sorted(raw)}, limits=dict(limits),
                raw_bytes=raw_bytes, logical_bytes=logical_bytes, verified_objects=sorted(used))
