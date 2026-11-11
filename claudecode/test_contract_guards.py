"""Guard tests for chunk_plan.py and review_input_contract.py.

Each case pins one check that could be deleted from its module without any
other test failing. Mutation runs during the review of #4 and #5 found them:
every check below was removed in turn and the existing suites stayed green.

The cases live in their own file so the per-module test files stay exactly as
their pull requests froze them. Fixtures come from those sibling test modules,
loaded by path the same way they load the modules under test.
"""
import copy
import importlib.util
from pathlib import Path
import unittest


def _load(name):
    spec = importlib.util.spec_from_file_location('guard_fixtures_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan_tests = _load('test_chunk_plan')
acquisition_tests = _load('test_review_input_contract')
planner = plan_tests.planner
contract = acquisition_tests.contract


class PlannerGuardTests(unittest.TestCase):
    def test_ledger_plan_for_another_inventory_refuses_despite_correctly_bound_results(self):
        inventory, blobs, budget = plan_tests.fixture()
        own = planner.plan(inventory, blobs, budget)
        foreign = copy.deepcopy(inventory)
        foreign['identity']['repository'] = 'other/project'
        foreign['files'][0]['path'] = 'other.txt'
        foreign['dependencies']['groups'][0]['paths'] = ['other.txt']
        ledger = plan_tests.ledger_for(own)
        ledger['plan'] = planner.plan(foreign, blobs, budget)
        result = planner.verify(ledger, inventory)
        self.assertEqual(result['reasons'], ['inventory binding refused'])
        self.assertIsNone(result['stub_findings'])

    def test_non_list_findings_container_never_reads_as_zero_findings(self):
        inventory, blobs, budget = plan_tests.fixture()
        for container in ({}, '', (), b''):
            with self.subTest(container=container):
                ledger = plan_tests.ledger_for(planner.plan(inventory, blobs, budget))
                ledger['results'][0]['findings'] = container
                result = planner.verify(ledger, inventory)
                self.assertEqual(result['reasons'], ['findings refused'])
                self.assertIsNone(result['stub_findings'])

    def test_boolean_chunk_id_refuses_on_the_chunk_whose_id_it_equals(self):
        # True == 1, so only the second chunk shows whether the type is checked.
        inventory, blobs, budget = plan_tests.fixture()
        plan_tests.add_file(inventory, blobs, 'second.txt', b'x' * 6000)
        plan = planner.plan(inventory, blobs, budget)
        self.assertGreater(len(plan['chunks']), 1)
        ledger = plan_tests.ledger_for(plan)
        ledger['results'][1]['chunk_id'] = True
        self.assertEqual(planner.verify(ledger, inventory)['reasons'], ['integer refused'])


class AcquisitionGuardTests(unittest.TestCase):
    def refused(self, args, reason):
        with self.assertRaises(contract.Refused) as caught:
            contract.validate_acquisition(*args)
        self.assertEqual(str(caught.exception), reason)

    def test_witness_must_begin_at_the_supplied_head_root(self):
        args = acquisition_tests.arguments()
        args[0]['head'] = 'f' * 40
        self.refused(args, 'ancestry refused')

    def test_witness_must_end_at_the_supplied_base_root(self):
        args = acquisition_tests.arguments()
        args[0]['base_tip'] = 'f' * 40
        self.refused(args, 'ancestry refused')

    def test_rename_source_must_be_a_tree_deletion(self):
        for source, before in [('modified', [('100644', 'old', b'a')]), ('added', [])]:
            with self.subTest(source=source):
                args = acquisition_tests.flat_args(
                    before, [('100644', 'old', b'b'), ('100644', 'new', b'c')],
                    [acquisition_tests.row('new', 'renamed', 'old')])
                self.refused(args, 'rename support refused')

    def test_directory_sorts_after_a_sibling_file_that_extends_its_name(self):
        # Git orders the directory `foo` as `foo/`, after the file `foo.txt`.
        t = acquisition_tests
        objects = {}
        before = t.git_object(objects, 'blob', b'before')
        after = t.git_object(objects, 'blob', b'after')
        same = t.git_object(objects, 'blob', b'same')
        old = t.tree(objects, [('100644', 'item', before)])
        new = t.tree(objects, [('100644', 'item', after)])
        base_tree = t.tree(objects, [('40000', 'foo', old), ('100644', 'foo.txt', same)])
        head_tree = t.tree(objects, [('40000', 'foo', new), ('100644', 'foo.txt', same)])
        base = t.commit(objects, base_tree)
        head = t.commit(objects, head_tree, [base])
        del objects[same]  # The unchanged blob is not acquired.
        args = [dict(repository='fixture/project', pr=1, base_tip=base, head=head), objects, [head, base],
                [t.page([t.row('foo/item', 'modified')])], 1, copy.deepcopy(t.LIMITS)]
        files = [t.file_row('foo/item', 'M', b'before', b'after')]
        blobs = {t.desc(raw)['oid']: raw.hex() for raw in [b'before', b'after']}
        self.assertEqual(contract.validate_acquisition(*args), t.expected_manifest(args, files, blobs, 11, 11))


if __name__ == '__main__':
    unittest.main()
