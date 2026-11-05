"""Two synthetic AArch64 objects; symbol planning never executes guest code."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_image import ROOT, symbol_fixture
from test_linker_audit import add_section, version_fixture
from test_relro import fixture as relro_fixture

sys.path.insert(0, str(ROOT / 'tools'))
import plan_resolution as planner


def ref(oid='A', table=2, index=1):
    return dict(object_id=oid, table_section=table, index=index)


def elf(spec=None, second=None):
    return symbol_fixture(symbols=[dict(binding=1, section=0) if spec is None else spec],
                          second_symbols=second or [], relocations=[])


class ResolutionPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / 'image-smoke'
        subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-I', str(ROOT / 'include'), str(ROOT / 'src/runtime.cpp'),
                        str(ROOT / 'src/elf_image.cpp'), str(ROOT / 'tests/image_smoke.cpp'),
                        '-lcrypto', '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def config(self, a, b, scope=None, references=None):
        objects = []
        for i, (oid, data) in enumerate((('A', a), ('B', b))):
            path = self.directory / (oid + '.elf')
            path.write_bytes(data)
            objects.append(dict(object_id=oid, input=str(path),
                                sha256=hashlib.sha256(data).hexdigest(),
                                load_bias=(i + 1) * 0x100000000))
        return dict(objects=objects, lookup_scope=scope or ['A', 'B'],
                    references=references or [ref()], guest_page_size=4096)

    def plan(self, a=None, b=None, scope=None, references=None):
        config = self.config(elf() if a is None else a,
                             elf(dict(binding=1)) if b is None else b, scope, references)
        before = [Path(o['input']).read_bytes() for o in config['objects']]
        plan = planner.prepare_plan(config, self.runner)
        self.assertEqual(before, [Path(o['input']).read_bytes() for o in config['objects']])
        self.assertFalse(plan['ready_to_execute'])
        self.assertFalse(plan['plan_applied'])
        self.assertTrue(all(o['image']['relro_sealed'] for o in plan['facts']['objects']))
        return plan

    def test_import_and_guest_address_and_func(self):
        for kind in (1, 2):
            plan = self.plan(elf(dict(binding=1, section=0, type=kind)),
                             elf(dict(binding=1, type=kind)))
            entry = plan['entries'][0]
            self.assertEqual(entry['status'], 'planned')
            self.assertEqual(entry['selected']['identity'], ref('B'))
            self.assertEqual(entry['selected']['guest_address'], 0x200009010)
            self.assertEqual(entry['implementation'], 'unknown')
            self.assertEqual(entry['bridge'], 'unknown')
            self.assertEqual(entry['candidates'][0]['reason'], 'undefined_not_provider')
            # A planned import remains in the independent unresolved inventory.
            self.assertEqual(plan['facts']['objects'][0]['image']['summary']['imports'], 1)

    def test_scope_and_default_preemption(self):
        a, b = elf(dict(binding=1)), elf(dict(binding=1, value=0x9020))
        for scope, winner in ((['A', 'B'], 'A'), (['B', 'A'], 'B')):
            entry = self.plan(a, b, scope)['entries'][0]
            self.assertEqual(entry['selected']['identity'], ref(winner))
            self.assertEqual(entry['lookup_stopped_after_scope_position'], 0)

    def test_internal_exact_identity(self):
        for binding, visibility in ((0, 0), (0, 1), (0, 2), (1, 1), (1, 2), (1, 3)):
            with self.subTest(binding=binding, visibility=visibility):
                a = elf(dict(binding=binding, visibility=visibility),
                        second=[dict(binding=0, value=0x9020)])
                plan = self.plan(a, scope=['B', 'A'], references=[ref(), ref(table=3)])
                for entry, table in zip(plan['entries'], (2, 3)):
                    self.assertEqual(entry['selected']['identity'], ref(table=table))
                    self.assertEqual(entry['selected']['reason'], 'non_preemptible_internal_identity')
                    self.assertEqual(entry['candidates'], [])

    def test_nonexported_and_protected_provider(self):
        for binding, visibility, reason in ((0, 0, 'local_not_exported'),
                                            (1, 1, 'hidden_or_internal_not_exported'),
                                            (1, 2, 'hidden_or_internal_not_exported')):
            entry = self.plan(b=elf(dict(binding=binding, visibility=visibility)))['entries'][0]
            self.assertEqual(entry['status'], 'missing_strong')
            self.assertEqual(entry['candidates'][-1]['reason'], reason)
        entry = self.plan(b=elf(dict(binding=1, visibility=3)))['entries'][0]
        self.assertEqual(entry['selected']['identity'], ref('B'))

    def test_missing_strong_and_weak_no_stub(self):
        for binding, status in ((1, 'missing_strong'), (2, 'missing_weak')):
            entry = self.plan(elf(dict(binding=binding, section=0)), elf())['entries'][0]
            self.assertEqual(entry['status'], status)
            self.assertIsNone(entry['selected'])
            self.assertNotIn('guest_address', entry)
        # Weak reference may select an ordinary GLOBAL definition.
        self.assertEqual(self.plan(elf(dict(binding=2, section=0)))['entries'][0]['status'], 'planned')

    def test_names_are_not_identity_and_symtab_not_exported(self):
        a = elf(dict(binding=1, section=0), second=[dict(binding=1, section=0)])
        b = elf(dict(binding=1), second=[dict(binding=1, value=0x9020)])
        plan = self.plan(a, b, references=[ref(), ref(table=3)])
        self.assertEqual(plan['entries'][0]['selected']['identity'], ref('B'))
        self.assertEqual(plan['entries'][1]['diagnostics'], ['external_reference_requires_dynsym'])
        entry = self.plan(a=elf(), b=elf(dict(binding=1, section=0),
                                        second=[dict(binding=1)]))['entries'][0]
        self.assertEqual(entry['status'], 'missing_strong')
        self.assertEqual(entry['candidates'][-1]['reason'], 'not_dynamic_symbol')
        # Same file/hash loaded twice still has distinct instance identities.
        same = elf(dict(binding=1))
        plan = self.plan(same, same, scope=['B', 'A'])
        self.assertEqual(plan['facts']['objects'][0]['sha256'], plan['facts']['objects'][1]['sha256'])
        self.assertEqual(plan['entries'][0]['selected']['identity']['object_id'], 'B')

    def test_unsupported_references_and_decisive_candidates(self):
        cases = [(dict(type=6), 'tls_unsupported'), (dict(type=10), 'ifunc_unsupported'),
                 (dict(type=5), 'common_unsupported'), (dict(section=0xfff2), 'common_unsupported'),
                 (dict(other=0x80), 'symbol_attributes_unsupported'),
                 (dict(other=4), 'symbol_attributes_unsupported'),
                 (dict(binding=10), 'symbol_binding_unsupported'),
                 (dict(binding=2), 'weak_definition_policy_unsupported'),
                 (dict(type=0), 'symbol_type_unsupported'),
                 (dict(section=0xfff1), 'special_section_unsupported'),
                 (dict(binding=0, visibility=3), 'local_protected_invalid')]
        for attrs, reason in cases:
            with self.subTest(attrs=attrs):
                spec = dict(binding=1)
                spec.update(attrs)
                entry = self.plan(a=elf(spec))['entries'][0]
                self.assertEqual(entry['status'], 'unsupported')
                self.assertIn(reason, entry['diagnostics'])
                # Unsupported externally visible candidate before a valid A must
                # block rather than silently skip to A. LOCAL is nonexported.
                if spec['binding'] != 0:
                    entry = self.plan(a=elf(dict(binding=1)), b=elf(spec),
                                      scope=['B', 'A'])['entries'][0]
                    self.assertEqual(entry['status'], 'unsupported')
                    self.assertIn(reason, entry['diagnostics'])
                    self.assertIsNone(entry['selected'])
        entry = self.plan(b=elf(dict(binding=1, type=2)))['entries'][0]
        self.assertEqual(entry['diagnostics'], ['symbol_type_matching_policy_unsupported'])

    def test_versioning_reference_provider_and_special_indices(self):
        for requirement in (False, True):
            entry = self.plan(a=version_fixture(requirement))['entries'][0]
            self.assertEqual(entry['diagnostics'], ['symbol_versioning_unsupported'])
        entry = self.plan(a=elf(dict(binding=1)), b=version_fixture(),
                          scope=['B', 'A'])['entries'][0]
        self.assertEqual(entry['diagnostics'], ['symbol_versioning_unsupported'])
        for index in (0, 1):
            data = version_fixture()
            struct.pack_into('<H', data, 0x1202, index)
            self.assertEqual(self.plan(a=data)['entries'][0]['status'], 'unsupported')

    def test_ambiguity_and_later_candidates(self):
        b = symbol_fixture(symbols=[dict(binding=1), dict(binding=1)],
                           second_symbols=[], relocations=[])
        entry = self.plan(b=b)['entries'][0]
        self.assertEqual(entry['diagnostics'], ['ambiguous_dynamic_definitions'])
        # Same-name DYNSYM entries in two different tables are also ambiguous.
        b = elf(dict(binding=1), second=[dict(binding=1)])
        struct.pack_into('<I', b, 0x1800 + 3 * 64 + 4, 11)
        self.assertEqual(self.plan(b=b)['entries'][0]['status'], 'unsupported')
        # Scope lookup stops at the first supported provider; later symbols have
        # no effect. The explicit stop position explains their absence in trace.
        entry = self.plan(a=elf(dict(binding=1)), b=elf(dict(binding=1, type=10)))['entries'][0]
        self.assertEqual(entry['status'], 'planned')
        self.assertEqual(entry['lookup_stopped_after_scope_position'], 0)

    def test_dynamic_policies_are_explicitly_unsupported(self):
        for tag, value in ((16, 0), (30, 2), (30, 0x80000000), (0x6ffffffb, 2),
                           (0x70000000, 1)):
            data = elf(dict(binding=1))
            struct.pack_into('<QQQQ', data, 0x1300, tag, value, 0, 0)
            add_section(data, 6, 0x1300, 32, 1, stride=16)
            entry = self.plan(b=data)['entries'][0]
            self.assertEqual(entry['diagnostics'], ['scope_lookup_policy_unsupported'])
            self.assertEqual(entry['policy_diagnostics'][0]['object_id'], 'B')

    def test_invalid_internal_and_section_semantics(self):
        for binding, visibility in ((0, 0), (1, 1), (1, 2), (1, 3), (2, 2)):
            data = elf(dict(binding=binding, visibility=visibility, section=0))
            self.assertEqual(self.plan(a=data)['entries'][0]['status'], 'unsupported')
        for flags, value, reason in ((0x403, 0x9010, 'tls_unsupported'),
                                     (0x10000003, 0x9010, 'symbol_section_attributes_unsupported'),
                                     (1, 0x9010, 'nonallocated_symbol_section'),
                                     (3, 0x9041, 'symbol_outside_section')):
            data = elf(dict(binding=1, value=value))
            struct.pack_into('<Q', data, 0x1800 + 4 * 64 + 8, flags)
            self.assertIn(reason, self.plan(b=data)['entries'][0]['diagnostics'])
        data = elf(dict(binding=1))
        struct.pack_into('<Q', data, 0x1800 + 4 * 64 + 16, (1 << 64) - 32)
        self.assertEqual(self.plan(b=data)['entries'][0]['diagnostics'],
                         ['symbol_section_extent_unsupported'])

    def test_address_overflow_and_unmapped_symbol(self):
        for value, reason in (((1 << 64) - 16, 'guest_address_overflow'),
                              (0xa000, 'symbol_outside_load_mapping')):
            data = elf(dict(binding=1, value=value))
            # Huge NOBITS section is metadata, not a new PT_LOAD mapping.
            struct.pack_into('<I', data, 0x1800 + 4 * 64 + 4, 8)
            struct.pack_into('<Q', data, 0x1800 + 4 * 64 + 16, 0)
            struct.pack_into('<Q', data, 0x1800 + 4 * 64 + 32, (1 << 64) - 1)
            self.assertEqual(self.plan(b=data)['entries'][0]['diagnostics'], [reason])

    def test_scope_and_reference_validation(self):
        config = self.config(elf(), elf(dict(binding=1)))
        for scope in ([], ['A'], ['A', 'A'], ['A', 'C'], ['A', 'B', 'B'], 'AB', [1, 'B']):
            bad = dict(config, lookup_scope=scope)
            with self.assertRaises(ValueError):
                planner.prepare_plan(bad, self.runner)
        for references in ([], [ref(index=0)], [ref(table=99)], [ref('C')], [ref(), ref()]):
            with self.assertRaises(ValueError):
                planner.prepare_plan(dict(config, references=references), self.runner)
        config['objects'][1]['object_id'] = 'A'
        with self.assertRaises(ValueError):
            planner.prepare_plan(config, self.runner)
        config = self.config(elf(), elf(dict(binding=1)))
        config['objects'][1]['load_bias'] = config['objects'][0]['load_bias']
        with self.assertRaisesRegex(ValueError, 'overlap'):
            planner.prepare_plan(config, self.runner)
        config['objects'][1]['load_bias'] = (1 << 64) - 1
        with self.assertRaises(subprocess.CalledProcessError):
            planner.prepare_plan(config, self.runner)

    def test_read_only_snapshots_include_relocations_and_sealed_state(self):
        a = relro_fixture(targets=(0x9000,))
        # Add an unresolved GLOBAL reference beside the applied RELATIVE.
        struct.pack_into('<B', a, 0x600 + 24 + 4, 0x11)
        struct.pack_into('<QQq', a, 0xc18, 0x9008, (1 << 32) | 257, 0)
        struct.pack_into('<Q', a, 0x1800 + 5 * 64 + 32, 48)
        plan = self.plan(a=a)
        objects = plan['facts']['objects']
        before = copy.deepcopy(objects)
        with mock.patch.object(planner, 'audit', side_effect=AssertionError('planner must not load')):
            first = planner.compose_plan(objects, ['B', 'A'], [ref()])
            second = planner.compose_plan(objects, ['B', 'A'], [ref()])
        self.assertEqual(first, second)
        self.assertEqual(objects, before)
        image = objects[0]['image']
        self.assertTrue(image['relro_sealed'])
        self.assertTrue(image['sealed_relro_ranges'])
        self.assertEqual(image['summary']['applied'], 1)
        self.assertEqual(image['summary']['unresolved'], 1)
        self.assertEqual(image['applied_relocations'][0]['bytes'], before[0]['image']['applied_relocations'][0]['bytes'])
        self.assertEqual(first['facts']['objects'], before)
        # Output owns its snapshots; mutating it does not mutate caller input.
        first['facts']['objects'][0]['image']['relro_sealed'] = False
        self.assertEqual(objects, before)
        # Pure composition also preserves an explicitly unsealed snapshot; it
        # never infers that planning should seal or finish relocation phases.
        unsealed = copy.deepcopy(objects)
        unsealed[0]['image']['relro_sealed'] = False
        unsealed_before = copy.deepcopy(unsealed)
        planner.compose_plan(unsealed, ['B', 'A'], [ref()])
        self.assertEqual(unsealed, unsealed_before)

    def test_failure_never_publishes_or_replaces_report(self):
        output = self.directory / 'resolution.json'
        config_path = self.directory / 'config.json'
        for failure in ('hash_A', 'hash_B', 'native', 'metadata', 'scope', 'overlap'):
            config = self.config(elf(), elf(dict(binding=1)))
            if failure.startswith('hash'):
                config['objects'][0 if failure == 'hash_A' else 1]['sha256'] = '0' * 64
            elif failure in ('native', 'metadata'):
                data = bytearray(b'invalid ELF') if failure == 'native' else version_fixture()
                if failure == 'metadata':
                    struct.pack_into('<H', data, 0x1202, 99)
                Path(config['objects'][1]['input']).write_bytes(data)
                config['objects'][1]['sha256'] = hashlib.sha256(data).hexdigest()
            elif failure == 'scope':
                config['lookup_scope'] = ['A', 'A']
            else:
                config['objects'][1]['load_bias'] = config['objects'][0]['load_bias']
            config_path.write_text(json.dumps(config))
            for existing in (False, True):
                output.unlink(missing_ok=True)
                if existing:
                    output.write_text('old report')
                result = subprocess.run([sys.executable, str(ROOT / 'tools/plan_resolution.py'),
                                         '--config', str(config_path), '--runner', str(self.runner),
                                         '--output', str(output)], capture_output=True)
                self.assertNotEqual(result.returncode, 0, failure)
                self.assertEqual(output.read_text() if existing else output.exists(),
                                 'old report' if existing else False)

    def test_cli_publication(self):
        config = self.config(elf(), elf(dict(binding=1)))
        path = self.directory / 'success-config.json'
        path.write_text(json.dumps(config))
        output = self.directory / 'success-plan.json'
        subprocess.run([sys.executable, str(ROOT / 'tools/plan_resolution.py'), '--config', str(path),
                        '--runner', str(self.runner), '--output', str(output)],
                       check=True, capture_output=True)
        self.assertEqual(json.loads(output.read_text())['summary'], {'planned': 1})


if __name__ == '__main__':
    unittest.main()
