"""Explicit synthetic dependency evidence; never derive an Android lookup scope."""
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
import audit_dependencies as manifest


def dependency_fixture(needed=(), soname=None, data=None):
    data = symbol_fixture(relocations=[]) if data is None else bytearray(data)
    strings, dynamic = bytearray(b'\0'), []
    for tag, name in [(1, n) for n in needed] + ([(14, soname)] if soname else []):
        dynamic.append((tag, len(strings)))
        strings.extend(name.encode('ascii') + b'\0')
    data[0x1400:0x1400 + len(strings)] = strings
    string_table = add_section(data, 3, 0x1400, len(strings), 0)
    for i, (tag, value) in enumerate(dynamic + [(0, 0)]):
        struct.pack_into('<QQ', data, 0x1500 + 16 * i, tag, value)
    add_section(data, 6, 0x1500, 16 * (len(dynamic) + 1), string_table, stride=16)
    return data


def edge(a, b, index=0, table=9):
    return dict(from_instance=a, to_instance=b, table_section=table, index=index,
                source='synthetic fixture declaration')


class DependencyManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / 'image-smoke'
        subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-I', str(ROOT / 'include'), str(ROOT / 'src/runtime.cpp'),
                        str(ROOT / 'src/elf_image.cpp'),
                        str(ROOT / 'src/aps2_rela.cpp'), str(ROOT / 'src/relr.cpp'), str(ROOT / 'tests/image_smoke.cpp'),
                        '-lcrypto', '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def config(self, *data):
        objects = []
        for i, binary in enumerate(data):
            path = self.directory / ('input-%d.elf' % i)
            path.write_bytes(binary)
            objects.append(dict(instance_id=chr(65 + i), path=str(path),
                                sha256=hashlib.sha256(binary).hexdigest(),
                                load_bias=(i + 1) * 0x100000000))
        return dict(schema_version=1, guest_page_size=4096, objects=objects, edges=[])

    def prepare(self, config):
        before = [(Path(o['path']).read_bytes(), Path(o['path']).stat().st_mode)
                  for o in config['objects']]
        report = manifest.prepare_manifest(config, self.runner)
        self.assertEqual(before, [(Path(o['path']).read_bytes(), Path(o['path']).stat().st_mode)
                                  for o in config['objects']])
        self.assertFalse(report['ready_to_execute'])
        self.assertFalse(report['plan_applied'])
        for obj in report['facts']['objects']:
            self.assertTrue(all(s['status'] == 'unresolved' and s['provider'] == 'unknown'
                                for s in obj['image']['imports']))
        return report

    def test_direct_transitive_and_missing(self):
        config = self.config(dependency_fixture(['B.so']), dependency_fixture(['C.so']),
                             dependency_fixture(['D.so']))
        config['edges'] = [edge('A', 'B'), edge('B', 'C')]
        report = self.prepare(config)
        self.assertEqual(report['summary'], dict(available_files=3, dependency_edges=3,
                                                available_edges=2, missing_dependencies=1))
        self.assertEqual([e['to_instance'] for e in report['facts']['dependency_edges']], ['B', 'C', None])
        missing = report['missing_dependencies'][0]
        self.assertEqual(missing['from_instance'], 'C')
        self.assertEqual(missing['needed']['string'], 'D.so')
        self.assertEqual(missing['association_status'], 'not_supplied')
        self.assertEqual(report['unknowns']['dependency_closure'], 'unknown')
        self.assertNotIn('lookup_scope', report['facts'])

    def test_explicit_missing_and_duplicate_needed_provenance(self):
        config = self.config(dependency_fixture(['B.so', 'B.so', 'C.so']))
        config['edges'] = [edge('A', None, 1)]
        report = self.prepare(config)
        edges = report['facts']['dependency_edges']
        self.assertEqual([e['needed_ordinal'] for e in edges], [0, 1, 2])
        self.assertEqual([e['needed']['index'] for e in edges], [0, 1, 2])
        self.assertEqual([e['needed']['table_section'] for e in edges], [9, 9, 9])
        self.assertEqual(edges[1]['association_status'], 'explicit')
        self.assertIsNone(edges[1]['to_instance'])
        self.assertNotIn('path', edges[1])
        self.assertEqual(report['summary']['missing_dependencies'], 3)

    def test_same_hash_instances_and_same_soname_never_select(self):
        same = dependency_fixture(soname='B.so')
        config = self.config(dependency_fixture(['B.so']), same, same)
        # Even overlapping isolated inventory biases are not a process layout claim.
        config['objects'][2]['load_bias'] = config['objects'][1]['load_bias']
        report = self.prepare(config)
        self.assertEqual(report['summary']['missing_dependencies'], 1)
        b, c = report['facts']['objects'][1:]
        self.assertEqual(b['sha256'], c['sha256'])
        self.assertNotEqual(b['instance_id'], c['instance_id'])
        different = dependency_fixture(soname='B.so')
        different[0x301] ^= 1
        config = self.config(dependency_fixture(['B.so']), same, different)
        report = self.prepare(config)
        self.assertNotEqual(report['facts']['objects'][1]['sha256'], report['facts']['objects'][2]['sha256'])
        self.assertEqual(report['summary']['missing_dependencies'], 1)
        # An explicit relation may name C; no SONAME-based tie breaking occurs.
        config['edges'] = [edge('A', 'C')]
        report = self.prepare(config)
        self.assertEqual(report['facts']['dependency_edges'][0]['to_instance'], 'C')
        self.assertEqual(report['facts']['dependency_edges'][0]['provider'], 'unknown')

    def test_cycles_and_long_iterative_graph(self):
        config = self.config(dependency_fixture(['B']), dependency_fixture(['A', 'B']))
        config['edges'] = [edge('A', 'B'), edge('B', 'A'), edge('B', 'B', 1)]
        report = self.prepare(config)
        self.assertEqual(report['facts']['cycle_components'], [['A', 'B']])
        self.assertEqual(report['summary']['missing_dependencies'], 0)
        ids = [str(i) for i in range(2000)]
        edges = [dict(from_instance=a, to_instance=b) for a, b in zip(ids, ids[1:] + ids[:1])]
        self.assertEqual(manifest.cycle_components(ids, edges), [ids])
        self.assertEqual(manifest.cycle_components(['A'], [dict(from_instance='A', to_instance='A')]), [['A']])

    def test_known_unknown_platform_evidence(self):
        config = self.config(dependency_fixture())
        config['platform_evidence'] = dict(android_api=dict(status='known', value=23,
                    sources=['synthetic device capture, not original game evidence']),
                    preload=dict(status='known', value=[], sources=['synthetic process capture']),
                    target_sdk=dict(status='unknown', value=None, sources=[]))
        config['assumptions'] = ['Synthetic values only for contract testing']
        before = copy.deepcopy(config)
        report = self.prepare(config)
        self.assertEqual(config, before)
        platform = report['facts']['platform_evidence']
        self.assertEqual(platform['android_api']['value'], 23)
        self.assertEqual(platform['target_sdk']['status'], 'unknown')
        self.assertEqual(platform['namespace']['status'], 'unknown')
        self.assertNotIn('preload', report['unknowns']['platform'])
        self.assertIn('target_sdk', report['unknowns']['platform'])
        self.assertEqual(report['assumptions'], config['assumptions'])

    def test_versions_tls_ifunc_attributes_inventory(self):
        special = symbol_fixture(symbols=[dict(type=6, other=0x80), dict(type=10)],
                                 relocations=[(0x9000, 1031, 1, 0, 2), (0x9008, 1032, 0, 0, 2)])
        struct.pack_into('<H', special, 56, 3)
        struct.pack_into('<IIQQQQQQ', special, 176, 7, 4, 0x300, 0x9000, 0, 8, 16, 8)
        struct.pack_into('<Q', special, 0x1800 + 4 * 64 + 8, 0x403)
        config = self.config(version_fixture(True), version_fixture(), special)
        report = self.prepare(config)
        req = report['facts']['requirements']
        self.assertEqual(req[0]['versions']['records'][0]['kind'], 'requirement')
        self.assertEqual(req[1]['versions']['records'][0]['kind'], 'definition')
        for field in ('tls_symbols', 'ifunc_symbols', 'tls_sections', 'tls_segments', 'extra_symbol_attributes'):
            self.assertEqual(len(req[2]['special'][field]), 1)
        self.assertEqual(req[0]['summary']['version_records'], 1)
        self.assertEqual(req[0]['summary']['versioned_symbol_entries'], 2)
        self.assertEqual(req[2]['summary']['tls_symbols'], 1)
        self.assertEqual(req[2]['summary']['ifunc_symbols'], 1)
        self.assertEqual(req[2]['summary']['extra_symbol_attributes'], 1)
        self.assertEqual(req[2]['relocation_types'], {'1031': 1, '1032': 1})
        self.assertEqual(req[2]['implementation'], 'unknown')

    def test_invalid_contract_and_edges(self):
        config = self.config(dependency_fixture(['B']), dependency_fixture())
        bads = []
        for edges in ([edge('A', 'Z')], [edge('Z', 'A')], [edge('A', 'B')] * 2,
                      [edge('A', 'B', 1)], [edge('B', 'A')], [edge('A', 'B', table=2)],
                      [dict(edge('A', 'B'), index=True)], [dict(edge('A', 'B'), source='')]):
            bads.append(dict(config, edges=edges))
        for field, value in (('guest_page_size', True), ('guest_page_size', 3), ('schema_version', 2),
                             ('objects', []), ('edges', None), ('lookup_scope', ['A', 'B'])):
            bads.append(dict(config, **{field: value}))
        for field, value in (('instance_id', 'A'), ('instance_id', ''), ('sha256', 'x' * 64),
                             ('load_bias', True), ('load_bias', -1), ('path', '')):
            bad = copy.deepcopy(config)
            bad['objects'][1][field] = value
            bads.append(bad)
        for entry in (dict(status='known', value=23, sources=[]),
                      dict(status='unknown', value=23, sources=[]),
                      dict(status='unknown', value=None, sources=['guessed']),
                      dict(status='inferred', value=23, sources=['name'])):
            bads.append(dict(config, platform_evidence=dict(android_api=entry)))
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                manifest.prepare_manifest(bad, self.runner)

    def test_composition_preserves_snapshots_bytes_permissions_and_sealing(self):
        data = relro_fixture(targets=(0x9000,))
        struct.pack_into('<B', data, 0x600 + 24 + 4, 0x11)
        struct.pack_into('<QQq', data, 0xc18, 0x9008, (1 << 32) | 257, 0)
        struct.pack_into('<Q', data, 0x1800 + 5 * 64 + 32, 48)
        config = self.config(data)
        report = self.prepare(config)
        objects = report['facts']['objects']
        before = copy.deepcopy(objects)
        image = objects[0]['image']
        self.assertEqual(image['summary']['applied'], 1)
        self.assertEqual(image['summary']['unresolved'], 1)
        self.assertTrue(image['sealed_relro_ranges'])
        self.assertTrue(image['relro_sealed'])
        with mock.patch.object(manifest, 'audit', side_effect=AssertionError('no new preparation')):
            first = manifest.compose_manifest(config, objects)
            self.assertEqual(first, manifest.compose_manifest(config, objects))
        self.assertEqual(objects, before)
        self.assertEqual(first['facts']['objects'], before)
        first['facts']['objects'][0]['image']['applied_relocations'].clear()
        self.assertEqual(objects, before)
        objects[0]['image']['relro_sealed'] = False
        unsealed = copy.deepcopy(objects)
        manifest.compose_manifest(config, objects)
        self.assertEqual(objects, unsealed)

    def cli(self, config, output):
        path = self.directory / 'manifest.json'
        path.write_text(json.dumps(config))
        return subprocess.run([sys.executable, str(ROOT / 'tools/audit_dependencies.py'),
                               '--manifest', str(path), '--runner', str(self.runner),
                               '--output', str(output)], capture_output=True)

    def test_failures_never_publish_or_replace(self):
        for failure in ('hash_first', 'hash_second', 'native', 'metadata', 'edge', 'absent_file', 'config'):
            config = self.config(dependency_fixture(['B']), dependency_fixture())
            if failure.startswith('hash'):
                config['objects'][0 if failure == 'hash_first' else 1]['sha256'] = '0' * 64
            elif failure in ('native', 'metadata'):
                data = bytearray(b'invalid ELF') if failure == 'native' else version_fixture()
                if failure == 'metadata':
                    struct.pack_into('<H', data, 0x1202, 99)
                Path(config['objects'][1]['path']).write_bytes(data)
                config['objects'][1]['sha256'] = hashlib.sha256(data).hexdigest()
            elif failure == 'edge':
                config['edges'] = [edge('B', 'A')]
            elif failure == 'absent_file':
                Path(config['objects'][1]['path']).unlink()
            else:
                config['objects'][1]['instance_id'] = 'A'
            output = self.directory / 'failure.json'
            for existing in (False, True):
                output.unlink(missing_ok=True)
                if existing:
                    output.write_bytes(b'previous report\n')
                result = self.cli(config, output)
                self.assertNotEqual(result.returncode, 0, (failure, result.stdout))
                self.assertEqual(output.read_bytes() if existing else output.exists(),
                                 b'previous report\n' if existing else False)

    def test_each_instance_rehashes_and_metadata_uses_captured_bytes(self):
        import audit_linker
        data = dependency_fixture(['original.so'])
        config = self.config(data)
        original = Path(config['objects'][0]['path'])
        native_run = subprocess.run

        def replace_original_after_native(*args, **kwargs):
            result = native_run(*args, **kwargs)
            original.write_bytes(b'replaced after capture')
            return result

        with mock.patch.object(audit_linker.subprocess, 'run', side_effect=replace_original_after_native):
            report = manifest.prepare_manifest(config, self.runner)
        self.assertEqual(report['missing_dependencies'][0]['needed']['string'], 'original.so')
        original.write_bytes(data)
        # Same path/hash is an independent instance, never an audit-cache key.
        config['objects'].append(dict(config['objects'][0], instance_id='B'))
        with mock.patch.object(audit_linker.subprocess, 'run', side_effect=replace_original_after_native):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                manifest.prepare_manifest(config, self.runner)

    def test_missing_is_successful_publication(self):
        config = self.config(dependency_fixture(['missing.so']))
        output = self.directory / 'success.json'
        result = self.cli(config, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['summary']['missing_dependencies'], 1)
        self.assertFalse(report['ready_to_execute'])


if __name__ == '__main__':
    unittest.main()
