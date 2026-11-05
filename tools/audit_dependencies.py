#!/usr/bin/env python3
"""Read-only dependency evidence manifest; no provider lookup or plan application."""

import argparse
import copy
import json
from pathlib import Path
import re

from audit_linker import ROOT, audit, publish, require

PLATFORM_FIELDS = ('android_api', 'device_build', 'target_sdk', 'namespace',
                   'main_executable', 'preload', 'load_order')


def text(value):
    return isinstance(value, str) and bool(value.strip())


def keys(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value) <=
            set(required) | set(optional), 'invalid manifest fields')


def validate_contract(config):
    keys(config, ('schema_version', 'objects', 'guest_page_size', 'edges'),
         ('platform_evidence', 'assumptions'))
    require(type(config['schema_version']) is int and config['schema_version'] == 1,
            'unsupported manifest schema')
    page = config['guest_page_size']
    require(type(page) is int and 0 < page < 1 << 64 and not page & (page - 1),
            'invalid explicit guest page size')
    objects = config['objects']
    require(isinstance(objects, list) and objects, 'explicit nonempty objects required')
    ids = set()
    for obj in objects:
        keys(obj, ('instance_id', 'path', 'sha256', 'load_bias'))
        oid = obj['instance_id']
        require(text(oid) and oid not in ids, 'duplicate or invalid instance ID')
        ids.add(oid)
        require(text(obj['path']), 'explicit path required')
        require(isinstance(obj['sha256'], str) and
                re.fullmatch('[0-9a-f]{64}', obj['sha256']) is not None,
                'expected lowercase SHA-256 required')
        require(type(obj['load_bias']) is int and 0 <= obj['load_bias'] < 1 << 64,
                'explicit uint64 load bias required')
    require(isinstance(config['edges'], list), 'explicit edge list required')
    seen = set()
    for edge in config['edges']:
        keys(edge, ('from_instance', 'table_section', 'index', 'to_instance', 'source'))
        require(text(edge['from_instance']) and edge['from_instance'] in ids,
                'unknown edge source instance')
        require(type(edge['table_section']) is int and edge['table_section'] > 0 and
                type(edge['index']) is int and edge['index'] >= 0, 'invalid DT_NEEDED identity')
        require(edge['to_instance'] is None or
                (text(edge['to_instance']) and edge['to_instance'] in ids),
                'unknown edge target instance')
        require(text(edge['source']), 'edge evidence source required')
        identity = (edge['from_instance'], edge['table_section'], edge['index'])
        require(identity not in seen, 'duplicate DT_NEEDED edge')
        seen.add(identity)
    platform = config.get('platform_evidence', {})
    require(isinstance(platform, dict) and set(platform) <= set(PLATFORM_FIELDS),
            'unknown platform evidence field')
    for entry in platform.values():
        keys(entry, ('status', 'value', 'sources'))
        require(isinstance(entry['sources'], list) and all(text(s) for s in entry['sources']),
                'invalid evidence sources')
        require((entry['status'] == 'known' and entry['value'] is not None and entry['sources']) or
                (entry['status'] == 'unknown' and entry['value'] is None and not entry['sources']),
                'known evidence needs value/sources; unknown needs null/empty sources')
    assumptions = config.get('assumptions', [])
    require(isinstance(assumptions, list) and all(text(s) for s in assumptions),
            'invalid explicit assumptions')


def cycle_components(ids, edges):
    """Iterative strongly connected components, including self edges, without recursion."""
    forward, reverse = {i: [] for i in ids}, {i: [] for i in ids}
    for edge in edges:
        a, b = edge['from_instance'], edge['to_instance']
        if b is not None:
            forward[a].append(b)
            reverse[b].append(a)
    visited, order = set(), []
    for root in ids:
        stack = [(root, False)]
        while stack:
            node, finished = stack.pop()
            if finished:
                order.append(node)
            elif node not in visited:
                visited.add(node)
                stack.append((node, True))
                stack.extend((n, False) for n in reversed(forward[node]) if n not in visited)
    visited, components = set(), []
    for root in reversed(order):
        if root in visited:
            continue
        members, stack = set(), [root]
        visited.add(root)
        while stack:
            node = stack.pop()
            members.add(node)
            for n in reverse[node]:
                if n not in visited:
                    visited.add(n)
                    stack.append(n)
        if len(members) > 1 or root in forward[root]:
            components.append([i for i in ids if i in members])
    return components


def compose_manifest(config, objects):
    """Pure composition of trusted native audit snapshots, never untrusted reports.

    prepare_manifest is the file validation entry point. No mutable image or
    runner is available here; snapshots and all nested inventories stay owned
    by the caller. Each object is an isolated inventory, not a process mapping.
    """
    validate_contract(config)
    require([o['instance_id'] for o in objects] ==
            [o['instance_id'] for o in config['objects']], 'snapshot instance mismatch')
    objects = copy.deepcopy(objects)
    supplied = {(e['from_instance'], e['table_section'], e['index']): e
                for e in config['edges']}
    edges, requirements = [], []
    for obj, declared in zip(objects, config['objects']):
        image, oid = obj['image'], obj['instance_id']
        require(image['sha256'] == declared['sha256'] and
                image['load_bias'] == declared['load_bias'] and
                image['guest_page_size'] == config['guest_page_size'] and
                image['ready_to_execute'] is False, 'snapshot identity/status mismatch')
        ordinal = 0
        for entry in image['dynamic']:
            if entry['tag'] != 1:
                continue
            key = (oid, entry['table_section'], entry['index'])
            link = supplied.pop(key, None)
            target = link['to_instance'] if link else None
            edges.append(dict(from_instance=oid, to_instance=target,
                              status='available' if target is not None else 'missing',
                              needed_ordinal=ordinal, needed=copy.deepcopy(entry),
                              association_source=link['source'] if link else None,
                              association_status='explicit' if link else 'not_supplied',
                              provider='unknown', implementation='unknown', bridge='unknown'))
            ordinal += 1
        require([e['string'] for e in image['dynamic'] if e['tag'] == 1] ==
                image['needed_libraries'], 'DT_NEEDED native inventory mismatch')
        special = image['special_requirements']
        counts = {field: len(special[field]) for field in
                  ('tls_symbols', 'tls_sections', 'tls_segments', 'ifunc_symbols',
                   'extra_symbol_attributes')}
        counts.update(version_records=len(image['symbol_versions']['records']),
                      version_tables=len(image['symbol_versions']['tables']),
                      versioned_symbol_entries=sum(s['version'] is not None for s in image['symbols']))
        requirements.append(dict(instance_id=oid, summary=counts,
                                 versions=copy.deepcopy(image['symbol_versions']),
                                 special=copy.deepcopy(special),
                                 relocation_types=copy.deepcopy(image['summary']['unresolved_by_type']),
                                 implementation='unknown', bridge='unknown'))
    require(not supplied, 'edge does not reference a DT_NEEDED entry')
    platform = {field: copy.deepcopy(config.get('platform_evidence', {}).get(field,
                dict(status='unknown', value=None, sources=[]))) for field in PLATFORM_FIELDS}
    missing = [copy.deepcopy(e) for e in edges if e['status'] == 'missing']
    ids = [o['instance_id'] for o in objects]
    return dict(schema_version=1, profile='explicit-dependency-evidence-v1',
                facts=dict(objects=objects, dependency_edges=edges,
                           cycle_components=cycle_components(ids, edges),
                           platform_evidence=platform, requirements=requirements),
                assumptions=copy.deepcopy(config.get('assumptions', [])),
                missing_dependencies=missing,
                unknowns=dict(platform=[k for k, v in platform.items() if v['status'] == 'unknown'],
                              dependency_closure='unknown', android_lookup_scope='unknown',
                              symbol_providers='unknown', implementation='unknown', bridge='unknown'),
                limitations=['Only explicitly supplied files are inspected; no filesystem search',
                             'Edge associations are caller evidence, not verified Android provider selection',
                             'DT_NEEDED order, SONAME and paths do not establish lookup scope',
                             'Transitive dependencies of missing files and runtime loads are unknown',
                             'Native ELF/relocation/RELRO support is unchanged; images are isolated',
                             'Platform evidence is caller-attributed, not independently authenticated'],
                summary=dict(available_files=len(objects), dependency_edges=len(edges),
                             available_edges=len(edges) - len(missing), missing_dependencies=len(missing)),
                preparation='Existing isolated native audit preparation only; no additional fixups',
                audit_effect='Read-only snapshots; no symbol selection, guest calls or resolution plan',
                plan_applied=False, ready_to_execute=False)


def prepare_manifest(config, runner, base=ROOT):
    validate_contract(config)
    objects = []
    for obj in config['objects']:
        image = audit(Path(base) / obj['path'], obj['sha256'], obj['load_bias'],
                      config['guest_page_size'], runner)
        objects.append(dict(instance_id=obj['instance_id'], path=obj['path'],
                            sha256=image['sha256'], load_bias=image['load_bias'], image=image))
    return compose_manifest(config, objects)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--runner', type=Path, default=ROOT / 'build/recomp_image_smoke')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/dependency-evidence.json')
    args = parser.parse_args()
    report = prepare_manifest(json.loads(args.manifest.read_text()), args.runner)
    publish(report, args.output)
    print(json.dumps(report['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
