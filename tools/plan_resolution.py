#!/usr/bin/env python3
"""Read-only two-object guest symbol plan under an explicit prototype scope."""

import argparse
from collections import Counter
import copy
import json
from pathlib import Path

from audit_linker import ROOT, audit, publish, require

LIMIT = 1 << 64
STATUS = dict(planned='Supported symbol selection only; no relocation or implementation supplied',
              missing_strong='No eligible definition for a GLOBAL undefined reference',
              missing_weak='No eligible definition for a WEAK undefined reference; no stub or fixup',
              unsupported='Reference or a potentially decisive candidate needs unsupported semantics')


def identity(object_id, symbol):
    return dict(object_id=object_id, table_section=symbol['table_section'], index=symbol['index'])


def validate_contract(objects, scope, references):
    require(isinstance(objects, list) and len(objects) == 2, 'exactly two objects required')
    ids = [o['object_id'] for o in objects]
    require(all(isinstance(i, str) and i for i in ids) and len(set(ids)) == 2,
            'object IDs must be distinct nonempty strings')
    require(isinstance(scope, list) and all(isinstance(i, str) for i in scope) and
            len(scope) == 2 and len(set(scope)) == 2 and set(scope) == set(ids),
            'scope must explicitly order both object IDs exactly once')
    require(isinstance(references, list) and references, 'explicit nonempty references required')
    keys = []
    for ref in references:
        require(set(ref) == {'object_id', 'table_section', 'index'} and
                ref['object_id'] in ids and
                type(ref['table_section']) is int and ref['table_section'] > 0 and
                type(ref['index']) is int and ref['index'] > 0, 'invalid symbol reference identity')
        keys.append((ref['object_id'], ref['table_section'], ref['index']))
    require(len(set(keys)) == len(keys), 'duplicate reference identity')


def policy_issues(image):
    # These tags are inventory/address metadata only in this symbol-only profile.
    # Unknown tags and flags are not silently interpreted as harmless policy.
    neutral = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18,
               19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 32, 33,
               0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffa,
               0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff}
    issues = []
    for d in image['dynamic']:
        tag, value = d['tag'], d['value']
        if ((tag == 30 and value & ~8) or (tag == 0x6ffffffb and value & ~1) or
                (tag not in neutral and tag not in (30, 0x6ffffffb))):
            issues.append(dict(reason='dynamic_lookup_policy_unsupported', entry=d))
    return issues


def symbol_issue(image, symbol):
    if symbol['version'] is not None:
        return 'symbol_versioning_unsupported'
    if symbol['other'] & ~3:
        return 'symbol_attributes_unsupported'
    if symbol['type'] == 6:
        return 'tls_unsupported'
    if symbol['type'] == 10:
        return 'ifunc_unsupported'
    if symbol['type'] == 5 or symbol['section_index'] == 0xfff2:
        return 'common_unsupported'
    if symbol['type'] not in (1, 2):
        return 'symbol_type_unsupported'
    if symbol['binding'] not in (0, 1, 2):
        return 'symbol_binding_unsupported'
    if symbol['binding'] == 0 and symbol['visibility'] == 3:
        return 'local_protected_invalid'
    if symbol['binding'] == 2 and symbol['section_index']:
        return 'weak_definition_policy_unsupported'
    if symbol['section_index']:
        index = symbol['section_index']
        # Absolute/special values need a separate profile; no bias is guessed.
        if index >= 0xff00:
            return 'special_section_unsupported'
        section = image['section_headers'][index]
        if section['flags'] & 0x400:
            return 'tls_unsupported'
        if section['flags'] & ~7:
            return 'symbol_section_attributes_unsupported'
        if section['address'] + section['size'] >= LIMIT:
            return 'symbol_section_extent_unsupported'
        if not section['flags'] & 2:
            return 'nonallocated_symbol_section'
        offset = symbol['value'] - section['address']
        if offset < 0 or offset > section['size'] or symbol['size'] > section['size'] - offset:
            return 'symbol_outside_section'
    return None


def guest_address(image, symbol):
    address = image['load_bias'] + symbol['value']
    if not 0 <= address < LIMIT or symbol['size'] > LIMIT - address:
        return None, 'guest_address_overflow'
    # A zero-size end marker is allowed, as in the internal relocation profile.
    for p in image['special_requirements']['program_headers']:
        if p['type'] != 1:
            continue
        offset = symbol['value'] - p['virtual_address']
        if 0 <= offset <= p['memory_size'] and symbol['size'] <= p['memory_size'] - offset:
            return address, None
    return None, 'symbol_outside_load_mapping'


def plan_reference(ref, by_id, scope):
    image = by_id[ref['object_id']]['image']
    symbol = next((s for s in image['symbols'] if
                   (s['table_section'], s['index']) == (ref['table_section'], ref['index'])), None)
    require(symbol is not None, 'reference absent from native symbol inventory')
    entry = dict(reference=dict(ref), referenced_symbol=copy.deepcopy(symbol),
                 status='unsupported', selected=None, candidates=[], diagnostics=[],
                 implementation='unknown', bridge='unknown', plan_applied=False)

    def unsupported(reason):
        entry['diagnostics'].append(reason)
        return entry

    issue = symbol_issue(image, symbol)
    if issue:
        return unsupported(issue)
    internal = symbol['binding'] == 0 or symbol['visibility'] in (1, 2, 3)
    if internal:
        if not symbol['section_index']:
            return unsupported('undefined_internal_reference_policy_unsupported')
        address, issue = guest_address(image, symbol)
        if issue:
            return unsupported(issue)
        entry.update(status='planned', selected=dict(identity=dict(ref), guest_address=address,
                     reason='non_preemptible_internal_identity', symbol=copy.deepcopy(symbol)))
        return entry
    if symbol['table_type'] != 11:
        return unsupported('external_reference_requires_dynsym')
    if not symbol['name']:
        return unsupported('unnamed_external_reference')
    # A policy requirement anywhere in the declared scope may affect the answer.
    policies = [dict(object_id=oid, issues=policy_issues(by_id[oid]['image'])) for oid in scope]
    policies = [p for p in policies if p['issues']]
    if policies:
        entry['policy_diagnostics'] = policies
        return unsupported('scope_lookup_policy_unsupported')
    for position, oid in enumerate(scope):
        provider = by_id[oid]['image']
        possible = []
        for candidate in provider['symbols']:
            if candidate['name'] != symbol['name'] or not candidate['index']:
                continue
            fact = dict(identity=identity(oid, candidate), scope_position=position,
                        symbol=copy.deepcopy(candidate))
            entry['candidates'].append(fact)
            if candidate['table_type'] != 11:
                fact.update(disposition='rejected', reason='not_dynamic_symbol')
            elif not candidate['section_index']:
                fact.update(disposition='rejected', reason='undefined_not_provider')
            elif candidate['binding'] == 0:
                fact.update(disposition='rejected', reason='local_not_exported')
            elif candidate['visibility'] in (1, 2) and not candidate['other'] & ~3:
                fact.update(disposition='rejected', reason='hidden_or_internal_not_exported')
            else:
                possible.append((candidate, fact))
        if not possible:
            continue
        # Table/index order is not ELF hash-chain precedence. Never guess between
        # duplicate dynamic definitions in one instance, even if values agree.
        if len(possible) != 1:
            for _, fact in possible:
                fact.update(disposition='unsupported', reason='ambiguous_dynamic_definitions')
            return unsupported('ambiguous_dynamic_definitions')
        candidate, fact = possible[0]
        issue = symbol_issue(provider, candidate)
        if not issue and candidate['type'] != symbol['type']:
            issue = 'symbol_type_matching_policy_unsupported'
        address, address_issue = guest_address(provider, candidate) if not issue else (None, None)
        issue = issue or address_issue
        if issue:
            fact.update(disposition='unsupported', reason=issue)
            return unsupported(issue)
        fact.update(disposition='selected', reason='first_eligible_definition_in_explicit_scope')
        entry.update(status='planned', selected=dict(identity=identity(oid, candidate),
                     guest_address=address, symbol=copy.deepcopy(candidate), reason=fact['reason']))
        entry['lookup_stopped_after_scope_position'] = position
        return entry
    if symbol['section_index']:
        return unsupported('defined_reference_without_scope_provider')
    entry.update(status='missing_weak' if symbol['binding'] == 2 else 'missing_strong')
    entry['diagnostics'].append('no_eligible_definition_in_explicit_scope')
    return entry


def compose_plan(objects, scope, references):
    """Pure function over trusted, hash-verified audit snapshots; no image handle.

    Use prepare_plan for untrusted files. This function cannot apply relocations,
    change permissions, or call guest code. Inputs remain owned by the caller.
    """
    validate_contract(objects, scope, references)
    by_id = {o['object_id']: o for o in objects}
    ranges = []
    for obj in objects:
        image = obj['image']
        require(image['ready_to_execute'] is False, 'unexpected execution readiness')
        for p in image['special_requirements']['program_headers']:
            if p['type'] == 1 and p['memory_size']:
                lo = image['load_bias'] + p['virtual_address']
                hi = lo + p['memory_size']
                require(0 <= lo < hi < LIMIT, 'object mapping address overflow')
                require(not any(lo < b and a < hi for a, b in ranges),
                        'object guest mappings overlap')
                ranges.append((lo, hi))
    entries = [plan_reference(ref, by_id, scope) for ref in references]
    return dict(schema_version=1, profile='explicit-two-object-unversioned-v1',
                facts=dict(objects=copy.deepcopy(objects), lookup_scope=list(scope),
                           references=copy.deepcopy(references)),
                assumptions=['Caller supplies the complete ordered scope for these references; '
                             'this is a prototype profile, not inferred Android policy'],
                unknowns=['Android API/namespace/process scope and dependency closure',
                          'platform implementations, bridges and compiled-entry dispatch'],
                status_definitions=STATUS.copy(), entries=entries,
                summary=dict(Counter(e['status'] for e in entries)),
                preparation='Separate isolated native images: existing supported RELA and RELRO checks',
                planner_effect='Read-only snapshots; symbol selections only; no fixups or guest calls',
                plan_applied=False, ready_to_execute=False)


def prepare_plan(config, runner, base=ROOT):
    """Validate every supplied file with its hash/native audit before publication."""
    validate_contract(config['objects'], config['lookup_scope'], config['references'])
    require(type(config['guest_page_size']) is int, 'explicit integer guest page size required')
    objects = []
    for obj in config['objects']:
        require(type(obj['load_bias']) is int, 'explicit integer load bias required')
        image = audit(Path(base) / obj['input'], obj['sha256'], obj['load_bias'],
                      config['guest_page_size'], runner)
        objects.append(dict(object_id=obj['object_id'], sha256=image['sha256'],
                            load_bias=image['load_bias'], image=image))
    return compose_plan(objects, config['lookup_scope'], config['references'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--runner', type=Path, default=ROOT / 'build/recomp_image_smoke')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/resolution-plan.json')
    args = parser.parse_args()
    report = prepare_plan(json.loads(args.config.read_text()), args.runner)
    publish(report, args.output)
    print(json.dumps(report['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
