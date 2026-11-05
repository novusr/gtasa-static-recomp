#!/usr/bin/env python3
"""Audit verified guest ELF linking requirements; never resolve or execute symbols."""

import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSYM, VERDEF, VERNEED = 0x6fffffff, 0x6ffffffd, 0x6ffffffe
TAG_NAMES = {0: 'NULL', 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH',
             5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA', 8: 'RELASZ', 9: 'RELAENT',
             10: 'STRSZ', 11: 'SYMENT', 12: 'INIT', 13: 'FINI', 14: 'SONAME',
             15: 'RPATH', 16: 'SYMBOLIC', 17: 'REL', 18: 'RELSZ', 19: 'RELENT',
             20: 'PLTREL', 21: 'DEBUG', 22: 'TEXTREL', 23: 'JMPREL', 24: 'BIND_NOW',
             25: 'INIT_ARRAY', 26: 'FINI_ARRAY', 27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ',
             29: 'RUNPATH', 30: 'FLAGS', 32: 'PREINIT_ARRAY', 33: 'PREINIT_ARRAYSZ',
             0x6ffffef5: 'GNU_HASH', 0x6ffffff0: 'VERSYM', 0x6ffffff9: 'RELACOUNT',
             0x6ffffffa: 'RELCOUNT', 0x6ffffffb: 'FLAGS_1', 0x6ffffffc: 'VERDEF',
             0x6ffffffd: 'VERDEFNUM', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERNEEDNUM'}
RELOC_NAMES = {257: 'R_AARCH64_ABS64', 1025: 'R_AARCH64_GLOB_DAT',
               1026: 'R_AARCH64_JUMP_SLOT', 1027: 'R_AARCH64_RELATIVE',
               1028: 'R_AARCH64_TLS_DTPMOD64', 1029: 'R_AARCH64_TLS_DTPREL64',
               1030: 'R_AARCH64_TLS_TPREL64', 1031: 'R_AARCH64_TLSDESC',
               1032: 'R_AARCH64_IRELATIVE'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Metadata:
    """Additional section-based metadata, after the native ELF validation gate.

    All offsets are file offsets or section-relative offsets, never host pointers.
    Version chains are bounded, forward-only, nonoverlapping and count checked.
    Unknown tag/flag values remain raw facts, not implemented loader features.
    """
    def __init__(self, data):
        self.data = data
        shoff, = struct.unpack_from('<Q', data, 40)
        shnum, = struct.unpack_from('<H', data, 60)
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * 64)
                         for i in range(shnum)]

    def read(self, section, offset, fmt):
        size = struct.calcsize(fmt)
        require(0 <= offset <= section[5] - size, 'metadata record outside section')
        return struct.unpack_from(fmt, self.data, section[4] + offset)

    def string(self, table, offset):
        require(0 <= table < len(self.sections), 'invalid metadata string table link')
        section = self.sections[table]
        require(section[1] == 3 and 0 <= offset < section[5], 'invalid metadata string offset')
        end = self.data.find(b'\0', section[4] + offset, section[4] + section[5])
        require(end >= 0, 'unterminated metadata string')
        return self.data[section[4] + offset:end].decode('latin1')

    def dynamic(self):
        result = []
        for table, section in enumerate(self.sections):
            if section[1] != 6:
                continue
            for index in range(section[5] // 16):
                tag, value = self.read(section, index * 16, '<QQ')
                entry = dict(table_section=table, index=index, tag=tag,
                             tag_name='DT_' + TAG_NAMES[tag] if tag in TAG_NAMES else 'unknown',
                             value=value)
                if tag in (1, 14, 15, 29, 0x7ffffffd, 0x7fffffff):
                    entry['string'] = self.string(section[6], value)
                if tag in (30, 0x6ffffffb):
                    flags = ({1: 'ORIGIN', 2: 'SYMBOLIC', 4: 'TEXTREL', 8: 'BIND_NOW',
                              16: 'STATIC_TLS'} if tag == 30 else
                             {1: 'NOW', 2: 'GLOBAL', 8: 'NODELETE', 0x20: 'INITFIRST',
                              0x80: 'NOOPEN', 0x800: 'NODEFLIB', 0x8000000: 'PIE'})
                    entry['known_flags'] = [name for bit, name in flags.items() if value & bit]
                    entry['other_flag_bits'] = value & ~sum(flags)
                result.append(entry)
                if tag == 0:
                    break
        return result

    def versions(self, symbols, dynamic):
        records, versyms = [], []
        for table, section in enumerate(self.sections):
            kind = section[1]
            if kind == VERSYM:
                require(section[6] < len(self.sections) and
                        self.sections[section[6]][1] == 11, 'versym must link DYNSYM')
                require(section[9] == 2 and section[5] ==
                        self.sections[section[6]][5] // 24 * 2, 'invalid versym entry count/size')
                require(not any(v['symbol_table'] == section[6] for v in versyms),
                        'duplicate versym for symbol table')
                versyms.append(dict(section=table, symbol_table=section[6], entries=[
                    self.read(section, i, '<H')[0] for i in range(0, section[5], 2)]))
            if kind not in (VERDEF, VERNEED):
                continue
            require(section[6] < len(self.sections) and
                    self.sections[section[6]][1] == 3, 'version must link STRTAB')
            count, pos, used = section[7], 0, set()
            require(0 < count <= section[5] // (20 if kind == VERDEF else 16),
                    'invalid version record count')

            def claim(offset, size):
                require(0 <= offset <= section[5] - size, 'version record outside section')
                locations = set(range(offset, offset + size))
                require(not used.intersection(locations), 'overlapping version records')
                used.update(locations)

            for record_index in range(count):
                claim(pos, 20 if kind == VERDEF else 16)
                if kind == VERDEF:
                    version, flags, ndx, naux, hash_value, aux, nxt = self.read(section, pos, '<HHHHIII')
                    entry = dict(kind='definition', version_index=ndx, flags=flags, hash=hash_value)
                else:
                    version, naux, file_name, aux, nxt = self.read(section, pos, '<HHIII')
                    entry = dict(kind='requirement', dependency=self.string(section[6], file_name))
                require(version == 1 and naux > 0 and aux >= (20 if kind == VERDEF else 16),
                        'invalid version header')
                entry.update(section=table, index=record_index, names=[])
                apos = pos + aux
                require(naux <= section[5] // (8 if kind == VERDEF else 16), 'invalid version aux count')
                for ai in range(naux):
                    claim(apos, 8 if kind == VERDEF else 16)
                    if kind == VERDEF:
                        name, anext = self.read(section, apos, '<II')
                        item = dict(name=self.string(section[6], name))
                    else:
                        h, flags, ndx, name, anext = self.read(section, apos, '<IHHII')
                        item = dict(name=self.string(section[6], name), hash=h, flags=flags,
                                    version_index=ndx & 0x7fff, raw_other=ndx)
                    entry['names'].append(item)
                    require((anext == 0) if ai == naux - 1 else
                            anext >= (8 if kind == VERDEF else 16), 'invalid version aux chain')
                    apos += anext
                records.append(entry)
                require((nxt == 0) if record_index == count - 1 else
                        nxt >= (20 if kind == VERDEF else 16), 'invalid version chain')
                pos += nxt
        # Version dynamic pointers/counts must agree with section inventories.
        for dtable in sorted({d['table_section'] for d in dynamic}):
            tags = {d['tag']: d['value'] for d in dynamic if d['table_section'] == dtable}
            for pointer, number, kind in ((0x6ffffffc, 0x6ffffffd, VERDEF),
                                          (0x6ffffffe, 0x6fffffff, VERNEED),
                                          (0x6ffffff0, None, VERSYM)):
                if number is not None:
                    require((pointer in tags) == (number in tags), 'incomplete version dynamic tags')
                if pointer not in tags:
                    continue
                matches = [s for s in self.sections if s[1] == kind and s[3] == tags[pointer]]
                require(len(matches) == 1, 'version dynamic pointer lacks unique section')
                if number is not None:
                    require(matches[0][7] == tags[number], 'version dynamic count mismatch')
                    require(matches[0][6] == self.sections[dtable][6],
                            'version dynamic string-table mismatch')
                elif 6 in tags:
                    require(self.sections[matches[0][6]][3] == tags[6],
                            'versym dynamic symbol-table mismatch')
        by_identity = {}
        for v in versyms:
            strings = self.sections[v['symbol_table']][6]
            indices = {}
            for record in records:
                if self.sections[record['section']][6] != strings:
                    continue
                items = ([record] if record['kind'] == 'definition' else record['names'])
                for auxiliary_index, item in enumerate(items):
                    ndx = item['version_index']
                    require(ndx not in indices, 'duplicate version index')
                    indices[ndx] = dict(section=record['section'], index=record['index'],
                                        kind=record['kind'],
                                        auxiliary_index=auxiliary_index if record['kind'] == 'requirement' else None)
            for index, raw in enumerate(v['entries']):
                ndx = raw & 0x7fff
                require(ndx <= 1 or ndx in indices, 'versym index lacks version metadata')
                by_identity[(v['symbol_table'], index)] = dict(
                    section=v['section'], raw=raw, index=ndx, hidden=bool(raw & 0x8000),
                    record=indices.get(ndx))
        require(all((s['table_section'], s['index']) in by_identity
                    for s in symbols if any(v['symbol_table'] == s['table_section'] for v in versyms)),
                'incomplete native symbol inventory')
        return dict(present=bool(records or versyms), records=records, tables=versyms), by_identity


def compose_report(data, native):
    """Pure audit over captured bytes and an existing prepared-image inventory."""
    report = copy.deepcopy(native)
    metadata = Metadata(data)
    dynamic = metadata.dynamic()
    versions, symbol_versions = metadata.versions(report['symbols'], dynamic)
    symbols = report['symbols']
    for s in symbols:
        s['version'] = symbol_versions.get((s['table_section'], s['index']))
        s['provider'] = 'unknown'
        s['implementation'] = 'unknown'
    by_id = {(s['table_section'], s['index']): s for s in symbols}
    # Reconstruct imports from the complete native inventory, preserving identity.
    report['imports'] = [dict(s, status='unresolved') for s in symbols
                         if s['table_type'] == 11 and not s['section_index'] and s['name']]
    require(len(report['imports']) == len(native['imports']), 'native import count disagrees')
    # Source section/index disambiguates even duplicate relocation records.
    queues = defaultdict(list)
    for entries in (report['relocations'], report['applied_relocations']):
        for r in entries:
            s = r['definition']
            key = (r['address'], r['type'], s['table_section'], s['index'], r['addend_bits'])
            queues[key].append(r)
            r['symbol_identity'] = dict(table_section=s['table_section'], index=s['index'])
            r['type_name'] = RELOC_NAMES.get(r['type'], 'unknown')
            r['version'] = symbol_versions.get((s['table_section'], s['index']))
    for table, section in enumerate(metadata.sections):
        if section[1] not in (4, 9):
            continue
        for index in range(section[5] // section[9]):
            offset = index * section[9]
            target, info = metadata.read(section, offset, '<QQ')
            addend = metadata.read(section, offset + 16, '<Q')[0] if section[1] == 4 else 0
            key = (native['load_bias'] + target, info & 0xffffffff, section[6], info >> 32, addend)
            require(bool(queues[key]), 'relocation missing from native inventory')
            r = queues[key].pop(0)
            r.update(relocation_section=table, relocation_index=index,
                     format='RELA' if section[1] == 4 else 'REL')
    require(not any(queues.values()), 'extra native relocation entries')
    unresolved = report.pop('relocations')
    groups = Counter((r['reason'], r['type'], r['symbol_identity']['table_section'],
                      r['symbol_identity']['index']) for r in unresolved)
    references = defaultdict(list)
    for r in unresolved + report['applied_relocations']:
        references[(r['symbol_identity']['table_section'], r['symbol_identity']['index'])].append(
            dict(section=r['relocation_section'], index=r['relocation_index'], status=r['status']))
    for entry in report['imports']:
        entry['relocation_references'] = references[(entry['table_section'], entry['index'])]
    # ABI classification is distinct from the loader's conservative resolution reason.
    preemptible = [dict(s, relocation_references=references[(s['table_section'], s['index'])])
                   for s in symbols if s['index'] and s['section_index'] and
                   s['binding'] in (1, 2) and s['visibility'] == 0]
    phoff, = struct.unpack_from('<Q', data, 32)
    phnum, = struct.unpack_from('<H', data, 56)
    phdrs = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * 56) for i in range(phnum)]
    special = dict(tls_symbols=[dict(table_section=s['table_section'], index=s['index'])
                               for s in symbols if s['type'] == 6],
                   ifunc_symbols=[dict(table_section=s['table_section'], index=s['index'])
                                  for s in symbols if s['type'] == 10],
                   extra_symbol_attributes=[dict(table_section=s['table_section'], index=s['index'],
                                                 other=s['other']) for s in symbols if s['other'] & ~3],
                   tls_segments=[dict(program_header=i, virtual_address=p[3], file_size=p[5],
                                      memory_size=p[6], alignment=p[7])
                                 for i, p in enumerate(phdrs) if p[0] == 7],
                   tls_sections=[i for i, s in enumerate(metadata.sections) if s[2] & 0x400],
                   program_headers=[dict(index=i, type=p[0], flags=p[1], virtual_address=p[3],
                                         file_offset=p[2], file_size=p[5], memory_size=p[6], alignment=p[7])
                                    for i, p in enumerate(phdrs)])
    report.update(schema_version=1, evidence='hash-verified ELF bytes and native data-loader inventory',
                  guest_page_profile=dict(size=native['guest_page_size'], source='explicit caller input',
                      policy='Android RELRO page rounding intersected with exact PT_LOAD mappings',
                      device_compatibility='unknown'),
                  dynamic=dynamic, symbol_versions=versions, unresolved_relocations=unresolved,
                  section_headers=[dict(index=i, type=s[1], flags=s[2], address=s[3],
                                        size=s[5], link=s[6])
                                   for i, s in enumerate(metadata.sections)],
                  preemptible_definitions=preemptible, special_requirements=special,
                  dependencies=[dict(name=name, provider='unknown', implementation='unknown',
                                     evidence='DT_NEEDED; dependency file not inspected')
                                for name in native['needed_libraries']],
                  unresolved_groups=[dict(reason=reason, type=typ,
                                          symbol_identity=dict(table_section=table, index=index),
                                          symbol=by_id[(table, index)]['name'], count=count)
                                     for (reason, typ, table, index), count in sorted(groups.items())],
                  summary=dict(applied=len(report['applied_relocations']), unresolved=len(unresolved),
                               imports=len(report['imports']),
                               unresolved_by_reason=dict(Counter(r['reason'] for r in unresolved)),
                               unresolved_by_type=dict(Counter(str(r['type']) for r in unresolved)),
                               applied_by_type=dict(Counter(str(r['type']) for r in report['applied_relocations'])),
                               relocation_formats=dict(Counter(r['format'] for r in
                                   unresolved + report['applied_relocations']))),
                  assumptions=[], unknowns=['dependency binaries and transitive closure',
                      'Android API/target SDK, namespace and process lookup scope',
                      'selected symbol providers and platform implementations'],
                  preparation='isolated native load, explicit supported RELA application, explicit RELRO seal',
                  audit_effect='read-only inventory transformation; no resolver or guest calls',
                  ready_to_execute=False)
    return report


def audit(path, digest, bias, page_size, runner):
    require(0 <= bias < 1 << 64, 'invalid explicit load bias')
    require(0 < page_size < 1 << 64 and not page_size & (page_size - 1), 'invalid guest page size')
    with Path(path).open('rb') as source:
        data = source.read(536870913)
    require(len(data) <= 536870912, 'input exceeds native file limit')
    require(hashlib.sha256(data).hexdigest() == digest, 'audit input SHA-256 mismatch')
    # Both decoders consume the same captured hash-verified bytes, even if the
    # original input path is replaced during the audit.
    with tempfile.TemporaryDirectory(prefix='recomp-linker-audit-') as directory:
        captured = Path(directory) / 'input.elf'
        captured.write_bytes(data)
        result = subprocess.run([str(Path(runner).resolve()), str(captured), digest,
                                 str(bias), '536870912', '--all', str(page_size)],
                                check=True, capture_output=True, text=True)
    native = json.loads(result.stdout)
    require(native['sha256'] == digest and native['load_bias'] == bias and
            native['guest_page_size'] == page_size and native['relro_sealed'] and
            native['ready_to_execute'] is False, 'invalid native preparation status')
    return compose_report(data, native)


def publish(report, output):
    """Publish only a complete validated report, atomically replacing any prior run."""
    output = Path(output)
    payload = json.dumps(report, indent=2) + '\n'
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--runner', type=Path, default=ROOT / 'build/recomp_image_smoke')
    parser.add_argument('--load-bias', required=True, type=lambda s: int(s, 0))
    parser.add_argument('--guest-page-size', required=True, type=lambda s: int(s, 0))
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/linker-audit.json')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    report = audit(ROOT / config['input'], config['sha256'], args.load_bias,
                   args.guest_page_size, args.runner)
    publish(report, args.output)
    print(json.dumps(report['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
