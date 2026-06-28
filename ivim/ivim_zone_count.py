#!/usr/bin/env python3
"""
IVIM Zone Counter
Reads one or more PCAP files and prints, for each unique IVIM
(identified by iviIdentificationNumber), the number of detection,
awareness and relevance zones defined in the GeneralIviContainer.

Usage:
    python ivim_zone_count.py SingleIVIM.pcap
    python ivim_zone_count.py AllCaptures.pcap
    python ivim_zone_count.py file1.pcap file2.pcap
"""

import argparse
import struct
import sys
from pathlib import Path

import asn1tools

# ─── Constants (shared with ivim_to_kml.py / ivim_croads_check.py) ────────────

BTP_IVIM_PORT = b'\x07\xd6'   # BTP destination port 2006 = IVIM
DEFAULT_ASN_DIR = Path(__file__).parent / 'ASN'
ASN_FILES = [
    'ETSI-ITS-CDD.asn',
    'ISO 17573-3 EfcDataDictionary V1.6.asn',
    'ISO19321IVIv3.1_patched.asn',
    'ISO_14823-1 ed1_AnnexE.asn',
    'IVIM-PDU-Descriptions.asn',
]

# ─── ASN.1 helpers ─────────────────────────────────────────────────────────────

def ensure_patched_asn(asn_dir: Path) -> None:
    patched = asn_dir / 'ISO19321IVIv3.1_patched.asn'
    if patched.exists():
        return
    original = asn_dir / 'ISO19321IVIv3.1.asn'
    if not original.exists():
        raise FileNotFoundError(f'Required ASN.1 file not found: {original}')
    patched.write_text(
        original.read_text(encoding='utf-8').replace('RELATIVE-OID', 'OBJECT IDENTIFIER'),
        encoding='utf-8')


def compile_asn(asn_dir: Path):
    ensure_patched_asn(asn_dir)
    files = [str(asn_dir / n) for n in ASN_FILES]
    for f in files:
        if not Path(f).exists():
            raise FileNotFoundError(f'ASN.1 file not found: {f}')
    return asn1tools.compile_files(files, codec='uper')


# ─── PCAP helpers ──────────────────────────────────────────────────────────────

def iter_its_packets(pcap_path: str):
    """Yield raw packet bytes for ITS-G5 (Ethertype 0x8947) frames."""
    with open(pcap_path, 'rb') as f:
        raw = f.read()
    magic = struct.unpack('<I', raw[:4])[0]
    if magic not in (0xa1b2c3d4, 0xa1b23c4d):
        raise ValueError(f'Not a supported PCAP file (magic={hex(magic)})')
    offset = 24
    while offset + 16 <= len(raw):
        _ts, _us, incl_len, _orig = struct.unpack('<IIII', raw[offset:offset + 16])
        pkt = raw[offset + 16:offset + 16 + incl_len]
        offset += 16 + incl_len
        if len(pkt) >= 14 and struct.unpack('>H', pkt[12:14])[0] == 0x8947:
            yield pkt


def extract_ivim(pkt: bytes, db):
    """Return decoded IVIM dict or None."""
    pos = 0
    while True:
        idx = pkt.find(BTP_IVIM_PORT, pos)
        if idx == -1:
            return None
        pos = idx + 1
        start = idx + 4
        if start + 6 >= len(pkt):
            continue
        if pkt[start + 1] != 6:
            continue
        try:
            return db.decode('IVIM', pkt[start:])
        except Exception:
            continue


# ─── Zone counting ─────────────────────────────────────────────────────────────

def count_zones(ivim: dict) -> dict:
    """
    Return zone counts per GicPart from the GeneralIviContainer.
    Result: {'detection': int, 'awareness': int, 'relevance': int}
    Sums across all GicParts (a single IVIM may carry multiple GicParts,
    each referencing its own sets of zone IDs).
    """
    optional = ivim['ivi'].get('optional') or []
    det = awa = rel = 0
    for ctype, cdata in optional:
        if ctype == 'giv':
            for gic_part in cdata:
                det += len(gic_part.get('detectionZoneIds') or [])
                awa += len(gic_part.get('driverAwarenessZoneIds') or [])
                rel += len(gic_part.get('relevanceZoneIds') or [])
    return {'detection': det, 'awareness': awa, 'relevance': rel}


# ─── Main ──────────────────────────────────────────────────────────────────────

def process(pcap_files: list, asn_dir: Path) -> None:
    print(f'Compiling ASN.1 definitions from: {asn_dir}')
    db = compile_asn(asn_dir)
    print('ASN.1 compilation successful.\n')

    # Collect first occurrence of each unique ivi_id across all input files
    ivim_cache: dict[int, dict] = {}
    for pcap_file in pcap_files:
        for pkt in iter_its_packets(pcap_file):
            ivim = extract_ivim(pkt, db)
            if ivim is None:
                continue
            ivi_id = ivim['ivi']['mandatory']['iviIdentificationNumber']
            if ivi_id not in ivim_cache:
                ivim_cache[ivi_id] = ivim

    if not ivim_cache:
        print('No IVIM messages found.')
        return

    # Print table
    col_id  = max(len('ivi_id'), max(len(str(k)) for k in ivim_cache))
    header  = (f'{"ivi_id":<{col_id}}  {"status":<13}  '
               f'{"detection":>9}  {"awareness":>9}  {"relevance":>9}')
    sep     = '-' * len(header)

    src = ', '.join(Path(p).name for p in pcap_files)
    print(f'Source : {src}')
    print(f'IVIMs  : {len(ivim_cache)} unique iviIdentificationNumber(s)\n')
    print(header)
    print(sep)

    status_names = {0: 'new', 1: 'update', 2: 'cancellation', 3: 'negation'}
    for ivi_id, ivim in sorted(ivim_cache.items()):
        status = ivim['ivi']['mandatory']['iviStatus']
        s_label = status_names.get(status, str(status))
        counts  = count_zones(ivim)
        print(f'{ivi_id:<{col_id}}  {s_label:<13}  '
              f'{counts["detection"]:>9}  '
              f'{counts["awareness"]:>9}  '
              f'{counts["relevance"]:>9}')

    print(sep)
    # Column totals
    all_counts = [count_zones(v) for v in ivim_cache.values()]
    tot_det = sum(c['detection'] for c in all_counts)
    tot_awa = sum(c['awareness'] for c in all_counts)
    tot_rel = sum(c['relevance'] for c in all_counts)
    print(f'{"TOTAL":<{col_id}}  {"":13}  '
          f'{tot_det:>9}  {tot_awa:>9}  {tot_rel:>9}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Count detection / awareness / relevance zones per IVIM in a PCAP.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s)')
    parser.add_argument('--asn-dir', type=Path, default=DEFAULT_ASN_DIR,
                        metavar='DIR',
                        help=f'Directory with ASN.1 files (default: {DEFAULT_ASN_DIR})')
    args = parser.parse_args()

    try:
        process(args.pcap, args.asn_dir)
    except (FileNotFoundError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
