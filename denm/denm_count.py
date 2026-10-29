#!/usr/bin/env python3
"""
DENM Counter
Reads one or more PCAP files, decodes all DENMs (ETSI EN 302 637-3, DENM
release 2 ASN.1 in ./ASN) and prints how many DENMs were found and how many
unique actionIds (originatingStationId + sequenceNumber) they contain.

Reuses PCAP parsing (Ethernet / 802.11 / Radiotap link types) from
../ivim/ivim_zone_count.py.

Usage:
    python denm_count.py capture.pcap
    python denm_count.py file1.pcap file2.pcap
"""

import argparse
import glob
import sys
from collections import Counter
from pathlib import Path

import asn1tools

# ─── Reuse PCAP parsing from the IVIM tools ─────────────────────────────────

_IVIM_DIR = Path(__file__).parent.parent / 'ivim'
if str(_IVIM_DIR) not in sys.path:
    sys.path.insert(0, str(_IVIM_DIR))
from ivim_zone_count import iter_its_packets  # noqa: E402

# ─── Constants ──────────────────────────────────────────────────────────────

BTP_DENM_PORT = b'\x07\xd2'   # BTP destination port 2002 = DENM
DENM_MESSAGE_ID = 1           # ItsPduHeader.messageId for DENM
DEFAULT_ASN_DIR = Path(__file__).parent / 'ASN'
ASN_FILES = [
    'ETSI-ITS-CDD.asn',
    'DENM-PDU-Descriptions.asn',
]


def expand_pcaps(patterns: list) -> list:
    """Expand wildcards (e.g. *.pcap) ourselves, since Windows cmd does not."""
    files = []
    for pat in patterns:
        if any(c in pat for c in '*?['):
            matches = sorted(glob.glob(pat))
            if not matches:
                raise FileNotFoundError(f'No files match: {pat}')
            files.extend(matches)
        else:
            files.append(pat)
    return files


def compile_asn(asn_dir: Path):
    files = [str(asn_dir / n) for n in ASN_FILES]
    for f in files:
        if not Path(f).exists():
            raise FileNotFoundError(f'ASN.1 file not found: {f}')
    return asn1tools.compile_files(files, codec='uper')


def extract_denm(pkt: bytes, db):
    """Return (decoded DENM dict | None, candidate_found: bool).

    candidate_found is True if a BTP port 2002 + messageId=1 pattern was seen
    even if UPER decoding failed (e.g. DENM of a different protocol version).
    """
    candidate = False
    pos = 0
    while True:
        idx = pkt.find(BTP_DENM_PORT, pos)
        if idx == -1:
            return None, candidate
        pos = idx + 1
        start = idx + 4
        if start + 6 >= len(pkt) or pkt[start + 1] != DENM_MESSAGE_ID:
            continue
        candidate = True
        try:
            return db.decode('DENM', pkt[start:]), True
        except Exception:
            continue


def process(pcap_files: list, asn_dir: Path) -> None:
    db = compile_asn(asn_dir)

    for pcap_file in expand_pcaps(pcap_files):
        n_pkt = n_denm = n_undecodable = 0
        action_ids: Counter = Counter()
        versions: Counter = Counter()

        for pkt in iter_its_packets(pcap_file):
            n_pkt += 1
            denm, candidate = extract_denm(pkt, db)
            if denm is None:
                if candidate:
                    n_undecodable += 1
                continue
            n_denm += 1
            versions[denm['header']['protocolVersion']] += 1
            aid = denm['denm']['management']['actionId']
            action_ids[(aid['originatingStationId'], aid['sequenceNumber'])] += 1

        print(f'\nFile: {Path(pcap_file).name}')
        print(f'  ITS-G5 packets            : {n_pkt}')
        print(f'  DENMs decoded             : {n_denm}')
        if n_undecodable:
            print(f'  DENM candidates undecodable: {n_undecodable}')
        print(f'  Unique actionIds          : {len(action_ids)}')
        if action_ids:
            print()
            print(f'  {"originatingStationId":>20}  {"sequenceNumber":>14}  {"DENMs":>6}')
            print('  ' + '-' * 44)
            for (station, seq), cnt in sorted(action_ids.items()):
                print(f'  {station:>20}  {seq:>14}  {cnt:>6}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Count DENMs and unique actionIds in PCAP files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP', help='Input PCAP file(s)')
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
