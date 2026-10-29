#!/usr/bin/env python3
"""
DENM Zone Counter
For every unique DENM (identified by actionId = originatingStationId +
sequenceNumber) in one or more PCAP files, prints one row per zone:

  - each trace (detection zone: location.detectionZonesToEventPosition, one
    trace = one Path) and the eventZone (relevance zone: situation.eventZone)
  - the number of points (items of the Path / of the eventZone)
  - the length in metres, calculated with the eventPosition as the start of
    the polyline
  - the event type of the DENM (cause(code) subcause(code), e.g. roadworks(3) unavailable(0);
    names read from the CDD ASN.1 file), shown on the first row of each actionId

The DENM equivalent of the IVIM referencePosition is management.eventPosition.
Deltas are cumulative: the first point is relative to the eventPosition, every
further point is relative to the previous one (same as the IVIM GLC zones).
Lengths are horizontal (haversine, altitude ignored).

Uses the first DENM seen for each actionId.

Reuses PCAP parsing, ASN.1 compilation and DENM extraction from denm_count.py
and the haversine/polyline length helpers from ../ivim/ivs-ts.

The complete output (ASN.1 loading, per-file tables) is printed to the console
and also written to a text file (default: denm_zones_report.txt, see -o).

Usage:
    python denm_zones.py capture.pcap
    python denm_zones.py file1.pcap file2.pcap -o report.txt
"""

import argparse
import sys
from pathlib import Path

from denm_common import denm_event_type, load_cause_names
from denm_count import ASN_FILES, DEFAULT_ASN_DIR, compile_asn, expand_pcaps, extract_denm, iter_its_packets

_IVS_TS_DIR = Path(__file__).parent.parent / 'ivim' / 'ivs-ts'
if str(_IVS_TS_DIR) not in sys.path:
    sys.path.insert(0, str(_IVS_TS_DIR))
from ivs_ts_croads_check import polyline_length  # noqa: E402

COORD_SCALE = 1e7   # ETSI raw integer -> degrees


def cumulative_points(ref_lat_raw: int, ref_lon_raw: int, deltas: list,
                      field: str) -> list:
    """Cumulative (lat°, lon°) points for a list of {field: {deltaLatitude,...}}."""
    lat, lon = ref_lat_raw, ref_lon_raw
    pts = []
    for item in deltas:
        d = item[field]
        lat += d['deltaLatitude']
        lon += d['deltaLongitude']
        pts.append((lat / COORD_SCALE, lon / COORD_SCALE))
    return pts


def zone_rows(denm: dict) -> tuple:
    """Return (rows, has_location) for one decoded DENM.

    Each row: (label, n_points, length_incl_eventPos_m)
    or (label, 0, None) for an absent eventZone.
    """
    payload = denm['denm']
    ep = payload['management']['eventPosition']
    ref_lat, ref_lon = ep['latitude'], ep['longitude']
    ref = (ref_lat / COORD_SCALE, ref_lon / COORD_SCALE)

    def measure(label, pts):
        return (label, len(pts), polyline_length([ref] + pts))

    rows = []
    location = payload.get('location')
    situation = payload.get('situation')

    if location is not None:
        for i, path in enumerate(location.get('detectionZonesToEventPosition') or [], 1):
            rows.append(measure(f'trace {i}',
                                cumulative_points(ref_lat, ref_lon, path, 'pathPosition')))

    if situation is not None:
        ez = situation.get('eventZone')
        if ez:
            rows.append(measure('eventZone',
                                cumulative_points(ref_lat, ref_lon, ez, 'eventPosition')))
        else:
            rows.append(('eventZone', 0, None))

    return rows, location is not None


def process(pcap_files: list, asn_dir: Path, output: str) -> None:
    lines: list = []

    def emit(text: str = '') -> None:
        print(text)
        lines.append(text)

    emit(f'Compiling ASN.1 definitions from: {asn_dir}')
    for name in ASN_FILES:
        emit(f'  - {name}')
    db = compile_asn(asn_dir)
    emit('ASN.1 compilation successful.')
    names = load_cause_names(asn_dir)

    for pcap_file in expand_pcaps(pcap_files):
        first_seen: dict = {}   # actionId -> (rows, has_location, terminated, event type)
        event_types: dict = {}  # actionId -> set of event type texts seen
        n_denm = 0

        for pkt in iter_its_packets(pcap_file):
            denm, _ = extract_denm(pkt, db)
            if denm is None:
                continue
            n_denm += 1
            aid = denm['denm']['management']['actionId']
            key = (aid['originatingStationId'], aid['sequenceNumber'])
            etype = denm_event_type(denm, names)
            event_types.setdefault(key, set()).add(etype)
            if key not in first_seen:
                rows, has_loc = zone_rows(denm)
                first_seen[key] = (rows, has_loc,
                                   'termination' in denm['denm']['management'], etype)

        emit(f'\nFile: {Path(pcap_file).name}')
        emit(f'  DENMs decoded: {n_denm}   Unique actionIds: {len(first_seen)}\n')
        hdr = (f'  {"originatingStationId":>20}  {"sequenceNumber":>14}  {"zone":<10}  '
               f'{"points":>6}  {"length incl. eventPos (m)":>25}  '
               f'event type: cause(code) subcause(code)')
        emit(hdr)
        emit('  ' + '-' * (len(hdr) - 2 + 20))

        for key in sorted(first_seen):
            rows, has_loc, terminated, etype = first_seen[key]
            if len(event_types[key]) > 1:
                etype += f'  (+{len(event_types[key]) - 1} other event type(s))'
            if not rows:
                emit(f'  {key[0]:>20}  {key[1]:>14}  (no location/situation container'
                     f'{", termination" if terminated else ""})  {etype}')
                continue
            for n, (label, pts, length) in enumerate(rows):
                sid = f'{key[0]:>20}' if n == 0 else ' ' * 20
                seq = f'{key[1]:>14}' if n == 0 else ' ' * 14
                et = f'  {etype}' if n == 0 else ''
                if length is None:
                    emit(f'  {sid}  {seq}  {label:<10}  {"-":>6}  {"-":>25}{et}')
                else:
                    emit(f'  {sid}  {seq}  {label:<10}  {pts:>6}  {length:>25.1f}{et}')

    out = output if output.endswith('.txt') else output + '.txt'
    with open(out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'\nOutput written to: {out}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Count points and measure length of traces and eventZone per unique DENM.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP', help='Input PCAP file(s)')
    parser.add_argument('-o', '--output', default='denm_zones_report', metavar='FILE',
                        help='Output text file (default: denm_zones_report.txt)')
    parser.add_argument('--asn-dir', type=Path, default=DEFAULT_ASN_DIR,
                        metavar='DIR',
                        help=f'Directory with ASN.1 files (default: {DEFAULT_ASN_DIR})')
    args = parser.parse_args()
    try:
        process(args.pcap, args.asn_dir, args.output)
    except (FileNotFoundError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
