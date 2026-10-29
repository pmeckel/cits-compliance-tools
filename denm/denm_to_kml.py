#!/usr/bin/env python3
"""
DENM PCAP → KML/KMZ Converter

DENM counterpart of ivim/ivim_to_kml.py. Parses C-ITS PCAP captures, extracts
DENM messages (ETSI EN 302 637-3, release 2) and their zones, and generates
KML/KMZ files for visualization in Google Earth, Google Maps, OpenStreetMap, etc.

Each actionId (originatingStationId + sequenceNumber) appears exactly once in
the output KML (first occurrence), even if the PCAP contains many repetitions.

The description of each eventPosition placemark states the event type with
cause code / sub cause code and their meaning (names read from the CDD ASN.1
file), e.g. "3 roadworks / 4 shortTermStationaryRoadworks".

The DENM eventPosition takes the role of the IVIM referencePosition and is
labeled with the actionId ("originatingStationId/sequenceNumber"). All deltas
are cumulative, starting at the eventPosition.

Zones are visualized with distinct colors (same palette as the IVIM tool):
  - traceX     (X = 1, 2, ...)  detection zones   : red
  - eventZone                   relevance zone    : green
  - awarenessArea (circle)      awareness area    : gold/yellow

Three DENM event types are drawn:
  - point event    : eventPosition + traces
  - linear event   : eventPosition + traces + eventZone
  - circular event : eventPosition + traces + awarenessDistance
                     (circle around the eventPosition; awarenessDistance is an
                     upper bound "lessThanXm", so the circle shows that bound;
                     "over10km" is drawn as 10 km)

Two output modes are available (--mode):
  lines   (default) – zones rendered as LineStrings (starting at the eventPosition)
  points  – each delta position rendered as an individual labeled Point
            (label format: trace1-Item0, eventZone-Item3, ...), grouped in one
            sub-folder per zone. The awareness circle is always drawn as a
            closed outline since it has no delta positions.

Reuses PCAP parsing, ASN.1 compilation and DENM extraction from denm_count.py
and the KML styling/serialisation helpers from ../ivim/ivim_to_kml.py.

Usage:
    python denm_to_kml.py capture.pcap
    python denm_to_kml.py *.pcap -o all_denms.kml
    python denm_to_kml.py capture.pcap --mode points -o denms_pts.kml
    python denm_to_kml.py *.pcap --kmz -o output
    python denm_to_kml.py capture.pcap --asn-dir /path/to/asn
"""

import argparse
import math
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from denm_count import (ASN_FILES, DEFAULT_ASN_DIR, compile_asn, expand_pcaps,
                        extract_denm, iter_its_packets)
from denm_common import describe_event_type, denm_event_type, load_cause_names
from ivim_to_kml import add_kml_styles, coords_to_kml_str, pretty_print_kml

# ETSI coordinate scale: raw integer → degrees (10^-7 degrees per unit)
COORD_SCALE = 1e7

# StandardLength3b (awarenessDistance) → upper bound in metres
AWARENESS_RADIUS_M = {
    'lessThan50m': 50, 'lessThan100m': 100, 'lessThan200m': 200,
    'lessThan500m': 500, 'lessThan1000m': 1000, 'lessThan5km': 5000,
    'lessThan10km': 10000, 'over10km': 10000,
}

EARTH_RADIUS_M = 6_371_000.0
CIRCLE_SEGMENTS = 72


# ─── Geometry helpers ─────────────────────────────────────────────────────────

def cumulative_points(ref_lat_raw: int, ref_lon_raw: int, items: list,
                      field: str) -> list:
    """Cumulative (lat°, lon°) points for a list of {field: {deltaLatitude,...}}."""
    lat, lon = ref_lat_raw, ref_lon_raw
    pts = []
    for item in items:
        d = item[field]
        lat += d['deltaLatitude']
        lon += d['deltaLongitude']
        pts.append((lat / COORD_SCALE, lon / COORD_SCALE))
    return pts


def circle_points(lat: float, lon: float, radius_m: float,
                  n: int = CIRCLE_SEGMENTS) -> list:
    """Closed ring of (lat°, lon°) points at radius_m around (lat, lon)."""
    lat_r, lon_r = math.radians(lat), math.radians(lon)
    ang = radius_m / EARTH_RADIUS_M
    pts = []
    for i in range(n + 1):
        brg = 2 * math.pi * i / n
        plat = math.asin(math.sin(lat_r) * math.cos(ang) +
                         math.cos(lat_r) * math.sin(ang) * math.cos(brg))
        plon = lon_r + math.atan2(math.sin(brg) * math.sin(ang) * math.cos(lat_r),
                                  math.cos(ang) - math.sin(lat_r) * math.sin(plat))
        pts.append((math.degrees(plat), math.degrees(plon)))
    return pts


# ─── DENM → record ────────────────────────────────────────────────────────────

def build_record(denm: dict, names: dict) -> dict:
    """Extract everything needed for the KML from one decoded DENM."""
    payload = denm['denm']
    mgmt = payload['management']
    ep = mgmt['eventPosition']
    ref_lat_raw, ref_lon_raw = ep['latitude'], ep['longitude']
    ref = (ref_lat_raw / COORD_SCALE, ref_lon_raw / COORD_SCALE)

    zones = []   # {'name', 'kind': 'detection'|'relevance', 'coords'}
    location = payload.get('location')
    if location is not None:
        for i, path in enumerate(location.get('detectionZonesToEventPosition') or [], 1):
            zones.append({
                'name': f'trace{i}', 'kind': 'detection',
                'coords': cumulative_points(ref_lat_raw, ref_lon_raw, path, 'pathPosition'),
            })

    situation = payload.get('situation')
    event_zone = situation.get('eventZone') if situation is not None else None
    if event_zone:
        zones.append({
            'name': 'eventZone', 'kind': 'relevance',
            'coords': cumulative_points(ref_lat_raw, ref_lon_raw, event_zone, 'eventPosition'),
        })

    awareness = None
    aw = mgmt.get('awarenessDistance')
    if aw is not None:
        radius = AWARENESS_RADIUS_M.get(aw)
        if radius:
            awareness = {'enum': aw, 'radius': radius}

    if awareness and event_zone:
        event_type = 'linear+circular'
    elif awareness:
        event_type = 'circular'
    elif event_zone:
        event_type = 'linear'
    else:
        event_type = 'point'

    return {
        'ref': ref,
        'zones': zones,
        'awareness': awareness,
        'event_type': event_type,
        'cause': denm_event_type(denm, names),
        'linked_cause': (describe_event_type(situation['linkedCause'], names)
                         if situation is not None and situation.get('linkedCause')
                         else None),
        'terminated': 'termination' in mgmt,
        'station_type': mgmt.get('stationType'),
    }


# ─── KML generation ───────────────────────────────────────────────────────────

def build_kml(records: dict, mode: str = 'lines') -> ET.Element:
    """Build the complete KML element tree from extracted DENM records.

    mode='lines'  – zones as LineStrings starting at the eventPosition
    mode='points' – each delta position as an individual labeled Point
                    (label: trace1-Item0, eventZone-Item3, ...)
    """
    kml = ET.Element('kml', xmlns='http://www.opengis.net/kml/2.2')
    doc = ET.SubElement(kml, 'Document')
    ET.SubElement(doc, 'name').text = 'DENM Messages'
    ET.SubElement(doc, 'description').text = (
        f'{len(records)} unique DENM message(s) extracted from PCAP capture(s) '
        f'[mode: {mode}]')

    add_kml_styles(doc)

    for (station, seq), rec in sorted(records.items()):
        action_id = f'{station}/{seq}'
        ref_lat, ref_lon = rec['ref']

        folder = ET.SubElement(doc, 'Folder')
        ET.SubElement(folder, 'name').text = f'DENM {action_id}'
        ET.SubElement(folder, 'visibility').text = '1'

        # ── eventPosition marker (same in both modes), labeled with actionId ──
        pm = ET.SubElement(folder, 'Placemark')
        ET.SubElement(pm, 'name').text = action_id
        n_traces = sum(1 for z in rec['zones'] if z['kind'] == 'detection')
        desc = [f'Event type (cause / sub cause): {rec["cause"]}']
        if rec['linked_cause']:
            desc.append(f'Linked cause: {rec["linked_cause"]}')
        desc += [f'Event geometry: {rec["event_type"]} event',
                 f'Traces: {n_traces}']
        ez = next((z for z in rec['zones'] if z['kind'] == 'relevance'), None)
        if ez:
            desc.append(f'eventZone points: {len(ez["coords"])}')
        if rec['awareness']:
            desc.append(f'awarenessDistance: {rec["awareness"]["enum"]}')
        if rec['terminated']:
            desc.append('termination DENM')
        ET.SubElement(pm, 'description').text = '\n'.join(desc)
        ET.SubElement(pm, 'styleUrl').text = '#refPosition'
        pt = ET.SubElement(pm, 'Point')
        ET.SubElement(pt, 'coordinates').text = f'{ref_lon:.7f},{ref_lat:.7f},0'

        # ── Zones: traces (red), eventZone (green) ────────────────────────────
        for zone in rec['zones']:
            name, kind, coords = zone['name'], zone['kind'], zone['coords']

            if mode == 'points':
                zone_folder = ET.SubElement(folder, 'Folder')
                ET.SubElement(zone_folder, 'name').text = name
                ET.SubElement(zone_folder, 'visibility').text = '1'
                for idx, (lat, lon) in enumerate(coords):
                    pm = ET.SubElement(zone_folder, 'Placemark')
                    ET.SubElement(pm, 'name').text = f'{name}-Item{idx}'
                    ET.SubElement(pm, 'styleUrl').text = f'#{kind}Point'
                    pt = ET.SubElement(pm, 'Point')
                    ET.SubElement(pt, 'altitudeMode').text = 'clampToGround'
                    ET.SubElement(pt, 'coordinates').text = f'{lon:.7f},{lat:.7f},0'
            else:  # lines
                pm = ET.SubElement(folder, 'Placemark')
                ET.SubElement(pm, 'name').text = name
                ET.SubElement(pm, 'styleUrl').text = f'#{kind}Zone'
                ls = ET.SubElement(pm, 'LineString')
                ET.SubElement(ls, 'altitudeMode').text = 'clampToGround'
                ET.SubElement(ls, 'coordinates').text = coords_to_kml_str(
                    [rec['ref']] + coords)

        # ── Circular awareness area (gold) ────────────────────────────────────
        if rec['awareness']:
            radius = rec['awareness']['radius']
            ring = circle_points(ref_lat, ref_lon, radius)
            holder = folder
            if mode == 'points':
                holder = ET.SubElement(folder, 'Folder')
                ET.SubElement(holder, 'name').text = 'awarenessArea'
                ET.SubElement(holder, 'visibility').text = '1'
            pm = ET.SubElement(holder, 'Placemark')
            ET.SubElement(pm, 'name').text = (
                f'awarenessArea ({rec["awareness"]["enum"]}, drawn r={radius} m)')
            ET.SubElement(pm, 'styleUrl').text = '#awarenessZone'
            ls = ET.SubElement(pm, 'LineString')
            ET.SubElement(ls, 'altitudeMode').text = 'clampToGround'
            ET.SubElement(ls, 'coordinates').text = coords_to_kml_str(ring)

    return kml


# ─── Main processing pipeline ─────────────────────────────────────────────────

def process(pcap_files: list, asn_dir: Path, output_path: str,
            write_kmz: bool, mode: str = 'lines') -> None:
    print(f'Compiling ASN.1 definitions from: {asn_dir}')
    for name in ASN_FILES:
        print(f'  - {name}')
    db = compile_asn(asn_dir)
    print('ASN.1 compilation successful.')
    names = load_cause_names(asn_dir)

    records: dict = {}   # (originatingStationId, sequenceNumber) -> record

    for pcap_file in expand_pcaps(pcap_files):
        print(f'\nProcessing: {pcap_file}')
        n_pkt = n_denm = n_new = 0

        for pkt in iter_its_packets(pcap_file):
            n_pkt += 1
            denm, _ = extract_denm(pkt, db)
            if denm is None:
                continue
            n_denm += 1

            aid = denm['denm']['management']['actionId']
            key = (aid['originatingStationId'], aid['sequenceNumber'])
            if key in records:
                continue  # deduplicate: keep only first occurrence
            n_new += 1
            records[key] = build_record(denm, names)

        print(f'  ITS-G5 packets: {n_pkt}  |  DENM decoded: {n_denm}  '
              f'|  New unique actionIds: {n_new}')

    print(f'\nTotal unique DENM actionIds across all input files: {len(records)}')
    type_counts: dict = {}
    n_traces = n_ez = n_aw = 0
    for rec in records.values():
        type_counts[rec['event_type']] = type_counts.get(rec['event_type'], 0) + 1
        n_traces += sum(1 for z in rec['zones'] if z['kind'] == 'detection')
        n_ez += any(z['kind'] == 'relevance' for z in rec['zones'])
        n_aw += rec['awareness'] is not None
    for etype, cnt in sorted(type_counts.items()):
        print(f'  {etype.capitalize()} events: {cnt}')
    print(f'  Traces: {n_traces}  |  eventZones: {n_ez}  |  Awareness circles: {n_aw}')
    cause_counts: dict = {}
    for rec in records.values():
        cause_counts[rec['cause']] = cause_counts.get(rec['cause'], 0) + 1
    print('  Event types (unique DENMs):')
    for cause, cnt in sorted(cause_counts.items(), key=lambda x: -x[1]):
        print(f'    {cnt:>3}  {cause}')

    kml_str = pretty_print_kml(build_kml(records, mode=mode))

    if write_kmz:
        out = output_path if output_path.endswith('.kmz') else output_path + '.kmz'
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('doc.kml', kml_str.encode('utf-8'))
    else:
        out = output_path if output_path.endswith('.kml') else output_path + '.kml'
        with open(out, 'w', encoding='utf-8') as f:
            f.write(kml_str)

    print(f'\nOutput written to: {out}')


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Convert DENM PCAP captures to KML/KMZ for map visualization.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s); wildcards such as *.pcap are expanded')
    parser.add_argument('-o', '--output', default='denm_output', metavar='FILE',
                        help='Output file name without extension (default: denm_output)')
    parser.add_argument('--kmz', action='store_true',
                        help='Write KMZ (compressed KML) instead of plain KML')
    parser.add_argument('--mode', choices=['lines', 'points'], default='lines',
                        help='Output mode: lines = zones as LineStrings (default); '
                             'points = each delta position as a labeled Point '
                             '(trace1-Item0, eventZone-Item3, ...)')
    parser.add_argument('--asn-dir', type=Path, default=DEFAULT_ASN_DIR,
                        metavar='DIR',
                        help=f'Directory with ASN.1 files (default: {DEFAULT_ASN_DIR})')
    args = parser.parse_args()

    try:
        process(args.pcap, args.asn_dir, args.output, args.kmz, args.mode)
    except (FileNotFoundError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
