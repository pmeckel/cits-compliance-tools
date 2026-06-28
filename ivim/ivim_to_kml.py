#!/usr/bin/env python3
"""
IVIM PCAP → KML/KMZ Converter

Parses C-ITS PCAP captures, extracts IVIM messages (ISO TS 19321 / ETSI TS 103 301)
and their geographic zone data, and generates KML/KMZ files for visualization
in Google Earth, Google Maps, OpenStreetMap, etc.

Each iviIdentificationNumber appears exactly once in the output KML, even if
the PCAP contains multiple transmissions of the same IVIM message.

Zone types from the GeneralIviContainer (GIV) are visualized with distinct colors:
  - Detection zones  : red
  - Relevance zones  : green
  - Awareness zones  : gold/yellow
  - Unassigned zones : gray

Two output modes are available (--mode):
  lines   (default) – zones rendered as LineStrings / Polygons
  points  – each delta position rendered as an individual labeled Point
            (label format: Zone{id}-Item{index}, e.g. Zone1-Item0)

Usage:
    python ivim_to_kml.py SingleIVIM.pcap
    python ivim_to_kml.py AllCaptures.pcap -o all_ivis.kml
    python ivim_to_kml.py AllCaptures.pcap --mode points -o all_ivis_pts.kml
    python ivim_to_kml.py *.pcap --kmz -o output
    python ivim_to_kml.py capture.pcap --asn-dir /path/to/asn
"""

import argparse
import struct
import sys
import zipfile
from pathlib import Path
from xml.dom import minidom
import xml.etree.ElementTree as ET

import asn1tools

# ─── Configuration ─────────────────────────────────────────────────────────────

# BTP destination port for IVIM = 2006 (0x07D6)
BTP_IVIM_PORT = b'\x07\xd6'

# ETSI coordinate scale: raw integer → degrees (10^-7 degrees per unit)
COORD_SCALE = 1e7

# KML colors in AABBGGRR format (alpha, blue, green, red)
KML_STYLE = {
    'detection': {'line_color': 'ff1400ff', 'line_width': 3},  # red
    'relevance': {'line_color': 'ff00aa00', 'line_width': 3},  # green
    'awareness': {'line_color': 'ff00d7ff', 'line_width': 2},  # gold
    'unknown':   {'line_color': 'ff808080', 'line_width': 1},  # gray
}

# Default ASN.1 directory (relative to this script)
DEFAULT_ASN_DIR = Path(__file__).parent / 'ASN'

# ASN.1 files to compile (order matters for dependency resolution)
ASN_FILES = [
    'ETSI-ITS-CDD.asn',
    'ISO 17573-3 EfcDataDictionary V1.6.asn',
    'ISO19321IVIv3.1_patched.asn',
    'ISO_14823-1 ed1_AnnexE.asn',
    'IVIM-PDU-Descriptions.asn',
]


# ─── ASN.1 setup ──────────────────────────────────────────────────────────────

def ensure_patched_asn(asn_dir: Path) -> None:
    """Create the patched ASN.1 file if it doesn't exist yet.

    asn1tools does not support RELATIVE-OID (used in InfrastructureSupportInformation
    for the optional baseOid field). We replace it with OBJECT IDENTIFIER which is
    structurally compatible and only affects the rarely-used ISC container (V3.1
    extension). This has no impact on decoding standard IVIM messages.
    """
    patched = asn_dir / 'ISO19321IVIv3.1_patched.asn'
    if patched.exists():
        return
    original = asn_dir / 'ISO19321IVIv3.1.asn'
    if not original.exists():
        raise FileNotFoundError(f"Required ASN.1 file not found: {original}")
    content = original.read_text(encoding='utf-8')
    patched.write_text(content.replace('RELATIVE-OID', 'OBJECT IDENTIFIER'),
                       encoding='utf-8')


def compile_asn(asn_dir: Path):
    ensure_patched_asn(asn_dir)
    files = []
    for name in ASN_FILES:
        p = asn_dir / name
        if not p.exists():
            raise FileNotFoundError(f"ASN.1 file not found: {p}")
        files.append(str(p))
    return asn1tools.compile_files(files, codec='uper')


# ─── PCAP parsing ─────────────────────────────────────────────────────────────

def iter_its_packets(pcap_path: str):
    """Yield raw packet bytes for every ITS-G5 (Ethertype 0x8947) frame."""
    with open(pcap_path, 'rb') as f:
        raw = f.read()

    magic = struct.unpack('<I', raw[:4])[0]
    if magic not in (0xa1b2c3d4, 0xa1b23c4d):
        raise ValueError(f"Not a supported PCAP file (magic={hex(magic)}). "
                         "PCAPNG format is not supported.")

    offset = 24  # skip 24-byte global header
    while offset + 16 <= len(raw):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            '<IIII', raw[offset:offset + 16])
        pkt = raw[offset + 16:offset + 16 + incl_len]
        offset += 16 + incl_len

        if len(pkt) < 14:
            continue
        ethertype = struct.unpack('>H', pkt[12:14])[0]
        if ethertype == 0x8947:
            yield pkt


# ─── IVIM extraction ──────────────────────────────────────────────────────────

def extract_ivim(pkt: bytes, db) -> dict | None:
    """Find and decode the IVIM UPER payload within a GeoNetworking packet.

    Strategy: scan for BTP destination port 0x07D6 (2006 = IVIM), then attempt
    to decode the IVIM UPER payload starting 4 bytes later (after the BTP-B
    header). The decoder validates the result, so false positives are dropped.
    """
    pos = 0
    while True:
        idx = pkt.find(BTP_IVIM_PORT, pos)
        if idx == -1:
            return None
        pos = idx + 1
        ivim_start = idx + 4
        if ivim_start + 6 >= len(pkt):
            continue
        # Quick sanity check: byte[1] must be messageId=6 (IVIM)
        if pkt[ivim_start + 1] != 6:
            continue
        try:
            return db.decode('IVIM', pkt[ivim_start:])
        except Exception:
            continue
    return None


# ─── Coordinate helpers ───────────────────────────────────────────────────────

def compute_delta_coords(ref_lat_raw: int, ref_lon_raw: int,
                         deltas: list) -> list[tuple[float, float]]:
    """Convert cumulative DeltaPositions to (lat°, lon°) tuples.

    ETSI TS 103 301 / ISO TS 19321: each delta is relative to the previous
    accumulated position, starting from the referencePosition.
    All values are in units of 10^-7 degrees.
    """
    lat, lon = ref_lat_raw, ref_lon_raw
    points = []
    for d in deltas:
        lat += d['deltaLatitude']
        lon += d['deltaLongitude']
        points.append((lat / COORD_SCALE, lon / COORD_SCALE))
    return points


def compute_delta_ref_coords(ref_lat_raw: int, ref_lon_raw: int,
                             deltas: list) -> list[tuple[float, float]]:
    """Same as compute_delta_coords but for DeltaReferencePositions (with altitude)."""
    lat, lon = ref_lat_raw, ref_lon_raw
    points = []
    for d in deltas:
        lat += d['deltaLatitude']
        lon += d['deltaLongitude']
        points.append((lat / COORD_SCALE, lon / COORD_SCALE))
    return points


def compute_absolute_coords(positions: list) -> list[tuple[float, float]]:
    return [(p['latitude'] / COORD_SCALE, p['longitude'] / COORD_SCALE)
            for p in positions]


def extract_polygonal_line_coords(ref_lat_raw: int, ref_lon_raw: int,
                                  polygonal_line) -> list[tuple[float, float]] | None:
    """Decode a PolygonalLine CHOICE into (lat°, lon°) tuples."""
    line_type, line_data = polygonal_line
    if line_type == 'deltaPositions':
        return compute_delta_coords(ref_lat_raw, ref_lon_raw, line_data)
    if line_type == 'deltaPositionsWithAltitude':
        return compute_delta_ref_coords(ref_lat_raw, ref_lon_raw, line_data)
    if line_type in ('absolutePositions', 'absolutePositionsWithAltitude'):
        return compute_absolute_coords(line_data)
    return None


def extract_zone_geometry(ref_lat_raw: int, ref_lon_raw: int,
                          zone) -> tuple[list | None, bool]:
    """Extract coordinates and is_area flag from a Zone CHOICE.

    Returns (points, is_area). is_area=True → use Polygon, False → use LineString.
    """
    zone_type, zone_data = zone
    if zone_type in ('segment-carriagewayOrLane', 'segment-setOfLanes'):
        line = zone_data.get('line')
        if line is None:
            return None, False
        return extract_polygonal_line_coords(ref_lat_raw, ref_lon_raw, line), False
    if zone_type == 'area':
        return extract_polygonal_line_coords(ref_lat_raw, ref_lon_raw, zone_data), True
    # computedSegment: references another zone by zoneId – skip
    return None, False


# ─── GIV zone-type mapping ────────────────────────────────────────────────────

def build_zone_type_map(giv_parts: list) -> dict[int, str]:
    """Build {zoneId: 'detection'|'relevance'|'awareness'} from GIV container."""
    zone_types: dict[int, str] = {}
    for part in giv_parts:
        for zid in (part.get('detectionZoneIds') or []):
            zone_types[zid] = 'detection'
        for zid in (part.get('relevanceZoneIds') or []):
            if zid not in zone_types:
                zone_types[zid] = 'relevance'
        for zid in (part.get('driverAwarenessZoneIds') or []):
            if zid not in zone_types:
                zone_types[zid] = 'awareness'
    return zone_types


# ─── KML generation ───────────────────────────────────────────────────────────

def coords_to_kml_str(points: list[tuple[float, float]]) -> str:
    """Format (lat, lon) list as KML coordinate string (lon,lat,0)."""
    return ' '.join(f'{lon:.7f},{lat:.7f},0' for lat, lon in points)


def add_kml_styles(doc: ET.Element) -> None:
    """Append Style elements for all zone types and the reference position."""
    for style_id, cfg in KML_STYLE.items():
        # Line / polygon style (used in 'lines' mode)
        s = ET.SubElement(doc, 'Style', id=f'{style_id}Zone')
        ls = ET.SubElement(s, 'LineStyle')
        ET.SubElement(ls, 'color').text = cfg['line_color']
        ET.SubElement(ls, 'width').text = str(cfg['line_width'])
        # Semi-transparent fill (for polygon areas)
        ps = ET.SubElement(s, 'PolyStyle')
        fill_color = cfg['line_color'][:2] + '30' + cfg['line_color'][4:]  # ~19% opacity
        ET.SubElement(ps, 'color').text = fill_color
        ET.SubElement(ps, 'fill').text = '0'  # off by default; on for area zones

        # Point / icon style (used in 'points' mode)
        s = ET.SubElement(doc, 'Style', id=f'{style_id}Point')
        ist = ET.SubElement(s, 'IconStyle')
        ET.SubElement(ist, 'color').text = cfg['line_color']
        ET.SubElement(ist, 'scale').text = '0.8'
        icon = ET.SubElement(ist, 'Icon')
        ET.SubElement(icon, 'href').text = (
            'http://maps.google.com/mapfiles/kml/shapes/shaded_dot.png')
        lst = ET.SubElement(s, 'LabelStyle')
        ET.SubElement(lst, 'scale').text = '0.7'

    # Reference position marker
    s = ET.SubElement(doc, 'Style', id='refPosition')
    ist = ET.SubElement(s, 'IconStyle')
    ET.SubElement(ist, 'color').text = 'ff00ffff'  # yellow
    ET.SubElement(ist, 'scale').text = '1.3'
    icon = ET.SubElement(ist, 'Icon')
    ET.SubElement(icon, 'href').text = (
        'http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png')
    lst = ET.SubElement(s, 'LabelStyle')
    ET.SubElement(lst, 'scale').text = '1.0'


def build_kml(ivim_records: dict, mode: str = 'lines') -> ET.Element:
    """Build the complete KML element tree from extracted IVIM records.

    mode='lines'  – zones as LineStrings / Polygons (default)
    mode='points' – each delta position as an individual labeled Point
                    (label: Zone{id}-Item{index}, e.g. Zone1-Item0)
    """
    kml = ET.Element('kml', xmlns='http://www.opengis.net/kml/2.2')
    doc = ET.SubElement(kml, 'Document')
    ET.SubElement(doc, 'name').text = 'IVIM Messages'
    ET.SubElement(doc, 'description').text = (
        f'{len(ivim_records)} unique IVIM message(s) extracted from PCAP capture(s) '
        f'[mode: {mode}]')

    add_kml_styles(doc)

    zone_type_order = {'detection': 0, 'relevance': 1, 'awareness': 2, 'unknown': 3}

    for ivi_id, info in sorted(ivim_records.items()):
        folder = ET.SubElement(doc, 'Folder')
        ET.SubElement(folder, 'name').text = f'IVIM {ivi_id}'
        ET.SubElement(folder, 'visibility').text = '1'

        ref_lat = info['ref_lat']
        ref_lon = info['ref_lon']

        # ── Reference position marker (same in both modes) ─────────────────
        pm = ET.SubElement(folder, 'Placemark')
        ET.SubElement(pm, 'name').text = str(ivi_id)
        ET.SubElement(pm, 'styleUrl').text = '#refPosition'
        pt = ET.SubElement(pm, 'Point')
        ET.SubElement(pt, 'coordinates').text = f'{ref_lon:.7f},{ref_lat:.7f},0'

        # ── Zone placemarks ────────────────────────────────────────────────
        sorted_zones = sorted(
            info['zones'].items(),
            key=lambda kv: (zone_type_order.get(kv[1]['type'], 9), kv[0]))

        for zone_id, zone_info in sorted_zones:
            ztype  = zone_info['type']
            points = zone_info['coords']
            is_area = zone_info['is_area']

            if mode == 'points':
                # Sub-folder per zone so all its points can be toggled at once
                zone_folder = ET.SubElement(folder, 'Folder')
                ET.SubElement(zone_folder, 'name').text = (
                    f'{ztype.capitalize()} Zone {zone_id}')
                ET.SubElement(zone_folder, 'visibility').text = '1'
                # One Placemark per coordinate, labeled Zone{id}-Item{index}
                for idx, (lat, lon) in enumerate(points):
                    pm = ET.SubElement(zone_folder, 'Placemark')
                    ET.SubElement(pm, 'name').text = f'Zone{zone_id}-Item{idx}'
                    ET.SubElement(pm, 'styleUrl').text = f'#{ztype}Point'
                    pt = ET.SubElement(pm, 'Point')
                    ET.SubElement(pt, 'altitudeMode').text = 'clampToGround'
                    ET.SubElement(pt, 'coordinates').text = (
                        f'{lon:.7f},{lat:.7f},0')

            else:  # mode == 'lines' (default)
                pm = ET.SubElement(folder, 'Placemark')
                ET.SubElement(pm, 'name').text = (
                    f'{ztype.capitalize()} Zone {zone_id}')
                ET.SubElement(pm, 'styleUrl').text = f'#{ztype}Zone'

                coords_str = coords_to_kml_str(points)

                if is_area:
                    # Close the ring if not already closed
                    if points and points[0] != points[-1]:
                        coords_str += f' {coords_str.split()[0]}'
                    pg = ET.SubElement(pm, 'Polygon')
                    ET.SubElement(pg, 'extrude').text = '0'
                    ET.SubElement(pg, 'altitudeMode').text = 'clampToGround'
                    outer = ET.SubElement(pg, 'outerBoundaryIs')
                    lr = ET.SubElement(outer, 'LinearRing')
                    ET.SubElement(lr, 'coordinates').text = coords_str
                else:
                    ls = ET.SubElement(pm, 'LineString')
                    ET.SubElement(ls, 'altitudeMode').text = 'clampToGround'
                    ET.SubElement(ls, 'coordinates').text = coords_str

    return kml


def pretty_print_kml(kml_elem: ET.Element) -> str:
    raw = ET.tostring(kml_elem, encoding='unicode')
    dom = minidom.parseString(raw)
    return dom.toprettyxml(indent='  ')


# ─── Main processing pipeline ─────────────────────────────────────────────────

def process(pcap_files: list[str], asn_dir: Path, output_path: str,
            write_kmz: bool, mode: str = 'lines') -> None:
    print(f'Compiling ASN.1 definitions from: {asn_dir}')
    db = compile_asn(asn_dir)
    print('ASN.1 compilation successful.')

    # {ivi_id: {ref_lat, ref_lon, zones: {zone_id: {type, coords, is_area}}}}
    ivim_records: dict[int, dict] = {}

    for pcap_file in pcap_files:
        print(f'\nProcessing: {pcap_file}')
        n_pkt = n_ivim = n_new = 0

        for pkt in iter_its_packets(pcap_file):
            n_pkt += 1
            ivim = extract_ivim(pkt, db)
            if ivim is None:
                continue
            n_ivim += 1

            mandatory = ivim['ivi']['mandatory']
            ivi_id = mandatory['iviIdentificationNumber']

            if ivi_id in ivim_records:
                continue  # deduplicate: keep only first occurrence
            n_new += 1

            containers = ivim['ivi'].get('optional') or []
            glc = None
            giv_parts = []
            for ctype, cdata in containers:
                if ctype == 'glc':
                    glc = cdata
                elif ctype == 'giv':
                    giv_parts = list(cdata)

            if glc is None:
                print(f'  Warning: IVIM {ivi_id} has no GLC container – skipped.')
                continue

            ref = glc['referencePosition']
            ref_lat_raw = ref['latitude']
            ref_lon_raw = ref['longitude']

            zone_type_map = build_zone_type_map(giv_parts)

            zones: dict[int, dict] = {}
            for part in glc.get('parts', []):
                zone_id = part['zoneId']
                zone = part.get('zone')
                if zone is None:
                    continue
                coords, is_area = extract_zone_geometry(ref_lat_raw, ref_lon_raw, zone)
                if coords:
                    zones[zone_id] = {
                        'type': zone_type_map.get(zone_id, 'unknown'),
                        'coords': coords,
                        'is_area': is_area,
                    }

            ivim_records[ivi_id] = {
                'ref_lat': ref_lat_raw / COORD_SCALE,
                'ref_lon': ref_lon_raw / COORD_SCALE,
                'zones': zones,
                'station_id': ivim['header']['stationId'],
            }

        zone_counts = {'detection': 0, 'relevance': 0, 'awareness': 0, 'unknown': 0}
        for rec in ivim_records.values():
            for z in rec['zones'].values():
                zone_counts[z['type']] += 1

        print(f'  ITS-G5 packets: {n_pkt}  |  IVIM decoded: {n_ivim}  '
              f'|  New unique IVI IDs: {n_new}')

    print(f'\nTotal unique IVIM IDs across all input files: {len(ivim_records)}')
    for ztype, cnt in zone_counts.items():
        if cnt:
            print(f'  {ztype.capitalize()} zones: {cnt}')

    kml_elem = build_kml(ivim_records, mode=mode)
    kml_str = pretty_print_kml(kml_elem)

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
        description='Convert IVIM PCAP captures to KML/KMZ for map visualization.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s)')
    parser.add_argument('-o', '--output', default='ivim_output',
                        metavar='FILE',
                        help='Output file name without extension (default: ivim_output)')
    parser.add_argument('--kmz', action='store_true',
                        help='Write KMZ (compressed KML) instead of plain KML')
    parser.add_argument('--mode', choices=['lines', 'points'], default='lines',
                        help='Output mode: lines = zones as LineStrings/Polygons '
                             '(default); points = each delta position as a labeled '
                             'Point (Zone{id}-Item{index})')
    parser.add_argument('--asn-dir', type=Path, default=DEFAULT_ASN_DIR,
                        metavar='DIR',
                        help=f'Directory with ASN.1 files (default: {DEFAULT_ASN_DIR})')
    args = parser.parse_args()

    try:
        process(args.pcap, args.asn_dir, args.output, args.kmz, args.mode)
    except FileNotFoundError as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
