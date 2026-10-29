#!/usr/bin/env python3
"""
IVS-TS (In-Vehicle Signage – Traffic Signs) C-ROADS Compliance Checker
C-Roads Release 3.2.0

Checks IVIM messages extracted from PCAP files against the C-ROADS IVS-TS
use case profile requirements defined in:
  - C-Roads_WG2_TF3_C-ITS MessageProfiles_3.2.0
      chapter 4.2.2.2  – IVIM general elements
      chapter 4.2.2.3  – IVS-TS-specific requirements
      chapter 4.2.2.8  – IVIM profile for cancellation (iviStatus=2)
  - C_Roads_WG2_TF2_Service_and_Use_Case_Definitions_02_IVS_3.2.0
      chapter 2.2.1.1  – IVS-TS use case requirements

Note: IVS-TS is one of several C-ROADS use cases carried by the IVIM message
(others include IVS-FT and, in future, additional IVIM-based use cases). This
script checks IVS-TS specifically; see sibling folders under ivim/ for other
use-case checkers as they are added.

For each unique IVIM (identified by iviIdentificationNumber) the script reports
for every requirement whether it is:
  PASS  – requirement satisfied
  FAIL  – requirement violated
  WARN  – recommendation not followed (should/should not)
  N/A   – not applicable to this specific IVIM
  SKIP  – out of scope for automated ASN.1-level checking

Reuses PCAP parsing and ASN.1 compilation from ../ivim_to_kml.py.

Usage:
    python ivs_ts_croads_check.py SingleIVIM.pcap
    python ivs_ts_croads_check.py AllCaptures_IVIM.pcap -o report.txt
    python ivs_ts_croads_check.py *.pcap -o combined_report.txt
"""

import argparse
import math
import struct
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asn1tools

# ─── Constants ─────────────────────────────────────────────────────────────────

BTP_IVIM_PORT   = b'\x07\xd6'       # BTP destination port 2006 = IVIM
COORD_SCALE     = 1e7                # ETSI raw integer → degrees
ITS_EPOCH_UNIX  = 1072915200         # 2004-01-01 00:00:00 UTC in Unix seconds
MS_PER_HOUR     = 3_600_000          # 1 hour in milliseconds

# Valid laneType values per MP_Req_0111 (see ISO 19321 / ETSI CDD)
VALID_LANE_TYPES = {0, 3, 4, 8, 9, 10, 11, 13, 18}
LANE_TYPE_NAMES  = {
    0: 'traffic', 1: 'through', 2: 'reversible', 3: 'acceleration',
    4: 'deceleration', 5: 'leftHandTurning', 6: 'rightHandTurning',
    7: 'dedicatedVehicle', 8: 'bus', 9: 'taxi', 10: 'hov', 11: 'hot',
    12: 'pedestrian', 13: 'cycleLane', 14: 'median', 15: 'striping',
    16: 'trackedVehicle', 17: 'parking', 18: 'emergency', 19: 'verge'
}

# iviType mapping from ISO 14823 serviceCategoryCode (MP_Req_0131)
# Key: (serviceCategoryCode_choice, serviceCategoryCode_value)
# Value: expected iviType integer
IVI_TYPE_MAPPING = {
    ('trafficSignPictogram',            'dangerWarning'):  0,  # immediateDangerWarningMessages
    ('trafficSignPictogram',            'regulatory'):     1,  # regulatoryMessages
    ('trafficSignPictogram',            'informative'):    2,  # trafficRelatedInformationMessages
    ('publicFacilitiesPictogram',       'publicFacilities'): 4,  # notTrafficRelatedInformationMessages
    ('ambientOrRoadConditionPictogram', 'ambientCondition'): 0,
    ('ambientOrRoadConditionPictogram', 'roadCondition'):    0,
    # supplementaryPanel → type depends on main sign, checked as N/A
}

DEFAULT_ASN_DIR = Path(__file__).parent.parent / 'ASN'
ASN_FILES = [
    'ETSI-ITS-CDD.asn',
    'ISO 17573-3 EfcDataDictionary V1.6.asn',
    'ISO19321IVIv3.1_patched.asn',
    'ISO_14823-1 ed1_AnnexE.asn',
    'IVIM-PDU-Descriptions.asn',
]

# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    req_id:      str          # e.g. 'MP_Req_0078 (1)'
    req_type:    str          # 'REQ' | 'REC' | 'OPT' | 'INF'
    de_path:     str          # DE/DF path from document
    result:      str          # 'PASS' | 'FAIL' | 'WARN' | 'N/A' | 'SKIP'
    details:     str          # human-readable explanation

@dataclass
class IvimReport:
    ivi_id:    int
    station_id: int
    status:    int
    checks:    list = field(default_factory=list)

    def summary(self):
        counts = {'PASS': 0, 'FAIL': 0, 'WARN': 0, 'N/A': 0, 'SKIP': 0}
        for c in self.checks:
            counts[c.result] = counts.get(c.result, 0) + 1
        return counts


# ─── ASN.1 / PCAP helpers (reused from ../ivim_to_kml.py) ────────────────────

def ensure_patched_asn(asn_dir: Path) -> None:
    patched = asn_dir / 'ISO19321IVIv3.1_patched.asn'
    if patched.exists():
        return
    original = asn_dir / 'ISO19321IVIv3.1.asn'
    if not original.exists():
        raise FileNotFoundError(f"Required ASN.1 file not found: {original}")
    patched.write_text(
        original.read_text(encoding='utf-8').replace('RELATIVE-OID', 'OBJECT IDENTIFIER'),
        encoding='utf-8')


def compile_asn(asn_dir: Path):
    ensure_patched_asn(asn_dir)
    files = [str(asn_dir / n) for n in ASN_FILES]
    for f in files:
        if not Path(f).exists():
            raise FileNotFoundError(f"ASN.1 file not found: {f}")
    return asn1tools.compile_files(files, codec='uper')


# PCAP link-layer types this parser understands.
LINKTYPE_ETHERNET            = 1    # pre-stripped Ethernet framing
LINKTYPE_IEEE802_11          = 105  # raw 802.11, no radio metadata
LINKTYPE_IEEE802_11_RADIOTAP = 127  # 802.11 + Radiotap header (common for
                                    # 802.11p / ITS-G5 monitor-mode captures)


def _is_its_g5_80211(pkt: bytes, has_radiotap: bool) -> bool:
    """Check whether an IEEE 802.11 frame (optionally preceded by a Radiotap
    header) carries an LLC/SNAP-encapsulated ITS-G5 payload (Ethertype 0x8947).
    """
    if has_radiotap:
        if len(pkt) < 4:
            return False
        rt_len = struct.unpack('<H', pkt[2:4])[0]  # radiotap header length
        body = pkt[rt_len:]
    else:
        body = pkt
    if len(body) < 24:
        return False
    frame_control = struct.unpack('<H', body[0:2])[0]
    frame_type    = (frame_control >> 2) & 0x3
    frame_subtype = (frame_control >> 4) & 0xF
    if frame_type != 2:  # not a Data frame
        return False
    hdr_len = 26 if (frame_subtype & 0x08) else 24  # QoS Data has 2 extra bytes
    llc = body[hdr_len:hdr_len + 8]
    if len(llc) < 8 or llc[:3] != b'\xaa\xaa\x03':  # not LLC/SNAP encapsulated
        return False
    return struct.unpack('>H', llc[6:8])[0] == 0x8947


def iter_its_packets(pcap_path: str):
    """Yield raw packet bytes for every ITS-G5 (Ethertype 0x8947) frame.

    Supports PCAP captures with Ethernet framing (linktype 1, as produced by
    tools that strip the radio layer) as well as raw IEEE 802.11 captures,
    with or without a Radiotap header (linktype 105 / 127, as produced by
    802.11p / ITS-G5 monitor-mode captures).
    """
    with open(pcap_path, 'rb') as f:
        raw = f.read()
    magic = struct.unpack('<I', raw[:4])[0]
    if magic not in (0xa1b2c3d4, 0xa1b23c4d):
        raise ValueError(f"Not a supported PCAP file (magic={hex(magic)}).")

    linktype = struct.unpack('<I', raw[20:24])[0]
    if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11,
                        LINKTYPE_IEEE802_11_RADIOTAP):
        raise ValueError(
            f"Unsupported PCAP link-layer type {linktype}. Supported: "
            f"Ethernet ({LINKTYPE_ETHERNET}), IEEE 802.11 "
            f"({LINKTYPE_IEEE802_11}), IEEE 802.11 + Radiotap "
            f"({LINKTYPE_IEEE802_11_RADIOTAP}).")

    offset = 24
    while offset + 16 <= len(raw):
        _ts, _us, incl_len, _orig = struct.unpack('<IIII', raw[offset:offset+16])
        pkt = raw[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        if linktype == LINKTYPE_ETHERNET:
            if len(pkt) >= 14 and struct.unpack('>H', pkt[12:14])[0] == 0x8947:
                yield pkt
        else:
            if _is_its_g5_80211(pkt, has_radiotap=(linktype == LINKTYPE_IEEE802_11_RADIOTAP)):
                yield pkt


def extract_ivim(pkt: bytes, db) -> Optional[dict]:
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
    return None


# ─── Geometry helpers ─────────────────────────────────────────────────────────

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Geodesic distance in metres between two WGS-84 points."""
    R = 6_371_000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(max(0.0, a)))


def polyline_length(pts: list) -> float:
    """Total length of a polyline [(lat,lon),...] in metres."""
    return sum(haversine(*pts[i], *pts[i+1]) for i in range(len(pts)-1))


def min_dist_to_zone(pt: tuple, zone_pts: list) -> float:
    """Minimum haversine distance from pt to any vertex in zone_pts."""
    if not zone_pts:
        return float('inf')
    return min(haversine(pt[0], pt[1], p[0], p[1]) for p in zone_pts)


def coords_from_polygon_line(ref_lat_raw: int, ref_lon_raw: int,
                              polygonal_line) -> Optional[list]:
    line_type, line_data = polygonal_line
    lat, lon = ref_lat_raw, ref_lon_raw
    pts = []
    if line_type in ('deltaPositions', 'deltaPositionsWithAltitude'):
        for d in line_data:
            lat += d['deltaLatitude']
            lon += d['deltaLongitude']
            pts.append((lat / COORD_SCALE, lon / COORD_SCALE))
        return pts
    if line_type in ('absolutePositions', 'absolutePositionsWithAltitude'):
        return [(p['latitude'] / COORD_SCALE, p['longitude'] / COORD_SCALE)
                for p in line_data]
    return None


def get_zone_coords(glc_part: dict, ref_lat_raw: int, ref_lon_raw: int,
                    all_zone_last_pts: dict) -> Optional[list]:
    """
    Compute the (lat°, lon°) point list for a GlcPart zone.
    Handles old segment, new segment-setOfLanes (with optional segmentReferencePosition),
    and area variants.
    """
    zone = glc_part.get('zone')
    if zone is None:
        return None
    zone_type, zone_data = zone

    if zone_type == 'segment-carriagewayOrLane':
        line = zone_data.get('line')
        return coords_from_polygon_line(ref_lat_raw, ref_lon_raw, line) if line else None

    if zone_type == 'segment-setOfLanes':
        line = zone_data.get('line')
        seg_ref_zid = zone_data.get('segmentReferencePosition')  # Zid or None
        if line is None:
            return None
        if seg_ref_zid is not None and seg_ref_zid in all_zone_last_pts:
            # Use last point of referenced zone as new reference
            ref_pt = all_zone_last_pts[seg_ref_zid]
            r_lat = round(ref_pt[0] * COORD_SCALE)
            r_lon = round(ref_pt[1] * COORD_SCALE)
        else:
            r_lat, r_lon = ref_lat_raw, ref_lon_raw
        return coords_from_polygon_line(r_lat, r_lon, line)

    if zone_type == 'area':
        return coords_from_polygon_line(ref_lat_raw, ref_lon_raw, zone_data)

    return None  # computedSegment or unknown


def get_raw_delta_list(glc_part: dict) -> Optional[list]:
    """Return the raw list of delta dicts for a zone, or None."""
    zone = glc_part.get('zone')
    if zone is None:
        return None
    zone_type, zone_data = zone
    if zone_type == 'segment-carriagewayOrLane':
        line = zone_data.get('line')
    elif zone_type == 'segment-setOfLanes':
        line = zone_data.get('line')
    elif zone_type == 'area':
        line = zone_data
    else:
        return None
    if line is None:
        return None
    line_type, line_data = line
    if line_type in ('deltaPositions', 'deltaPositionsWithAltitude'):
        return list(line_data)
    return None


def zone_type_name(glc_part: dict) -> str:
    zone = glc_part.get('zone')
    if zone is None:
        return 'none'
    return zone[0]


def find_consecutive_chains(zone_ids: list, zone_coords: dict,
                             threshold: float = 25.0) -> list:
    """
    Group zone_ids into ordered chains of *consecutive* zones.

    Zone A is followed by zone B if the last point of A is within `threshold`
    metres of the first point of B (checked for all ordered pairs, so
    both forward and reverse orderings are handled).

    Parallel zones (same road section, different lanes) end up as separate
    singleton chains because their start/end points are not close to each
    other's start/end points.

    Returns a list of chains, each chain being an ordered list of zone_ids.
    """
    from collections import defaultdict

    if not zone_ids:
        return []

    # Build directed adjacency: A → B when last(A) is close to first(B)
    successors: dict = defaultdict(list)
    for a in zone_ids:
        for b in zone_ids:
            if a == b:
                continue
            pts_a = zone_coords.get(a)
            pts_b = zone_coords.get(b)
            if not pts_a or not pts_b:
                continue
            if haversine(*pts_a[-1], *pts_b[0]) <= threshold:
                successors[a].append(b)

    # Zones that appear as a successor have a predecessor
    has_predecessor: set = set()
    for nexts in successors.values():
        has_predecessor.update(nexts)

    # Chain starts: zones with no predecessor
    starts = [z for z in zone_ids if z not in has_predecessor]

    visited: set = set()
    chains: list = []

    def build_chain(start):
        chain = [start]
        visited.add(start)
        cur = start
        while True:
            nxt = next((z for z in successors.get(cur, [])
                        if z not in visited), None)
            if nxt is None:
                break
            chain.append(nxt)
            visited.add(nxt)
            cur = nxt
        return chain

    for start in starts:
        if start not in visited:
            chains.append(build_chain(start))

    # Any zone not yet visited is isolated (parallel) → singleton chain
    for z in zone_ids:
        if z not in visited:
            chains.append([z])

    return chains


def chain_length(chain: list, zone_coords: dict) -> float:
    """Total polyline length in metres of a consecutive chain of zones."""
    return sum(polyline_length(zone_coords[z])
               for z in chain if z in zone_coords and zone_coords[z])


def chain_summary(chains_with_len: list) -> str:
    """Human-readable description of chains and their lengths."""
    parts = []
    for chain, length in chains_with_len:
        if len(chain) == 1:
            parts.append(f'zone {chain[0]}: {length:.0f}m')
        else:
            arrow = ' → '.join(str(z) for z in chain)
            parts.append(f'[{arrow}]: {length:.0f}m (consecutive)')
    return ', '.join(parts)


# ─── Requirement checks ───────────────────────────────────────────────────────

def _chk(req_id, req_type, de_path, result, details) -> CheckResult:
    return CheckResult(req_id=req_id, req_type=req_type, de_path=de_path,
                       result=result, details=details)

def _pass(rid, rt, path, msg): return _chk(rid, rt, path, 'PASS', msg)
def _fail(rid, rt, path, msg): return _chk(rid, rt, path, 'FAIL', msg)
def _warn(rid, rt, path, msg): return _chk(rid, rt, path, 'WARN', msg)
def _na(rid, rt, path, msg):   return _chk(rid, rt, path, 'N/A',  msg)
def _skip(rid, rt, path, msg): return _chk(rid, rt, path, 'SKIP', msg)


def check_ivim_cancellation(ivim: dict) -> IvimReport:
    """
    Compliance checks for a *cancellation* IVIM per MP chapter 4.2.2.8.

    Cancellation IVIMs only require the mandatory container (iviStatus=2 plus
    the original iviIdentificationNumber).  All optional containers are not
    required and their content checks are N/A.
    """
    hdr       = ivim['header']
    mandatory = ivim['ivi']['mandatory']

    ivi_id     = mandatory['iviIdentificationNumber']
    report     = IvimReport(ivi_id=ivi_id, station_id=hdr['stationId'], status=2)
    R = report.checks.append

    # ── IviManagementContainer ──────────────────────────────────────────────
    ts = mandatory.get('timeStamp')
    if ts is not None:
        R(_pass('MP_Req_0078 (1)', 'REQ', 'mandatory.timestamp',
                f'timestamp present: {ts}'))
    else:
        R(_fail('MP_Req_0078 (1)', 'REQ', 'mandatory.timestamp',
                'timestamp absent – mandatory field'))

    R(_na('MP_Req_0082 (1)', 'REQ', 'mandatory.validTo',
          'validTo not required for cancellation IVIM (MP 4.2.2.8)'))

    R(_pass('MP_Req_0086 (1)', 'REQ', 'mandatory.iviStatus',
            'iviStatus = 2 (cancellation) – valid'))

    # ── Optional containers: N/A for cancellation ───────────────────────────
    _na_cancel = ('N/A for cancellation IVIM – optional containers not '
                  'required (MP 4.2.2.8)')
    for rid, path in [
        ('MP_Req_0637 (1)', 'optional.glc'),
        ('MP_Req_0092 (1)', 'optional.glc.parts'),
        ('MP_Req_0094 (1)', 'optional.glc.parts.zoneId'),
        ('MP_Req_0097 (2)', 'optional.glc.parts.zone'),
        ('MP_Req_0099 (1)', 'optional.glc.parts.zone'),
        ('MP_Rec_0098 (1)', 'optional.glc.parts.zone'),
        ('MP_Req_0103 (1)', 'optional.glc.parts.zone'),
        ('MP_Req_0128 (1)', 'optional.glc.parts.zone.segment-setOfLanes.segmentWidthLeft'),
    ]:
        R(_na(rid, 'REQ', path, _na_cancel))

    R(_skip('SUD_IVS_Rec_0004 (1)', 'REC', 'optional.glc + optional.giv',
            'N/A for cancellation IVIM'))

    _na_rcc = 'N/A for cancellation IVIM – RCC not required (MP 4.2.2.8)'
    for rid, path in [
        ('MP_Req_0105 (1)', 'optional.rcc'),
        ('MP_Req_0108 (1)', 'optional.rcc.laneConfiguration'),
        ('MP_Req_0109 (1)', 'optional.rcc.laneConfiguration.direction'),
        ('MP_Req_0111 (1)', 'optional.rcc.laneConfiguration.laneType'),
    ]:
        R(_na(rid, 'REQ', path, _na_rcc))

    _na_giv = 'N/A for cancellation IVIM – GIV not required (MP 4.2.2.8)'
    for rid, path in [
        ('MP_Req_0113 (1)', 'optional.giv'),
        ('MP_Req_0121 (1)', 'optional.giv.relevanceZoneIds'),
        ('MP_Req_0114 (1)', 'optional.giv GicPart: roadSignCodes'),
        ('MP_Req_0123 (1)', 'optional.giv.direction'),
        ('MP_Req_0138 (1)', 'optional.giv.RSCode.code'),
        ('MP_Req_0131 (1)', 'optional.giv.iviType'),
        ('MP_Req_0116 (1)', 'optional.giv.detectionZoneIds'),
        ('MP_Req_0117 (1)', 'optional.giv.detectionZoneIds – total length'),
        ('MP_Rec_0118 (1)', 'optional.giv.detectionZoneIds – total length'),
        ('MP_Req_0119 (1)', 'optional.giv.driverAwarenessZoneIds'),
        ('MP_Req_0125 (1)', 'optional.giv.driverAwarenessZoneIds'),
        ('MP_Req_0135 (1)', 'optional.giv – RSCode uniqueness across GicParts'),
    ]:
        R(_na(rid, 'REQ', path, _na_giv))

    # ── SUD requirements ────────────────────────────────────────────────────
    R(_pass('SUD_IVS_Req_0001 (1)', 'REQ', 'IVIM for IVS-TS',
            'Meta-requirement: cancellation checked per MP 4.2.2.8'))
    R(_skip('SUD_IVS_Req_0002 (1)', 'REQ', 'cancellation IVIM repetition',
            'Out-of-scope: requires runtime/network-level observation '
            '(cancellation repeated ≥5min) – not checkable from PCAP snapshot'))
    R(_na('SUD_IVS_Rec_0003 (1)', 'REC', 'cancellation repetition for validTo messages',
          'N/A – this IVIM IS the cancellation'))

    _na_sud = 'N/A for cancellation IVIM'
    for rid, path in [
        ('SUD_IVS_Req_0005 (1)', 'optional.giv.roadSignCodes'),
        ('SUD_IVS_Req_0020 (1)', 'IVIM self-contained'),
        ('SUD_IVS_Req_0021 (1)', 'one GicPart per sign'),
        ('SUD_IVS_Req_0022 (1)', 'extraText null char'),
        ('SUD_IVS_Req_0023 (1)', 'optional.giv.roadSignCodes.attributes'),
        ('SUD_IVS_Req_0024 (1)', 'optional.giv.roadSignCodes'),
        ('SUD_IVS_Req_0027 (1)', 'RCC present'),
    ]:
        R(_na(rid, 'REQ', path, _na_sud))

    return report


def check_ivim(ivim: dict) -> IvimReport:
    """Run all applicable C-ROADS IVS compliance checks on one decoded IVIM."""
    hdr       = ivim['header']
    mandatory = ivim['ivi']['mandatory']
    optional  = ivim['ivi'].get('optional') or []

    ivi_id     = mandatory['iviIdentificationNumber']
    ivi_status = mandatory['iviStatus']

    # Cancellation IVIMs use a reduced profile (MP 4.2.2.8)
    if ivi_status == 2:
        return check_ivim_cancellation(ivim)

    report     = IvimReport(ivi_id=ivi_id, station_id=hdr['stationId'],
                            status=ivi_status)
    R = report.checks.append  # shorthand

    # Parse containers
    glc_list, giv_parts, rcc_parts = [], [], []
    for ctype, cdata in optional:
        if ctype == 'glc':
            glc_list.append(cdata)
        elif ctype == 'giv':
            giv_parts = list(cdata)
        elif ctype == 'rcc':
            rcc_parts = list(cdata)

    # Helper: status label
    status_names = {0: 'new', 1: 'update', 2: 'cancellation', 3: 'negation'}
    status_label = status_names.get(ivi_status, str(ivi_status))

    # ── Section 1: IviManagementContainer ─────────────────────────────────────

    # MP_Req_0078: timestamp shall be provided
    rid = 'MP_Req_0078 (1)'; path = 'mandatory.timestamp'
    ts = mandatory.get('timeStamp')
    if ts is not None:
        R(_pass(rid, 'REQ', path, f'timestamp present: {ts}'))
    else:
        R(_fail(rid, 'REQ', path, 'timestamp is absent – mandatory field'))

    # MP_Req_0082: validTo ≥ timestamp + 1h (only for new/update)
    rid = 'MP_Req_0082 (1)'; path = 'mandatory.validTo'
    valid_to = mandatory.get('validTo')
    if valid_to is None:
        R(_na(rid, 'REQ', path, 'validTo not present – requirement does not apply'))
    elif ivi_status not in (0, 1):
        R(_na(rid, 'REQ', path,
              f'iviStatus={status_label} – requirement only applies to new/update'))
    elif ts is None:
        R(_na(rid, 'REQ', path, 'timestamp absent – cannot evaluate validTo delta'))
    else:
        delta_ms  = valid_to - ts
        delta_s   = delta_ms / 1000
        min_ms    = MS_PER_HOUR
        if delta_ms >= min_ms:
            R(_pass(rid, 'REQ', path,
                    f'validTo − timestamp = {delta_s:.0f}s ≥ 3600s (1 hour)'))
        else:
            R(_fail(rid, 'REQ', path,
                    f'validTo − timestamp = {delta_s:.0f}s < 3600s (1 hour minimum). '
                    f'timestamp={ts}, validTo={valid_to}'))

    # MP_Req_0086: iviStatus valid range 0..3
    rid = 'MP_Req_0086 (1)'; path = 'mandatory.iviStatus'
    if ivi_status in (0, 1, 2, 3):
        R(_pass(rid, 'REQ', path,
                f'iviStatus = {ivi_status} ({status_label}) – valid'))
    else:
        R(_fail(rid, 'REQ', path,
                f'iviStatus = {ivi_status} – not in valid range {{0,1,2,3}}'))

    # ── Section 2: GeographicLocationContainer ─────────────────────────────────

    # MP_Req_0637: at least one GLC
    rid = 'MP_Req_0637 (1)'; path = 'optional.glc'
    if glc_list:
        R(_pass(rid, 'REQ', path, f'{len(glc_list)} GLC container(s) present'))
    else:
        R(_fail(rid, 'REQ', path, 'No GLC container present – at least one is required'))

    if not glc_list:
        # No GLC → skip all zone-level checks
        R(_skip('MP_Req_0092 (1)', 'REQ', 'optional.glc.parts',
                'Skipped: no GLC present'))
        R(_skip('MP_Req_0094 (1)', 'REQ', 'optional.glc.parts.zoneId',
                'Skipped: no GLC present'))
    else:
        # Collect all zone definitions across all GLCs
        all_glc_zone_ids: set[int] = set()
        for glc in glc_list:
            for part in glc.get('parts', []):
                all_glc_zone_ids.add(part['zoneId'])

        # Collect all zone IDs referenced in GIV / RCC
        referenced_zone_ids: set[int] = set()
        for gp in giv_parts:
            for fld in ('detectionZoneIds', 'relevanceZoneIds', 'driverAwarenessZoneIds'):
                referenced_zone_ids.update(gp.get(fld) or [])
        for rp in rcc_parts:
            referenced_zone_ids.update(rp.get('relevanceZoneIds') or [])
            for li in (rp.get('laneConfiguration') or []):
                for fld in ('detectionZoneIds', 'relevanceZoneIds'):
                    referenced_zone_ids.update(li.get(fld) or [])

        # MP_Req_0092: self-contained – all referenced zones defined in GLC
        rid = 'MP_Req_0092 (1)'; path = 'optional.glc.parts'
        active_refs = referenced_zone_ids - {32}  # 32 = "no zone" sentinel
        missing = active_refs - all_glc_zone_ids
        if not missing:
            R(_pass(rid, 'REQ', path,
                    f'All referenced zone IDs {sorted(active_refs)} are defined in GLC'))
        else:
            R(_fail(rid, 'REQ', path,
                    f'Zone IDs {sorted(missing)} are referenced but not defined in GLC'))

        # MP_Req_0094: zoneId 32 not used as active zone
        rid = 'MP_Req_0094 (1)'; path = 'optional.glc.parts.zoneId'
        if 32 in all_glc_zone_ids:
            R(_fail(rid, 'REQ', path,
                    'zoneId=32 ("noZone") is used as an active zone in GLC – forbidden'))
        else:
            R(_pass(rid, 'REQ', path,
                    'zoneId=32 not used as active zone ID in GLC'))

        # Per-zone checks across all GLCs
        old_fmt_zones = []
        zones_without_geometry = []

        for glc in glc_list:
            ref_lat_raw = glc['referencePosition']['latitude']
            ref_lon_raw = glc['referencePosition']['longitude']
            ref_lat = ref_lat_raw / COORD_SCALE
            ref_lon = ref_lon_raw / COORD_SCALE
            parts   = glc.get('parts', [])

            # Two-pass: first compute coords for all zones so segmentReferencePosition works
            zone_coords:    dict[int, list] = {}
            zone_last_pts:  dict[int, tuple] = {}
            for part in parts:
                coords = get_zone_coords(part, ref_lat_raw, ref_lon_raw, zone_last_pts)
                if coords:
                    zone_coords[part['zoneId']] = coords
                    zone_last_pts[part['zoneId']] = coords[-1]

            # MP_Req_0097 (2): zone type shall be segment-setOfLanes
            rid = 'MP_Req_0097 (2)'; path = 'optional.glc.parts.zone'
            old_in_glc = [p['zoneId'] for p in parts
                          if zone_type_name(p) == 'segment-carriagewayOrLane']
            new_in_glc = [p['zoneId'] for p in parts
                          if zone_type_name(p) == 'segment-setOfLanes']
            other_in_glc = [p['zoneId'] for p in parts
                            if zone_type_name(p) not in
                            ('segment-carriagewayOrLane', 'segment-setOfLanes')]
            if old_in_glc:
                old_fmt_zones.extend(old_in_glc)
                msg = (f'Zone(s) {old_in_glc} use segment-carriagewayOrLane (old format). '
                       'segment-setOfLanes is required (MP 3.2.0). '
                       'Old format accepted for backwards compatibility (note in MP_Req_0100).')
                R(_warn(rid, 'REQ', path, msg))
            elif new_in_glc:
                R(_pass(rid, 'REQ', path,
                        f'All {len(new_in_glc)} zone(s) use segment-setOfLanes'))
            else:
                R(_na(rid, 'REQ', path,
                      f'No segment zones found (types: {[zone_type_name(p) for p in parts]})'))

            for part in parts:
                zid  = part['zoneId']
                ztyp = zone_type_name(part)
                pts  = zone_coords.get(zid)
                if pts is None:
                    zones_without_geometry.append(zid)

                # MP_Req_0099: non-empty deltaPositions
                rid = f'MP_Req_0099 (1)'; path = f'optional.glc.parts.zone (zone {zid})'
                raw_deltas = get_raw_delta_list(part)
                if raw_deltas is None:
                    R(_na(rid, 'REQ', path,
                          f'Zone {zid}: zone type {ztyp} does not use deltaPositions'))
                elif len(raw_deltas) == 0:
                    R(_fail(rid, 'REQ', path,
                            f'Zone {zid}: deltaPositions list is empty'))
                else:
                    R(_pass(rid, 'REQ', path,
                            f'Zone {zid}: deltaPositions has {len(raw_deltas)} point(s)'))

                # MP_Rec_0098: refPos should not be start of zone (first delta ≠ (0,0))
                rid = 'MP_Rec_0098 (1)'; path = f'optional.glc.parts.zone (zone {zid})'
                if raw_deltas and len(raw_deltas) > 0:
                    d0 = raw_deltas[0]
                    if d0['deltaLatitude'] == 0 and d0['deltaLongitude'] == 0:
                        R(_warn(rid, 'REC', path,
                                f'Zone {zid}: first deltaPosition is (0,0) – '
                                'referencePosition is explicitly the zone start point. '
                                'Recommendation: refPos should not be part of zone definition.'))
                    else:
                        R(_pass(rid, 'REC', path,
                                f'Zone {zid}: first deltaPosition ≠ (0,0) – '
                                'referencePosition is not duplicated as zone start'))
                else:
                    R(_na(rid, 'REC', path,
                          f'Zone {zid}: no delta positions available'))

                # MP_Req_0103: sorted closest-to-farthest from reference
                rid = 'MP_Req_0103 (1)'; path = f'optional.glc.parts.zone (zone {zid})'
                if pts and len(pts) >= 2:
                    d_first = haversine(ref_lat, ref_lon, pts[0][0], pts[0][1])
                    d_last  = haversine(ref_lat, ref_lon, pts[-1][0], pts[-1][1])
                    is_old  = (ztyp == 'segment-carriagewayOrLane')
                    note    = (' [backwards-compat zone type – check informational only]'
                               if is_old else '')
                    if d_first <= d_last:
                        R(_pass(rid, 'REQ', path,
                                f'Zone {zid}: first point {d_first:.1f}m from refPos, '
                                f'last point {d_last:.1f}m – sorted closest-to-farthest{note}'))
                    else:
                        R(_fail(rid, 'REQ', path,
                                f'Zone {zid}: first point {d_first:.1f}m from refPos, '
                                f'last point {d_last:.1f}m – sorted farthest-to-closest '
                                f'(should be closest-to-farthest){note}'))
                elif pts and len(pts) == 1:
                    R(_na(rid, 'REQ', path,
                          f'Zone {zid}: single-point zone – ordering check not applicable'))
                else:
                    R(_na(rid, 'REQ', path,
                          f'Zone {zid}: no geometry available'))

                # MP_Req_0128: segmentWidthLeft shall be present for segment-setOfLanes
                rid = 'MP_Req_0128 (1)'
                path = f'optional.glc.parts.zone.segment-setOfLanes.segmentWidthLeft (zone {zid})'
                if ztyp == 'segment-setOfLanes':
                    zone_data = part.get('zone', (None, {}))[1]
                    sw_left   = zone_data.get('segmentWidthLeft')
                    if sw_left is not None:
                        R(_pass(rid, 'REQ', path,
                                f'Zone {zid}: segmentWidthLeft = {sw_left} (present)'))
                    else:
                        R(_fail(rid, 'REQ', path,
                                f'Zone {zid}: segmentWidthLeft absent – '
                                'shall be provided (except if road operator lacks the info)'))
                else:
                    R(_na(rid, 'REQ', path,
                          f'Zone {zid}: only applies to segment-setOfLanes zones '
                          f'(this zone is {ztyp})'))

    # ── Section 3: RoadConfigurationContainer ────────────────────────────────

    # MP_Req_0105: RCC shall be provided
    rid = 'MP_Req_0105 (1)'; path = 'optional.rcc'
    if rcc_parts:
        R(_pass(rid, 'REQ', path,
                f'{len(rcc_parts)} RCC part(s) present'))
    else:
        R(_fail(rid, 'REQ', path,
                'No RCC container present – shall be provided (unless road operator '
                'does not have the information)'))

    for rcc_idx, rcc_part in enumerate(rcc_parts):
        lane_cfg = rcc_part.get('laneConfiguration', [])

        # MP_Req_0108: each lane represented only once
        rid  = 'MP_Req_0108 (1)'; path = f'optional.rcc.laneConfiguration (RCC part {rcc_idx+1})'
        lane_nums = [li.get('laneNumber') for li in lane_cfg]
        seen, dupes = set(), set()
        for ln in lane_nums:
            (dupes if ln in seen else seen).add(ln)
        if dupes:
            R(_fail(rid, 'REQ', path,
                    f'Duplicate laneNumber(s) in RCC part {rcc_idx+1}: {sorted(dupes)}'))
        else:
            R(_pass(rid, 'REQ', path,
                    f'All {len(lane_nums)} lane(s) have unique laneNumbers in RCC part {rcc_idx+1}'))

        for li in lane_cfg:
            ln = li.get('laneNumber', '?')

            # MP_Req_0109: direction = sameDirection(0)
            rid  = 'MP_Req_0109 (1)'
            path = f'optional.rcc.laneConfiguration.direction (lane {ln})'
            direction = li.get('direction')
            if direction is None:
                R(_fail(rid, 'REQ', path,
                        f'Lane {ln}: direction absent – shall be sameDirection(0)'))
            elif direction == 0:
                R(_pass(rid, 'REQ', path,
                        f'Lane {ln}: direction = 0 (sameDirection)'))
            else:
                R(_fail(rid, 'REQ', path,
                        f'Lane {ln}: direction = {direction} – shall be sameDirection(0)'))

            # MP_Req_0111: laneType within valid set
            rid  = 'MP_Req_0111 (1)'
            path = f'optional.rcc.laneConfiguration.laneType (lane {ln})'
            lt   = li.get('laneType')
            lt_name = LANE_TYPE_NAMES.get(lt, str(lt))
            if lt is None:
                R(_fail(rid, 'REQ', path,
                        f'Lane {ln}: laneType absent – mandatory field'))
            elif lt in VALID_LANE_TYPES:
                R(_pass(rid, 'REQ', path,
                        f'Lane {ln}: laneType = {lt} ({lt_name}) – valid per C-Roads profile'))
            else:
                R(_fail(rid, 'REQ', path,
                        f'Lane {ln}: laneType = {lt} ({lt_name}) – '
                        f'not in C-Roads valid set {VALID_LANE_TYPES}'))

    # ── Section 4: GeneralIviContainer (IVS-specific) ─────────────────────────

    # MP_Req_0113: giv shall be used for IVS
    rid = 'MP_Req_0113 (1)'; path = 'optional.giv'
    if giv_parts:
        R(_pass(rid, 'REQ', path,
                f'GeneralIviContainer (giv) present with {len(giv_parts)} GicPart(s)'))
    else:
        R(_fail(rid, 'REQ', path,
                'No GeneralIviContainer (giv) present – required for IVS'))

    # Rebuild zone geometry lookup for GIV checks
    all_zone_coords: dict[int, list] = {}
    if glc_list:
        for glc in glc_list:
            ref_lat_raw = glc['referencePosition']['latitude']
            ref_lon_raw = glc['referencePosition']['longitude']
            parts       = glc.get('parts', [])
            last_pts: dict[int, tuple] = {}
            for part in parts:
                coords = get_zone_coords(part, ref_lat_raw, ref_lon_raw, last_pts)
                if coords:
                    all_zone_coords[part['zoneId']] = coords
                    last_pts[part['zoneId']] = coords[-1]

    for gic_idx, gic_part in enumerate(giv_parts):
        det_ids = list(gic_part.get('detectionZoneIds') or [])
        rel_ids = list(gic_part.get('relevanceZoneIds') or [])
        awa_ids = list(gic_part.get('driverAwarenessZoneIds') or [])
        rsc     = list(gic_part.get('roadSignCodes') or [])

        # MP_Req_0121: relevanceZoneIds shall be present – the relevance zone
        # shall represent the complete road segment where the traffic rules
        # indicated by this GicPart are applicable
        rid  = 'MP_Req_0121 (1)'
        path = f'optional.giv.relevanceZoneIds (GicPart {gic_idx+1})'
        if not rel_ids:
            R(_fail(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: no relevanceZoneIds – at least one zone '
                    'must be dedicated as the relevance zone (representing the '
                    'complete road segment where this GicPart\'s traffic rules apply)'))
        else:
            R(_pass(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: relevanceZoneIds = {rel_ids}'))

        # MP_Req_0114: one GicPart per traffic sign (max 1 main + 3 subsigns via RSCode)
        rid  = 'MP_Req_0114 (1)'
        path = f'optional.giv GicPart {gic_idx+1}: roadSignCodes'
        if len(rsc) == 0:
            R(_fail(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: no roadSignCodes – at least one required'))
        elif len(rsc) <= 4:
            R(_pass(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: {len(rsc)} RSCode(s) – '
                    '1 main sign + up to 3 subsigns'))
        else:
            R(_fail(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: {len(rsc)} RSCodes exceed maximum of 4 '
                    '(1 main + 3 subsigns)'))

        # MP_Req_0123: direction = sameDirection(0)
        rid     = 'MP_Req_0123 (1)'
        path    = f'optional.giv.direction (GicPart {gic_idx+1})'
        giv_dir = gic_part.get('direction')
        if giv_dir is None:
            R(_fail(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: direction absent – '
                    'mandatory, shall be sameDirection(0)'))
        elif giv_dir == 0:
            R(_pass(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: direction = 0 (sameDirection)'))
        else:
            R(_fail(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: direction = {giv_dir} – '
                    'shall be sameDirection(0)'))

        # MP_Req_0138: RSCode.code choice shall be iso14823
        rid = 'MP_Req_0138 (1)'
        for rsc_idx, rsc_item in enumerate(rsc):
            path  = (f'optional.giv.RSCode.code (GicPart {gic_idx+1}, '
                     f'RSCode {rsc_idx+1})')
            code  = rsc_item.get('code')
            if code is None:
                R(_fail(rid, 'REQ', path,
                        f'GicPart {gic_idx+1} RSCode {rsc_idx+1}: code absent'))
            else:
                choice, _ = code
                if choice == 'iso14823':
                    R(_pass(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} RSCode {rsc_idx+1}: '
                            'code choice is iso14823'))
                else:
                    R(_fail(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} RSCode {rsc_idx+1}: '
                            f'code choice is {choice!r} – shall be iso14823'))

        # MP_Req_0131: iviType shall match ISO 14823 service category of main sign
        rid  = 'MP_Req_0131 (1)'
        path = f'optional.giv.iviType (GicPart {gic_idx+1})'
        ivi_type = gic_part.get('iviType')
        if ivi_type is None:
            R(_fail(rid, 'REQ', path,
                    f'GicPart {gic_idx+1}: iviType absent – mandatory field'))
        elif rsc:
            main_code = rsc[0].get('code')
            if main_code and main_code[0] == 'iso14823':
                iso = main_code[1]
                pc  = iso.get('pictogramCode', {})
                scc = pc.get('serviceCategoryCode')
                if scc:
                    sc_choice, sc_val = scc
                    expected = IVI_TYPE_MAPPING.get((sc_choice, sc_val))
                    if expected is None:
                        R(_na(rid, 'REQ', path,
                              f'GicPart {gic_idx+1}: serviceCategoryCode '
                              f'({sc_choice}/{sc_val}) has no standard iviType mapping '
                              f'(supplementaryPanel or unknown) – manual check required'))
                    elif ivi_type == expected:
                        R(_pass(rid, 'REQ', path,
                                f'GicPart {gic_idx+1}: iviType={ivi_type} matches '
                                f'ISO14823 category {sc_choice}/{sc_val}'))
                    else:
                        R(_fail(rid, 'REQ', path,
                                f'GicPart {gic_idx+1}: iviType={ivi_type} but '
                                f'ISO14823 category {sc_choice}/{sc_val} requires '
                                f'iviType={expected}'))
                else:
                    R(_na(rid, 'REQ', path,
                          f'GicPart {gic_idx+1}: serviceCategoryCode not found '
                          'in main sign'))
            else:
                R(_na(rid, 'REQ', path,
                      f'GicPart {gic_idx+1}: main sign not iso14823 – '
                      'iviType mapping not applicable'))
        else:
            R(_na(rid, 'REQ', path, f'GicPart {gic_idx+1}: no RSCodes to map'))

        # Zone-length and connectivity checks require geometry
        if not all_zone_coords:
            for rid2 in ('MP_Req_0116 (1)', 'MP_Req_0117 (1)', 'MP_Rec_0118 (1)',
                         'MP_Req_0119 (1)', 'MP_Req_0125 (1)'):
                R(_skip(rid2, 'REQ', f'GicPart {gic_idx+1}',
                        'Skipped: no GLC geometry available'))
        else:
            # Gather points for detection/relevance/awareness zones
            rel_pts_all = [pt for zid in rel_ids
                           for pt in (all_zone_coords.get(zid) or [])]

            # ── Consecutive-chain analysis ─────────────────────────────────
            # Only consecutive (end-to-start linked) zones may be summed for
            # length requirements.  Parallel zones (different lanes covering the
            # same road section) form separate chains and are NOT added together.
            CHAIN_THRESHOLD = 25.0  # metres – max gap between end of A and start of B

            det_chains = find_consecutive_chains(det_ids, all_zone_coords, CHAIN_THRESHOLD)
            det_chains_len = [(ch, chain_length(ch, all_zone_coords)) for ch in det_chains]
            # Best chain = longest consecutive trajectory
            best_det = max(det_chains_len, key=lambda x: x[1], default=([], 0.0))
            max_det_len = best_det[1]

            awa_chains = find_consecutive_chains(awa_ids, all_zone_coords, CHAIN_THRESHOLD)
            awa_chains_len = [(ch, chain_length(ch, all_zone_coords)) for ch in awa_chains]
            best_awa = max(awa_chains_len, key=lambda x: x[1], default=([], 0.0))
            max_awa_len = best_awa[1]

            # MP_Req_0116: first point of each detection zone ≤1m from
            #              any point in relevance zone or other detection zone
            rid  = 'MP_Req_0116 (1)'
            path = f'optional.giv.detectionZoneIds (GicPart {gic_idx+1})'
            old_fmt = any(zone_type_name(p) == 'segment-carriagewayOrLane'
                          for glc in glc_list
                          for p in glc.get('parts', [])
                          if p['zoneId'] in det_ids)
            compat_note = (' [backwards-compat zone type – informational check]'
                           if old_fmt else '')
            failures = []
            for zid in det_ids:
                coords = all_zone_coords.get(zid)
                if not coords:
                    continue
                first_pt = coords[0]
                # Compare against all relevance zone points + all other detection zone points
                other_pts = list(rel_pts_all)
                for other_id in det_ids:
                    if other_id != zid:
                        other_pts.extend(all_zone_coords.get(other_id) or [])
                if not other_pts:
                    failures.append(f'zone {zid}: no reference points to compare against')
                    continue
                d = min_dist_to_zone(first_pt, other_pts)
                if d > 1.0:
                    failures.append(
                        f'zone {zid}: first point {d:.1f}m from nearest '
                        'relevance/detection zone point (max 1m)')
            if not det_ids:
                R(_na(rid, 'REQ', path,
                      f'GicPart {gic_idx+1}: no detectionZoneIds – N/A'))
            elif failures:
                R(_fail(rid, 'REQ', path,
                        f'GicPart {gic_idx+1}: {"; ".join(failures)}{compat_note}'))
            else:
                R(_pass(rid, 'REQ', path,
                        f'GicPart {gic_idx+1}: first points of detection zones '
                        f'{det_ids} are within 1m of relevance/detection zone points'
                        f'{compat_note}'))

            # MP_Req_0117: longest consecutive detection zone chain ≥ 800m
            rid  = 'MP_Req_0117 (1)'
            path = f'optional.giv.detectionZoneIds – total length (GicPart {gic_idx+1})'
            chain_desc_str = chain_summary(det_chains_len)
            n_parallel = sum(1 for ch, _ in det_chains_len if len(ch) == 1)
            parallel_note = (f' ({n_parallel} parallel singleton(s), only longest '
                             f'consecutive chain counts)'
                             if len(det_chains_len) > 1 else '')
            if not det_ids:
                R(_na(rid, 'REQ', path,
                      f'GicPart {gic_idx+1}: no detectionZoneIds – N/A'))
            elif max_det_len >= 800:
                R(_pass(rid, 'REQ', path,
                        f'GicPart {gic_idx+1}: longest consecutive detection chain = '
                        f'{max_det_len:.0f}m ≥ 800m{parallel_note}. '
                        f'Chains: {chain_desc_str}'))
            elif max_det_len >= 795:
                R(_warn(rid, 'REQ', path,
                        f'GicPart {gic_idx+1}: longest consecutive detection chain = '
                        f'{max_det_len:.0f}m – marginally below 800m minimum '
                        f'(tolerance band 795–799m){parallel_note}. '
                        f'Chains: {chain_desc_str}'))
            else:
                R(_fail(rid, 'REQ', path,
                        f'GicPart {gic_idx+1}: longest consecutive detection chain = '
                        f'{max_det_len:.0f}m < 795m (800m minimum, tolerance band '
                        f'795–799m){parallel_note}. '
                        f'Chains: {chain_desc_str}'))

            # MP_Rec_0118: longest consecutive detection zone chain ≤ 2000m
            rid  = 'MP_Rec_0118 (1)'
            path = f'optional.giv.detectionZoneIds – total length (GicPart {gic_idx+1})'
            if not det_ids:
                R(_na(rid, 'REC', path,
                      f'GicPart {gic_idx+1}: no detectionZoneIds – N/A'))
            elif max_det_len <= 2000:
                R(_pass(rid, 'REC', path,
                        f'GicPart {gic_idx+1}: longest consecutive detection chain = '
                        f'{max_det_len:.0f}m ≤ 2000m'))
            else:
                R(_warn(rid, 'REC', path,
                        f'GicPart {gic_idx+1}: longest consecutive detection chain = '
                        f'{max_det_len:.0f}m > 2000m recommended maximum. '
                        f'Chains: {chain_desc_str}'))

            # MP_Req_0119 / MP_Req_0125: longest consecutive detection chain ≥
            #                            longest consecutive awareness chain
            rid_119 = 'MP_Req_0119 (1)'; rid_125 = 'MP_Req_0125 (1)'
            path_awa = f'optional.giv.driverAwarenessZoneIds (GicPart {gic_idx+1})'
            if not awa_ids:
                R(_na(rid_119, 'REQ', path_awa,
                      f'GicPart {gic_idx+1}: no driverAwarenessZoneIds – N/A'))
                R(_na(rid_125, 'REQ', path_awa,
                      f'GicPart {gic_idx+1}: no driverAwarenessZoneIds – N/A'))
            else:
                cmp_txt = (f'max consecutive detection chain={max_det_len:.0f}m, '
                           f'max consecutive awareness chain={max_awa_len:.0f}m')
                if max_det_len >= max_awa_len:
                    R(_pass(rid_119, 'REQ', path_awa,
                            f'GicPart {gic_idx+1}: {cmp_txt} – detection ≥ awareness'))
                    R(_pass(rid_125, 'REQ', path_awa,
                            f'GicPart {gic_idx+1}: {cmp_txt} – awareness ≤ detection'))
                else:
                    R(_fail(rid_119, 'REQ', path_awa,
                            f'GicPart {gic_idx+1}: {cmp_txt} – '
                            'longest consecutive detection chain shorter than '
                            'longest consecutive awareness chain'))
                    R(_fail(rid_125, 'REQ', path_awa,
                            f'GicPart {gic_idx+1}: {cmp_txt} – '
                            'longest consecutive awareness chain longer than '
                            'longest consecutive detection chain'))

        # MP_Req_0142 & MP_Req_0144: extraText checks
        extra_text = gic_part.get('extraText')
        if extra_text is not None:
            for et_idx, et in enumerate(extra_text):
                tc = et.get('textContent', '')
                lc = et.get('layoutComponentId')

                # MP_Req_0142: null char if no extra text
                rid  = 'MP_Req_0142 (1)'
                path = (f'optional.giv.extraText (GicPart {gic_idx+1}, '
                        f'text entry {et_idx+1})')
                if tc == '' or (len(tc) == 1 and tc[0] == '\x00'):
                    R(_pass(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} extraText[{et_idx+1}]: '
                            'null character present for empty text slot'))
                else:
                    # non-empty text – acceptable (requirement only mandates null if no text)
                    R(_pass(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} extraText[{et_idx+1}]: '
                            f'text content present ({len(tc)} chars)'))

                # MP_Req_0144: layoutComponentId shall be 1
                rid  = 'MP_Req_0144 (1)'
                path = (f'optional.giv.extraText.layoutComponentId '
                        f'(GicPart {gic_idx+1}, entry {et_idx+1})')
                if lc is None:
                    R(_fail(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} extraText[{et_idx+1}]: '
                            'layoutComponentId absent – shall be set to 1'))
                elif lc == 1:
                    R(_pass(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} extraText[{et_idx+1}]: '
                            'layoutComponentId = 1'))
                else:
                    R(_fail(rid, 'REQ', path,
                            f'GicPart {gic_idx+1} extraText[{et_idx+1}]: '
                            f'layoutComponentId = {lc} – shall be 1'))

    # MP_Req_0135: RSCode appears only once across all GicParts
    rid  = 'MP_Req_0135 (1)'; path = 'optional.giv – RSCode uniqueness across GicParts'
    iso_codes = []
    for gic_idx, gic_part in enumerate(giv_parts):
        for rsc_item in (gic_part.get('roadSignCodes') or []):
            code = rsc_item.get('code')
            if code and code[0] == 'iso14823':
                pc  = code[1].get('pictogramCode', {})
                pcc = pc.get('pictogramCategoryCode', {})
                sig = (pc.get('serviceCategoryCode'),
                       pcc.get('nature'),
                       pcc.get('serialNumber'))
                iso_codes.append((gic_idx+1, sig))
    seen_codes, dup_codes = {}, []
    for gic_nr, sig in iso_codes:
        if sig in seen_codes:
            dup_codes.append(f'{sig} in GicPart {seen_codes[sig]} and {gic_nr}')
        else:
            seen_codes[sig] = gic_nr
    if dup_codes:
        R(_fail(rid, 'REQ', path,
                'Duplicate RSCode(s) found across GicParts: ' + '; '.join(dup_codes)))
    else:
        R(_pass(rid, 'REQ', path,
                f'All {len(iso_codes)} RSCode(s) appear uniquely across GicParts'))

    # ── Section 5: SUD-specific requirements (2.2.1.1) ───────────────────────

    # SUD_IVS_Req_0001: covered by all MP checks above
    R(_pass('SUD_IVS_Req_0001 (1)', 'REQ',
            'IVIM for IVS-TS',
            'Meta-requirement: all applicable MP chapter 4.2.2.2 requirements '
            'checked above'))

    # SUD_IVS_Req_0002 / SUD_IVS_Rec_0003: apply only to cancellation IVIMs
    R(_na('SUD_IVS_Req_0002 (1)', 'REQ',
          'cancellation IVIM repetition',
          f'N/A – applies only to cancellation IVIMs (iviStatus=2); '
          f'this IVIM has iviStatus={ivi_status} ({status_label})'))
    R(_na('SUD_IVS_Rec_0003 (1)', 'REC',
          'cancellation repetition for validTo messages',
          f'N/A – applies only to cancellation IVIMs (iviStatus=2); '
          f'this IVIM has iviStatus={ivi_status} ({status_label})'))

    # SUD_IVS_Rec_0004: zones for diverging roads referenced in GIC
    rid  = 'SUD_IVS_Rec_0004 (1)'; path = 'optional.glc + optional.giv'
    R(_skip(rid, 'REC', path,
            'Out-of-scope: whether all diverging/converging roads have suitable zones '
            'requires map/topology knowledge not available at ASN.1 level'))

    # SUD_IVS_Req_0005: machine-readable encoding (check iso14823 used)
    rid  = 'SUD_IVS_Req_0005 (1)'; path = 'optional.giv.roadSignCodes'
    non_iso = []
    for gic_idx, gic_part in enumerate(giv_parts):
        for rsc_idx, rsc_item in enumerate(gic_part.get('roadSignCodes') or []):
            code = rsc_item.get('code')
            if code and code[0] != 'iso14823':
                non_iso.append(f'GicPart {gic_idx+1} RSCode {rsc_idx+1}: {code[0]}')
    if giv_parts and not non_iso:
        R(_pass(rid, 'REQ', path,
                'All RSCodes use iso14823 choice – machine-readable encoding used'))
    elif non_iso:
        R(_fail(rid, 'REQ', path,
                'Non-iso14823 RSCode choice(s) found: ' + '; '.join(non_iso) +
                ' – information shall be machine-readable via ISO 14823'))
    else:
        R(_na(rid, 'REQ', path, 'No GIV/RSCodes present'))

    # SUD_IVS_Req_0020: self-contained (same as MP_Req_0092 – already checked)
    R(_pass('SUD_IVS_Req_0020 (1)', 'REQ',
            'IVIM self-contained',
            'Covered by MP_Req_0092 (1) above'))

    # SUD_IVS_Req_0021: one GicPart per sign (same as MP_Req_0114 – already checked)
    R(_pass('SUD_IVS_Req_0021 (1)', 'REQ',
            'one GicPart per sign',
            'Covered by MP_Req_0114 (1) above'))

    # SUD_IVS_Req_0022: extraText NULL char (same as MP_Req_0142)
    R(_pass('SUD_IVS_Req_0022 (1)', 'REQ',
            'extraText null char',
            'Covered by MP_Req_0142 (1) above'))

    # SUD_IVS_Req_0023: temporal restrictions via ISO14823Attributes not validFrom/validTo
    rid  = 'SUD_IVS_Req_0023 (1)'; path = 'optional.giv.roadSignCodes.attributes'
    R(_skip(rid, 'REQ', path,
            'Out-of-scope: determining whether ISO14823Attributes (DTM/EDT) are used '
            'where temporal restrictions exist requires knowledge of the physical sign '
            'and its validity period – not determinable from message alone'))

    # SUD_IVS_Req_0024: IVIM corresponds to legal statement
    R(_skip('SUD_IVS_Req_0024 (1)', 'REQ',
            'optional.giv.roadSignCodes',
            'Out-of-scope: verifying correctness vs. physical sign requires '
            'real-world observation'))

    # SUD_IVS_Req_0027: RCC provided (same as MP_Req_0105 – already checked)
    R(_pass('SUD_IVS_Req_0027 (1)', 'REQ',
            'RCC present',
            'Covered by MP_Req_0105 (1) above'))

    return report


# ─── Report formatting ────────────────────────────────────────────────────────

RESULT_ICON = {'PASS': 'PASS', 'FAIL': 'FAIL', 'WARN': 'WARN',
               'N/A': 'N/A ', 'SKIP': 'SKIP'}
COLUMN_WIDTH = 22   # req_id column
TYPE_WIDTH   = 3    # REQ/REC/...

def format_report(reports: list, source_files: list) -> str:
    from collections import defaultdict

    lines = []
    w = 88

    def rule(c='─'): return c * w

    # ── Pre-pass: compute totals and key-findings aggregation ─────────────────
    total_counts = {'PASS': 0, 'FAIL': 0, 'WARN': 0, 'N/A': 0, 'SKIP': 0}

    # For key findings: per req_id track IVIMs with FAIL / WARN
    # Structure: {req_id: {'result': str, 'req_type': str, 'de_path': str,
    #                      'ivim_ids': set()}}
    finding_fail: dict = {}   # req_id → info dict
    finding_warn: dict = {}

    for rep in reports:
        counts = rep.summary()
        for k, v in counts.items():
            total_counts[k] += v

        seen_fail_ids: set = set()
        seen_warn_ids: set = set()
        for chk in rep.checks:
            if chk.result == 'FAIL' and chk.req_id not in seen_fail_ids:
                seen_fail_ids.add(chk.req_id)
                if chk.req_id not in finding_fail:
                    finding_fail[chk.req_id] = {
                        'req_type': chk.req_type,
                        'de_path':  chk.de_path,
                        'ivim_ids': set(),
                    }
                finding_fail[chk.req_id]['ivim_ids'].add(rep.ivi_id)
            if chk.result == 'WARN' and chk.req_id not in seen_warn_ids:
                seen_warn_ids.add(chk.req_id)
                if chk.req_id not in finding_warn:
                    finding_warn[chk.req_id] = {
                        'req_type': chk.req_type,
                        'de_path':  chk.de_path,
                        'ivim_ids': set(),
                    }
                finding_warn[chk.req_id]['ivim_ids'].add(rep.ivi_id)

    n_ivim = len(reports)

    # Short descriptions for well-known requirement IDs
    REQ_DESC = {
        'MP_Req_0078 (1)': 'timestamp absent',
        'MP_Req_0082 (1)': 'validTo − timestamp < 1 hour minimum',
        'MP_Req_0086 (1)': 'iviStatus out of range {0,1,2,3}',
        'MP_Req_0637 (1)': 'no GLC container present',
        'MP_Req_0092 (1)': 'referenced zone ID not defined in GLC',
        'MP_Req_0094 (1)': 'zoneId=32 used as active zone',
        'MP_Req_0097 (2)': 'zone uses segment-carriagewayOrLane (old format)',
        'MP_Req_0099 (1)': 'deltaPositions list empty',
        'MP_Rec_0098 (1)': 'first deltaPosition is (0,0) — refPos duplicated as zone start',
        'MP_Req_0103 (1)': 'zone points sorted farthest-to-closest (should be closest-to-farthest)',
        'MP_Req_0128 (1)': 'segmentWidthLeft absent for segment-setOfLanes zone',
        'MP_Req_0105 (1)': 'no RCC container present',
        'MP_Req_0108 (1)': 'duplicate laneNumbers in RCC',
        'MP_Req_0109 (1)': 'lane direction ≠ sameDirection(0)',
        'MP_Req_0111 (1)': 'laneType not in C-Roads valid set',
        'MP_Req_0113 (1)': 'no GeneralIviContainer (giv) present',
        'MP_Req_0121 (1)': 'no relevanceZoneIds – GicPart has no dedicated relevance zone',
        'MP_Req_0114 (1)': 'RSCode count exceeds 4 (1 main + 3 subsigns)',
        'MP_Req_0123 (1)': 'GIV direction ≠ sameDirection(0)',
        'MP_Req_0138 (1)': 'RSCode.code choice ≠ iso14823',
        'MP_Req_0131 (1)': 'iviType does not match ISO14823 service category',
        'MP_Req_0116 (1)': 'detection zone first point > 1m from relevance/detection zone',
        'MP_Req_0117 (1)': 'total detection zone length < 795m (FAIL) or 795–799m (WARN)',
        'MP_Rec_0118 (1)': 'total detection zone length > 2000m',
        'MP_Req_0119 (1)': 'detection zone shorter than awareness zone',
        'MP_Req_0125 (1)': 'awareness zone longer than detection zone',
        'MP_Req_0135 (1)': 'duplicate RSCode across GicParts',
        'MP_Req_0142 (1)': 'extraText missing null character for empty slot',
        'MP_Req_0144 (1)': 'extraText layoutComponentId ≠ 1',
        'SUD_IVS_Req_0005 (1)': 'RSCode not using iso14823 (not machine-readable)',
    }

    # ── Report header ─────────────────────────────────────────────────────────
    lines.append('=' * w)
    lines.append('  C-ROADS IVS-TS IVIM COMPLIANCE REPORT')
    lines.append(f'  Generated : {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}')
    lines.append(f'  Source    : {", ".join(source_files)}')
    lines.append(f'  IVIMs     : {n_ivim} unique iviIdentificationNumber(s)')
    lines.append('  Profile   : C-Roads Release 3.2.0')
    lines.append('  Chapters  : MP 4.2.2.2 (IVIM general elements), '
                 'MP 4.2.2.3 (IVS), MP 4.2.2.8 (cancellation), SUD 2.2.1.1')
    lines.append('=' * w)
    lines.append('')
    lines.append('  Legend:')
    lines.append('    PASS – requirement / recommendation satisfied')
    lines.append('    FAIL – requirement violated  (REQ = requirement, REC = recommendation)')
    lines.append('    WARN – recommendation not followed')
    lines.append('    N/A  – not applicable to this specific IVIM')
    lines.append('    SKIP – out of scope for automated ASN.1-level checking')
    lines.append('')

    # ── Overall totals ────────────────────────────────────────────────────────
    lines.append(rule('═'))
    lines.append('  OVERALL TOTALS ACROSS ALL IVIMs')
    lines.append(rule('─'))
    lines.append(f'  {total_counts["PASS"]:5d}  PASS')
    lines.append(f'  {total_counts["FAIL"]:5d}  FAIL')
    lines.append(f'  {total_counts["WARN"]:5d}  WARN')
    lines.append(f'  {total_counts["N/A"]:5d}  N/A')
    lines.append(f'  {total_counts["SKIP"]:5d}  SKIP')
    lines.append(rule('─'))
    lines.append('')

    # ── Key findings ──────────────────────────────────────────────────────────
    lines.append('  KEY FINDINGS  (requirements / recommendations with FAIL or WARN)')
    lines.append(f'  {rule("-")}')

    # Sort FAILs by affected IVIM count (descending), then req_id
    sorted_fails = sorted(finding_fail.items(),
                          key=lambda x: (-len(x[1]['ivim_ids']), x[0]))
    sorted_warns = sorted(finding_warn.items(),
                          key=lambda x: (-len(x[1]['ivim_ids']), x[0]))

    def _finding_lines(result_tag, sorted_findings):
        """Format one block of FAIL or WARN key-finding lines."""
        out = []
        for req_id, info in sorted_findings:
            n_affected = len(info['ivim_ids'])
            rt     = f'[{info["req_type"]}]'
            desc   = REQ_DESC.get(req_id, info['de_path'])
            prefix = (f'    {result_tag}  {n_affected:3d}/{n_ivim} IVIMs  '
                      f'{req_id:<22} {rt:<5}  ')
            indent = ' ' * len(prefix)
            wrapped = textwrap.fill(
                prefix + desc,
                width=w,
                subsequent_indent=indent,
                break_long_words=True,
                break_on_hyphens=False,
            )
            out.append(wrapped)
        return out

    if sorted_fails:
        lines.append('  FAIL findings:')
        lines.extend(_finding_lines('FAIL', sorted_fails))
    else:
        lines.append('  No FAIL findings.')

    if sorted_warns:
        lines.append('')
        lines.append('  WARN findings:')
        lines.extend(_finding_lines('WARN', sorted_warns))
    else:
        lines.append('')
        lines.append('  No WARN findings.')

    lines.append(f'  {rule("-")}')
    lines.append(rule('═'))
    lines.append('')

    # ── Per-IVIM sections ─────────────────────────────────────────────────────
    sections = [
        ('IviManagementContainer',       lambda c: c.de_path.startswith('mandatory')),
        ('GeographicLocationContainer',  lambda c: c.de_path.startswith('optional.glc')),
        ('RoadConfigurationContainer',   lambda c: c.de_path.startswith('optional.rcc')),
        ('GeneralIviContainer (IVS)',     lambda c: c.de_path.startswith('optional.giv')),
        ('SUD 2.2.1.1 Requirements',     lambda c: c.req_id.startswith('SUD')),
    ]

    def get_section(chk):
        for name, pred in sections:
            if pred(chk):
                return name
        return 'Other'

    status_names = {0: 'new', 1: 'update', 2: 'cancellation', 3: 'negation'}

    for rep in sorted(reports, key=lambda r: r.ivi_id):
        s_label = status_names.get(rep.status, str(rep.status))

        cancel_note = ('  →  MP 4.2.2.8 (cancellation profile)'
                       if rep.status == 2 else '')
        lines.append(rule('═'))
        lines.append(f'  IVIM  ivi_id={rep.ivi_id}  |  '
                     f'stationId={rep.station_id}  |  '
                     f'iviStatus={rep.status} ({s_label}){cancel_note}')
        lines.append(rule('═'))

        by_section = defaultdict(list)
        for chk in rep.checks:
            by_section[get_section(chk)].append(chk)

        for sec_name, _ in sections:
            sec_checks = by_section.get(sec_name, [])
            if not sec_checks:
                continue
            lines.append('')
            lines.append(f'  [{sec_name}]')
            lines.append(f'  {rule("-")}')
            for chk in sec_checks:
                icon = RESULT_ICON.get(chk.result, chk.result)
                rid  = chk.req_id.ljust(COLUMN_WIDTH)
                rt   = f'[{chk.req_type}]'.ljust(TYPE_WIDTH + 2)
                lines.append(f'  {icon}  {rid} {rt}  {chk.de_path}')
                detail_width = w - 12
                detail = chk.details
                while detail:
                    lines.append(f'{"":12}{detail[:detail_width]}')
                    detail = detail[detail_width:]
            lines.append(f'  {rule("-")}')

        counts = rep.summary()
        lines.append('')
        lines.append(f'  Summary: '
                     f'{counts["PASS"]} PASS  '
                     f'{counts["FAIL"]} FAIL  '
                     f'{counts["WARN"]} WARN  '
                     f'{counts["N/A"]} N/A  '
                     f'{counts["SKIP"]} SKIP')
        lines.append('')

    return '\n'.join(lines)


# ─── Main processing ──────────────────────────────────────────────────────────

def process(pcap_files: list, asn_dir: Path, output: str) -> None:
    print(f'Compiling ASN.1 definitions from: {asn_dir}')
    db = compile_asn(asn_dir)
    print('ASN.1 compilation successful.')

    ivim_cache: dict[int, dict] = {}   # ivi_id → decoded IVIM (first occurrence)

    for pcap_file in pcap_files:
        print(f'Processing: {pcap_file}')
        n_pkt = n_ivim = n_new = 0
        for pkt in iter_its_packets(pcap_file):
            n_pkt += 1
            ivim = extract_ivim(pkt, db)
            if ivim is None:
                continue
            n_ivim += 1
            ivi_id = ivim['ivi']['mandatory']['iviIdentificationNumber']
            if ivi_id not in ivim_cache:
                ivim_cache[ivi_id] = ivim
                n_new += 1
        print(f'  ITS-G5 packets: {n_pkt}  |  IVIM decoded: {n_ivim}  '
              f'|  New unique IVI IDs: {n_new}')

    print(f'\nRunning compliance checks on {len(ivim_cache)} unique IVIM(s)...')
    reports = [check_ivim(ivim) for ivim in ivim_cache.values()]
    reports.sort(key=lambda r: r.ivi_id)

    text = format_report(reports, [Path(p).name for p in pcap_files])

    out = output if output.endswith('.txt') else output + '.txt'
    with open(out, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f'Report written to: {out}')

    # Print brief summary to console
    total_fail = sum(sum(1 for c in r.checks if c.result == 'FAIL') for r in reports)
    total_warn = sum(sum(1 for c in r.checks if c.result == 'WARN') for r in reports)
    print(f'  Across all IVIMs: {total_fail} FAIL, {total_warn} WARN findings')


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Check IVIM messages against the C-Roads IVS-TS use case profile '
                    '(Release 3.2.0).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s)')
    parser.add_argument('-o', '--output', default='ivs_ts_croads_report',
                        metavar='FILE',
                        help='Output report file (default: ivs_ts_croads_report.txt)')
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
