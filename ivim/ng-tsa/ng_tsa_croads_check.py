#!/usr/bin/env python3
"""
NG-TSA (Navigation Guidance – Toll Station Approaching) C-ROADS Compliance Checker
C-Roads Release 3.2.0

Checks IVIM messages extracted from PCAP files against the C-ROADS NG-TSA
use case profile. NG-TSA reuses every IVS-TS requirement (MP chapters
4.2.2.2, 4.2.2.3, 4.2.2.8, and SUD IVS chapter 2.2.1.1 — see
../ivs-ts/ivs_ts_croads_check.py) and adds the NG-TSA-specific requirements
from:
  - C_Roads_WG2_TF2_Service_and_Use_Case_Definitions_07_NG_3.2.0
      chapter 7.2.1.1  – NG-TSA message profile requirements
        SUD_NG_Req_0001 .. SUD_NG_Req_0005, SUD_NG_Rec_0006

All other chapters of that document (7.2.1.2 communication technology,
7.2.1.3 IP based, 7.2.1.4 test/validation, and other NG use cases such as
Smart Routing / Route Advice) are out of scope for this checker.

For each unique IVIM (identified by iviIdentificationNumber) the script reports
for every requirement whether it is:
  PASS  – requirement satisfied
  FAIL  – requirement violated
  WARN  – recommendation not followed (should/should not)
  N/A   – not applicable to this specific IVIM
  SKIP  – out of scope for automated ASN.1-level checking

Reuses PCAP parsing, ASN.1 compilation, and all IVS-TS checks from
../ivs-ts/ivs_ts_croads_check.py (imported as a module).

Usage:
    python ng_tsa_croads_check.py SingleIVIM.pcap
    python ng_tsa_croads_check.py AllCaptures.pcap -o report.txt
    python ng_tsa_croads_check.py *.pcap -o combined_report.txt
"""

import argparse
import sys
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ─── Import the IVS-TS checker as a library module (sibling folder) ──────────

_IVS_TS_DIR = Path(__file__).parent.parent / 'ivs-ts'
if str(_IVS_TS_DIR) not in sys.path:
    sys.path.insert(0, str(_IVS_TS_DIR))
import ivs_ts_croads_check as ivs_ts  # noqa: E402

_pass = ivs_ts._pass
_fail = ivs_ts._fail
_warn = ivs_ts._warn
_na   = ivs_ts._na
_skip = ivs_ts._skip
CheckResult      = ivs_ts.CheckResult
IvimReport       = ivs_ts.IvimReport
compile_asn      = ivs_ts.compile_asn
iter_its_packets = ivs_ts.iter_its_packets
extract_ivim     = ivs_ts.extract_ivim
zone_type_name   = ivs_ts.zone_type_name

DEFAULT_ASN_DIR = Path(__file__).parent.parent / 'ASN'

# ─── NG-TSA sign codes (ISO 14823 pictogramCategoryCode: nature, serialNumber) ─
# per SUD chapter 7.2.1.1

TOLL_GATE_MAIN_SIGN = (8, 33)  # "Automatic toll gate" pictogram (mandatory main sign)

PAYMENT_SUB_SIGNS = {
    (6, 81): 'toll booth with human operator',
    (6, 82): 'credit card',
    (6, 83): 'coins',
    (6, 84): 'coins and banknotes',
    (6, 85): 'electronic toll subscription',
}

LANE_AVAILABILITY_MAIN_SIGNS = {
    (6, 59): 'red cross (lane closed)',
    (6, 60): 'green arrow (lane open)',
    (9, 99): 'danger identified',
    (9, 98): 'reversible lane closed',
    (4, 12): 'reversible lane closed',
}

TRAFFIC_RESTRICTION_SUB_SIGNS = {
    (5, 57): 'maximum speed limit',
    (5, 11): 'height restriction',
    (1, 34): 'HOV reserved lane',
}


def _sign_nature_serial(rsc_item: dict):
    """Return (nature, serialNumber) tuple for an ISO14823 RSCode, or None."""
    code = rsc_item.get('code')
    if not code or code[0] != 'iso14823':
        return None
    pc  = code[1].get('pictogramCode', {})
    pcc = pc.get('pictogramCategoryCode')
    if not pcc:
        return None
    return (pcc.get('nature'), pcc.get('serialNumber'))


# ─── NG-TSA-specific requirement checks (SUD chapter 7.2.1.1) ────────────────

def check_ng_tsa_specific(ivim: dict, report: IvimReport) -> None:
    """Append NG-TSA-specific checks to an IvimReport already produced by
    ivs_ts_croads_check.check_ivim() (i.e. all IVS-TS checks are already
    present in report.checks).
    """
    R = report.checks.append
    optional = ivim['ivi'].get('optional') or []

    glc_list, giv_parts, rcc_parts = [], [], []
    for ctype, cdata in optional:
        if ctype == 'glc':
            glc_list.append(cdata)
        elif ctype == 'giv':
            giv_parts = list(cdata)
        elif ctype == 'rcc':
            rcc_parts = list(cdata)

    # zoneId -> zone type name, across all GLC parts
    zone_type_by_id: dict = {}
    zone_part_by_id: dict = {}
    for glc in glc_list:
        for part in glc.get('parts', []):
            zone_type_by_id[part['zoneId']] = zone_type_name(part)
            zone_part_by_id[part['zoneId']] = part

    # zoneIds covered by an RccPart's relevanceZoneIds (RCC-covered)
    rcc_relevance_zone_ids: set = set()
    for rp in rcc_parts:
        rcc_relevance_zone_ids.update(rp.get('relevanceZoneIds') or [])

    # ── SUD_NG_Req_0001: meta-requirement ───────────────────────────────────
    R(_pass('SUD_NG_Req_0001 (1)', 'REQ', 'IVI message for NG-TSA',
            'Meta-requirement: MP 4.2.2.2 requirements checked via shared '
            'IVS-TS checks above. MP 4.2.2.1 (general profile requirements) '
            'is not itemized by this checker.'))

    # ── SUD_NG_Req_0002: relevanceZone shall be segment-setOfLanes ─────────
    rid  = 'SUD_NG_Req_0002 (1)'
    path = 'optional.giv.relevanceZoneIds'
    rel_ids = sorted({zid for gp in giv_parts
                       for zid in (gp.get('relevanceZoneIds') or [])})
    if not rel_ids:
        R(_fail(rid, 'REQ', path,
                'No relevanceZoneIds present in GIV – mandatory for NG-TSA '
                '(relevance zone leading to the toll island is required)'))
    else:
        bad_type = [(zid, zone_type_by_id.get(zid, 'undefined'))
                    for zid in rel_ids
                    if zone_type_by_id.get(zid) != 'segment-setOfLanes']
        if bad_type:
            detail = ', '.join(f'zone {zid} ({ztype})' for zid, ztype in bad_type)
            R(_fail(rid, 'REQ', path,
                    f'Relevance zone(s) not using segment-setOfLanes: {detail} '
                    '– NG-TSA requires the relevance zone to be a '
                    'segment-setOfLanes leading to the toll island'))
        else:
            R(_pass(rid, 'REQ', path,
                    f'All relevance zone(s) {rel_ids} use segment-setOfLanes'))

    # ── SUD_NG_Req_0003: payment-option signage ─────────────────────────────
    rid  = 'SUD_NG_Req_0003 (1)'
    path = 'optional.giv (payment roadSignCodes)'
    payment_gic_parts = []
    for gic_idx, gp in enumerate(giv_parts):
        rsc = list(gp.get('roadSignCodes') or [])
        if not rsc:
            continue
        if _sign_nature_serial(rsc[0]) == TOLL_GATE_MAIN_SIGN:
            payment_gic_parts.append((gic_idx, rsc))

    if not payment_gic_parts:
        R(_fail(rid, 'REQ', path,
                'No GicPart with main sign 8-33 ("Automatic toll gate") found '
                '– payment option signage is mandatory for NG-TSA'))
    else:
        bad = []
        for gic_idx, rsc in payment_gic_parts:
            for sub_idx, rsc_item in enumerate(rsc[1:], start=1):
                sig = _sign_nature_serial(rsc_item)
                if sig not in PAYMENT_SUB_SIGNS:
                    bad.append(f'GicPart {gic_idx + 1} sub-sign {sub_idx + 1}: '
                              f'{sig} not in allowed payment-method set')
        if bad:
            R(_fail(rid, 'REQ', path,
                    f'{len(payment_gic_parts)} payment GicPart(s) found (main '
                    f'sign 8-33), but: {"; ".join(bad)}'))
        else:
            R(_pass(rid, 'REQ', path,
                    f'{len(payment_gic_parts)} GicPart(s) with main sign 8-33 '
                    'found, all secondary signs are valid payment-method codes'))

    # ── SUD_NG_Req_0004: lane availability / traffic restriction signage ────
    # (Requirement text uses "should" — treated as a recommendation.)
    rid  = 'SUD_NG_Req_0004 (1)'
    path = 'optional.giv (lane availability roadSignCodes)'
    avail_gic_parts = []
    for gic_idx, gp in enumerate(giv_parts):
        rsc = list(gp.get('roadSignCodes') or [])
        if not rsc:
            continue
        main = _sign_nature_serial(rsc[0])
        if main in LANE_AVAILABILITY_MAIN_SIGNS:
            avail_gic_parts.append((gic_idx, rsc))

    if not avail_gic_parts:
        R(_warn(rid, 'REC', path,
                'No GicPart with a lane-availability main sign '
                f'{sorted(LANE_AVAILABILITY_MAIN_SIGNS)} found – lane '
                'availability / traffic restriction signage should be '
                'provided for NG-TSA (recommendation, not mandatory)'))
    else:
        bad = []
        for gic_idx, rsc in avail_gic_parts:
            for sub_idx, rsc_item in enumerate(rsc[1:], start=1):
                sig = _sign_nature_serial(rsc_item)
                if sig not in TRAFFIC_RESTRICTION_SUB_SIGNS:
                    bad.append(f'GicPart {gic_idx + 1} sub-sign {sub_idx + 1}: '
                              f'{sig} not in allowed traffic-restriction set')
        if bad:
            R(_warn(rid, 'REC', path,
                    f'{len(avail_gic_parts)} lane-availability GicPart(s) '
                    f'found, but: {"; ".join(bad)}'))
        else:
            R(_pass(rid, 'REC', path,
                    f'{len(avail_gic_parts)} GicPart(s) with a lane-availability '
                    'main sign found, all secondary signs are valid '
                    'traffic-restriction codes'))

    # ── SUD_NG_Req_0005 / SUD_NG_Rec_0006: segmentWidthLeft on relevance zone ─
    rid5  = 'SUD_NG_Req_0005 (1)'
    rid6  = 'SUD_NG_Rec_0006 (1)'
    path56 = 'optional.glc.parts.zone.segment-setOfLanes.segmentWidthLeft'
    if not rel_ids:
        R(_na(rid5, 'REQ', path56, 'No relevanceZoneIds present – N/A'))
        R(_na(rid6, 'REC', path56, 'No relevanceZoneIds present – N/A'))
    else:
        for zid in rel_ids:
            ztype = zone_type_by_id.get(zid)
            if ztype != 'segment-setOfLanes':
                R(_na(rid5, 'REQ', path56,
                      f'Zone {zid}: not segment-setOfLanes ({ztype}) – '
                      'segmentWidthLeft check not applicable (see Req_0002)'))
                R(_na(rid6, 'REC', path56,
                      f'Zone {zid}: not segment-setOfLanes ({ztype}) – N/A'))
                continue

            part = zone_part_by_id.get(zid)
            zone_data = part.get('zone', (None, {}))[1] if part else {}
            sw_left = zone_data.get('segmentWidthLeft')
            rcc_covers = zid in rcc_relevance_zone_ids

            if not rcc_covers:
                if sw_left is not None:
                    R(_pass(rid5, 'REQ', path56,
                            f'Zone {zid}: no RccPart covers this relevance zone; '
                            f'segmentWidthLeft = {sw_left} (present, as required)'))
                else:
                    R(_fail(rid5, 'REQ', path56,
                            f'Zone {zid}: no RccPart covers this relevance zone '
                            'and segmentWidthLeft is absent – mandatory in this '
                            'case (tolling islands can have a large lateral extent)'))
                R(_na(rid6, 'REC', path56,
                      f'Zone {zid}: covered by Req_0005 (no RccPart covers zone)'))
            else:
                R(_na(rid5, 'REQ', path56,
                      f'Zone {zid}: covered by an RccPart (laneWidth available) – '
                      'segmentWidthLeft not mandatory (see Rec_0006)'))
                if sw_left is not None:
                    R(_pass(rid6, 'REC', path56,
                            f'Zone {zid}: RccPart covers this zone; '
                            f'segmentWidthLeft = {sw_left} also provided'))
                else:
                    R(_warn(rid6, 'REC', path56,
                            f'Zone {zid}: RccPart covers this zone (laneWidth '
                            'available), segmentWidthLeft should additionally be '
                            'provided but is absent'))


# ─── Combined IVS-TS + NG-TSA check ────────────────────────────────────────

_NG_TSA_CANCELLATION_NA = [
    ('SUD_NG_Req_0001 (1)', 'REQ', 'IVI message for NG-TSA'),
    ('SUD_NG_Req_0002 (1)', 'REQ', 'optional.giv.relevanceZoneIds'),
    ('SUD_NG_Req_0003 (1)', 'REQ', 'optional.giv (payment roadSignCodes)'),
    ('SUD_NG_Req_0004 (1)', 'REC', 'optional.giv (lane availability roadSignCodes)'),
    ('SUD_NG_Req_0005 (1)', 'REQ', 'optional.glc.parts.zone.segment-setOfLanes.segmentWidthLeft'),
    ('SUD_NG_Rec_0006 (1)', 'REC', 'optional.glc.parts.zone.segment-setOfLanes.segmentWidthLeft'),
]


def check_ivim(ivim: dict) -> IvimReport:
    """Run all IVS-TS checks plus NG-TSA-specific checks (SUD chapter 7.2.1.1)."""
    report = ivs_ts.check_ivim(ivim)  # runs full IVS-TS check set (incl. cancellation profile)

    if report.status == 2:  # cancellation IVIM: NG-TSA optional-container checks are N/A too
        for rid, rt, path in _NG_TSA_CANCELLATION_NA:
            report.checks.append(_na(rid, rt, path,
                'N/A for cancellation IVIM – optional containers not required '
                '(MP 4.2.2.8)'))
        return report

    check_ng_tsa_specific(ivim, report)
    return report


# ─── Report formatting ────────────────────────────────────────────────────────

RESULT_ICON = {'PASS': 'PASS', 'FAIL': 'FAIL', 'WARN': 'WARN',
               'N/A': 'N/A ', 'SKIP': 'SKIP'}
COLUMN_WIDTH = 22
TYPE_WIDTH   = 3


def format_report(reports: list, source_files: list) -> str:
    lines = []
    w = 88

    def rule(c='─'): return c * w

    # ── Pre-pass: totals and key-findings aggregation ──────────────────────
    total_counts = {'PASS': 0, 'FAIL': 0, 'WARN': 0, 'N/A': 0, 'SKIP': 0}
    finding_fail: dict = {}
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
                finding_fail.setdefault(chk.req_id, {
                    'req_type': chk.req_type, 'de_path': chk.de_path, 'ivim_ids': set(),
                })['ivim_ids'].add(rep.ivi_id)
            if chk.result == 'WARN' and chk.req_id not in seen_warn_ids:
                seen_warn_ids.add(chk.req_id)
                finding_warn.setdefault(chk.req_id, {
                    'req_type': chk.req_type, 'de_path': chk.de_path, 'ivim_ids': set(),
                })['ivim_ids'].add(rep.ivi_id)

    n_ivim = len(reports)

    # Short descriptions for well-known requirement IDs (IVS-TS base + NG-TSA)
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
        'SUD_NG_Req_0002 (1)': 'relevance zone not segment-setOfLanes',
        'SUD_NG_Req_0003 (1)': 'payment signage (8-33 + sub-signs) missing/invalid',
        'SUD_NG_Req_0004 (1)': 'lane availability signage missing/invalid',
        'SUD_NG_Req_0005 (1)': 'segmentWidthLeft absent on uncovered relevance zone',
        'SUD_NG_Rec_0006 (1)': 'segmentWidthLeft absent though RCC covers relevance zone',
    }

    # ── Report header ───────────────────────────────────────────────────────
    lines.append('=' * w)
    lines.append('  C-ROADS NG-TSA IVIM COMPLIANCE REPORT')
    lines.append(f'  Generated : {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}')
    lines.append(f'  Source    : {", ".join(source_files)}')
    lines.append(f'  IVIMs     : {n_ivim} unique iviIdentificationNumber(s)')
    lines.append('  Profile   : C-Roads Release 3.2.0')
    lines.append('  Chapters  : MP 4.2.2.2 (IVIM general elements), '
                 'MP 4.2.2.3 (IVS), MP 4.2.2.8 (cancellation), '
                 'SUD 2.2.1.1 (IVS-TS base), SUD 7.2.1.1 (NG-TSA)')
    lines.append('=' * w)
    lines.append('')
    lines.append('  Legend:')
    lines.append('    PASS – requirement / recommendation satisfied')
    lines.append('    FAIL – requirement violated  (REQ = requirement, REC = recommendation)')
    lines.append('    WARN – recommendation not followed')
    lines.append('    N/A  – not applicable to this specific IVIM')
    lines.append('    SKIP – out of scope for automated ASN.1-level checking')
    lines.append('')
    lines.append('  Note: NG-TSA reuses every IVS-TS requirement (MP 4.2.2.2/4.2.2.3/4.2.2.8,')
    lines.append('  SUD 2.2.1.1) and adds the NG-TSA-specific requirements from SUD chapter')
    lines.append('  7.2.1.1 (SUD_NG_Req_0001..0005, SUD_NG_Rec_0006).')
    lines.append('')

    # ── Overall totals ──────────────────────────────────────────────────────
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

    # ── Key findings ─────────────────────────────────────────────────────────
    lines.append('  KEY FINDINGS  (requirements / recommendations with FAIL or WARN)')
    lines.append(f'  {rule("-")}')

    sorted_fails = sorted(finding_fail.items(),
                          key=lambda x: (-len(x[1]['ivim_ids']), x[0]))
    sorted_warns = sorted(finding_warn.items(),
                          key=lambda x: (-len(x[1]['ivim_ids']), x[0]))

    def _finding_lines(result_tag, sorted_findings):
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

    # ── Per-IVIM sections ────────────────────────────────────────────────────
    def get_section(chk):
        if chk.req_id.startswith('SUD_NG'):
            return 'NG-TSA (SUD 7.2.1.1)'
        if chk.req_id.startswith('SUD_IVS'):
            return 'SUD 2.2.1.1 Requirements (IVS-TS base)'
        if chk.de_path.startswith('mandatory'):
            return 'IviManagementContainer'
        if chk.de_path.startswith('optional.glc'):
            return 'GeographicLocationContainer'
        if chk.de_path.startswith('optional.rcc'):
            return 'RoadConfigurationContainer'
        if chk.de_path.startswith('optional.giv'):
            return 'GeneralIviContainer (IVS)'
        return 'Other'

    section_order = [
        'IviManagementContainer',
        'GeographicLocationContainer',
        'RoadConfigurationContainer',
        'GeneralIviContainer (IVS)',
        'SUD 2.2.1.1 Requirements (IVS-TS base)',
        'NG-TSA (SUD 7.2.1.1)',
    ]

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

        for sec_name in section_order:
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

    ivim_cache: dict = {}

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

    total_fail = sum(sum(1 for c in r.checks if c.result == 'FAIL') for r in reports)
    total_warn = sum(sum(1 for c in r.checks if c.result == 'WARN') for r in reports)
    print(f'  Across all IVIMs: {total_fail} FAIL, {total_warn} WARN findings')


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Check IVIM messages against the C-Roads NG-TSA use case profile '
                    '(Release 3.2.0). Includes all IVS-TS checks plus SUD chapter 7.2.1.1.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s)')
    parser.add_argument('-o', '--output', default='ng_tsa_croads_report',
                        metavar='FILE',
                        help='Output report file (default: ng_tsa_croads_report.txt)')
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
