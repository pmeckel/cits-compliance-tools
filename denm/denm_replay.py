#!/usr/bin/env python3
"""
DENM Replay

Reads one or more PCAP files, decodes all DENMs and CAMs and writes a
self-contained HTML page (Leaflet + Esri World Imagery satellite map, online)
that replays all DENMs of a selected originatingStationId in real time on the
capture (receiver) clock, together with the matching CAM station.

Selection:
  - stationType filter: checkboxes for all stationTypes found in the capture;
    by default all are selected except 15 (roadSideUnit)
  - one entry per originatingStationId; every DENM with a new detectionTime
    (first reception, any sequenceNumber) is one step of the replay
  - static actionIds (eventPosition, traces and eventZone the same in all its
    DENMs, e.g. roadside units): every sequenceNumber is a message of its own,
    selected from a list; the selected one is shown with its most recent DENM
    (eventPosition, all traces and eventZone) for the whole replay

Layers (each with colour, points or line only, time labels, full preview and a
minimal view with only the last n points; shown individually or together):
  - DENM: eventPositions of all DENMs up to the replay time (labels: time to the
    previous DENM, "seq n" at a new sequenceNumber); options eventZone of the
    latest DENM, eventPositionHeading arrows and smoothing (as for the CAM, on by default)
  - DENM traces: first trace (location.detectionZonesToEventPosition) of the latest
    DENM, only the part from the replay start on (labels: pathDeltaTime)
  - CAM: positions of the matched CAM station; options heading arrows and
    smoothing (Kalman filter + RTS smoother on position, time and, weakly,
    speed/heading, cubic interpolation between CAMs; on by default)
  - CAM pathHistory: pathHistory of the latest CAM with low frequency container,
    only the part from the replay start on (labels: pathDeltaTime); a warning
    banner "CAM pathHistory inconsistent / broken" is shown while the received
    pathHistory has a point with pathDeltaTime 0 or a step of more than 50 m at
    more than 250 km/h
  pathDeltaTime (10 ms) is the time to the previous point (to the eventPosition /
  referencePosition for the first one), so point i was passed at the reception
  time minus the sum of pathDeltaTime 1..i.

CAM matching (ASN.1 in ../cam/ASN, disable with --no-cam): every CAM station with
CAMs in the time window of the DENMs is scored (0..100) and listed:
      40  track  - median distance between the eventPositions and the CAM
                   position at the same time (<= 5 m: full, >= 50 m: none)
      25  timing - share of the DENM time span covered by CAMs
      20  cause  - incidentIndication of the CAM special vehicle container:
                   same cause and sub cause / same cause / container fits
      15  station - same stationId (or at least the same stationType)
The best candidate is selected automatically if it reaches 50/100.

Reuses PCAP parsing, ASN.1 compilation and DENM extraction from denm_count.py,
the event type text from denm_common.py and the delta position helper from
denm_to_kml.py.

Usage:
    python denm_replay.py TrafficManager.pcap
    python denm_replay.py TrafficManager.pcap --station 10101004
    python denm_replay.py ../test-data/DENM*.pcap -o replay.html
    python denm_replay.py capture.pcap --no-open
"""

import argparse
import json
import math
import re
import sys
import webbrowser
from pathlib import Path

import asn1tools

from denm_common import CDD_FILE, denm_event_type, event_type_info, load_cause_names
from denm_count import ASN_FILES, DEFAULT_ASN_DIR, compile_asn, expand_pcaps, extract_denm
from denm_to_kml import COORD_SCALE, cumulative_points
from ivim_zone_count import iter_its_packets_ts

RSU_STATION_TYPE = 15   # roadSideUnit, deselected by default in the stationType filter
WGS84_ANGLE_UNAVAILABLE = 3601   # Wgs84AngleValue, unit 0.1 degree

# CAM decoding (ETSI EN 302 637-2, CAM release 2, ASN.1 in ../cam/ASN)
DEFAULT_CAM_ASN_DIR = Path(__file__).parent.parent / 'cam' / 'ASN'
CAM_ASN_FILES = ['ETSI-ITS-CDD.asn', 'CAM-PDU-Descriptions.asn']
BTP_CAM_PORT = b'\x07\xd1'   # BTP destination port 2001 = CAM
CAM_MESSAGE_ID = 2
SPEED_UNAVAILABLE = 16383     # SpeedValue, unit 0.01 m/s
HEADING_UNAVAILABLE = 3601    # HeadingValue, unit 0.1 degree

_STATION_TYPE_RE = re.compile(r'^StationType\s*::=\s*INTEGER\s*\{(.*?)\}', re.S | re.M)
_NAMED_RE = re.compile(r'([A-Za-z][\w-]*)\s*\((\d+)\)')


def load_station_type_names(asn_dir: Path) -> dict:
    """{stationType: name} from the StationType INTEGER of the CDD file."""
    text = (Path(asn_dir) / CDD_FILE).read_text(encoding='utf-8', errors='replace')
    m = _STATION_TYPE_RE.search(text)
    return {int(n): name for name, n in _NAMED_RE.findall(m.group(1))} if m else {}


# Track smoothing for CAM positions and DENM eventPositions (Kalman filter + Rauch-Tung-Striebel
# smoother, constant velocity model). The received positions jitter by about 1-1.5 m from message to
# message; the reported heading is often off (e.g. at low speed), so speed/heading only weakly
# support the positions.
CAM_MAX_GAP = 3.0             # s; the track is split (and not interpolated) at larger gaps
CAM_SMOOTH_POS_SIGMA = 1.0    # m, referencePosition
CAM_SMOOTH_VEL_SIGMA = 5.0    # m/s, velocity from speed and heading
CAM_SMOOTH_ACCEL = 2.0        # m/s^2, process noise (acceleration)
M_PER_DEG = 111320.0


def _kf_update(x, P, k, z, r):
    """Scalar Kalman update of state component k with measurement z (variance r)."""
    s_ = P[k][k] + r
    K = (P[0][k] / s_, P[1][k] / s_)
    y = z - x[k]
    x = [x[0] + K[0] * y, x[1] + K[1] * y]
    P = [[P[i][j] - K[i] * P[k][j] for j in range(2)] for i in range(2)]
    return x, P


def _rts_1d(ts, zp, zv):
    """Smoothed [position, velocity] per sample for one axis (position zp, velocity zv | None)."""
    sp2, sv2, qa2 = CAM_SMOOTH_POS_SIGMA ** 2, CAM_SMOOTH_VEL_SIGMA ** 2, CAM_SMOOTH_ACCEL ** 2
    n = len(ts)
    xf, Pf, xp, Pp = [], [], [None], [None]
    x, P = [zp[0], 0.0], [[sp2, 0.0], [0.0, 100.0]]
    if zv[0] is not None:
        x, P = _kf_update(x, P, 1, zv[0], sv2)
    xf.append(x); Pf.append(P)
    for i in range(1, n):
        dt = ts[i] - ts[i - 1]
        x0, P0 = xf[-1], Pf[-1]
        xpr = [x0[0] + dt * x0[1], x0[1]]
        b = P0[0][1] + dt * P0[1][1] + dt ** 3 / 2 * qa2
        Ppr = [[P0[0][0] + 2 * dt * P0[0][1] + dt * dt * P0[1][1] + dt ** 4 / 4 * qa2, b],
               [b, P0[1][1] + dt * dt * qa2]]
        x, P = _kf_update(xpr, Ppr, 0, zp[i], sp2)
        if zv[i] is not None:
            x, P = _kf_update(x, P, 1, zv[i], sv2)
        xp.append(xpr); Pp.append(Ppr); xf.append(x); Pf.append(P)
    xs = [None] * n
    xs[-1] = xf[-1]
    for i in range(n - 2, -1, -1):
        dt = ts[i + 1] - ts[i]
        P = Pf[i]
        PFt = [[P[0][0] + dt * P[0][1], P[0][1]], [P[1][0] + dt * P[1][1], P[1][1]]]   # P F^T
        A = Pp[i + 1]
        det = A[0][0] * A[1][1] - A[0][1] * A[1][0]
        inv = [[A[1][1] / det, -A[0][1] / det], [-A[1][0] / det, A[0][0] / det]]
        C = [[sum(PFt[r][k] * inv[k][c] for k in range(2)) for c in range(2)] for r in range(2)]
        dx = [xs[i + 1][0] - xp[i + 1][0], xs[i + 1][1] - xp[i + 1][1]]
        xs[i] = [xf[i][0] + C[0][0] * dx[0] + C[0][1] * dx[1],
                 xf[i][1] + C[1][0] * dx[0] + C[1][1] * dx[1]]
    return xs


def smooth_track(positions: list) -> None:
    """Append [smoothed lat, lon, velocity east, north (m/s)] to every (time sorted) position row
    [time s, lat, lon, speed km/h | None, heading deg | None, ...]."""
    seg = []
    for row in positions + [None]:
        if row is not None and (not seg or row[0] - seg[-1][0] <= CAM_MAX_GAP):
            seg.append(row)
            continue
        if seg:
            lat0, lon0 = seg[0][1], seg[0][2]
            ky, kx = M_PER_DEG, M_PER_DEG * math.cos(math.radians(lat0))
            ts = [r[0] for r in seg]
            ve, vn = [], []
            for r in seg:
                if r[3] is not None and r[4] is not None:
                    v, h = r[3] / 3.6, math.radians(r[4])
                    ve.append(v * math.sin(h)); vn.append(v * math.cos(h))
                else:
                    ve.append(None); vn.append(None)
            ex = _rts_1d(ts, [(r[2] - lon0) * kx for r in seg], ve)
            ny = _rts_1d(ts, [(r[1] - lat0) * ky for r in seg], vn)
            for r, (x, vx), (y, vy) in zip(seg, ex, ny):
                r.extend([round(lat0 + y / ky, 8), round(lon0 + x / kx, 8), round(vx, 2), round(vy, 2)])
        seg = [row] if row is not None else []


def compile_cam_asn(asn_dir: Path):
    files = [str(Path(asn_dir) / n) for n in CAM_ASN_FILES]
    for f in files:
        if not Path(f).exists():
            raise FileNotFoundError(f'ASN.1 file not found: {f}')
    return asn1tools.compile_files(files, codec='uper')


def extract_cam(pkt: bytes, db):
    """Return the decoded CAM of a packet or None (BTP port 2001, messageId 2)."""
    pos = 0
    while True:
        idx = pkt.find(BTP_CAM_PORT, pos)
        if idx == -1:
            return None
        pos = idx + 1
        start = idx + 4
        if start + 6 >= len(pkt) or pkt[start + 1] != CAM_MESSAGE_ID:
            continue
        try:
            return db.decode('CAM', pkt[start:])
        except Exception:
            continue


def cam_record(cam: dict, rx: float, names: dict) -> tuple:
    """(stationId, stationType, position row, incident) for one decoded CAM.

    position row: [rx time s, lat, lon, speed km/h | None, heading deg | None]
    (the caller appends the incident index as row[5], smooth_track the smoothed
    position and velocity as row[6..9])
    incident: (container name, cause no | None, sub cause no | None, text) of the
    special vehicle container, or None.
    """
    params = cam['cam']['camParameters']
    basic = params['basicContainer']
    ref = basic['referencePosition']
    speed = heading = None
    hf_type, hf = params['highFrequencyContainer']
    if hf_type == 'basicVehicleContainerHighFrequency':
        sv = hf['speed']['speedValue']
        hv = hf['heading']['headingValue']
        speed = round(sv * 0.036, 1) if sv != SPEED_UNAVAILABLE else None
        heading = round(hv / 10, 1) if hv != HEADING_UNAVAILABLE else None
    row = [round(rx, 3), ref['latitude'] / COORD_SCALE, ref['longitude'] / COORD_SCALE, speed, heading]

    incident = None
    svc = params.get('specialVehicleContainer')
    if svc:
        ctype, cdata = svc
        ii = cdata.get('incidentIndication') if isinstance(cdata, dict) else None
        if ii:
            no, cname, sub, subname = event_type_info(ii, names)
            incident = (ctype, no, sub, f'{cname}({no}) {subname or "unknown"}({sub})')
        else:
            incident = (ctype, None, None, '')
    return cam['header']['stationId'], basic['stationType'], row, incident


def cam_path_history(cam: dict):
    """pathHistory of the CAM low frequency container as [[lat, lon, pathDeltaTime | None], ...]
    (cumulative from the CAM referencePosition), or None without low frequency container."""
    params = cam['cam']['camParameters']
    lf = params.get('lowFrequencyContainer')
    if not lf or lf[0] != 'basicVehicleContainerLowFrequency':
        return None
    ph = lf[1].get('pathHistory') or []
    ref = params['basicContainer']['referencePosition']
    coords = cumulative_points(ref['latitude'], ref['longitude'], ph, 'pathPosition')
    return [[round(lat, 7), round(lon, 7), pp.get('pathDeltaTime')] for (lat, lon), pp in zip(coords, ph)]


def build_candidate(denm: dict, names: dict, st_names: dict) -> dict:
    """Everything the replay page needs from one decoded DENM."""
    payload = denm['denm']
    mgmt = payload['management']
    ep = mgmt['eventPosition']
    lat0, lon0 = ep['latitude'], ep['longitude']

    traces = []
    for path in (payload.get('location') or {}).get('detectionZonesToEventPosition') or []:
        coords = cumulative_points(lat0, lon0, path, 'pathPosition')
        traces.append([{'lat': lat, 'lon': lon, 'dt': pp.get('pathDeltaTime')}
                       for (lat, lon), pp in zip(coords, path)])

    situation = payload.get('situation') or {}
    event_zone = situation.get('eventZone')
    location = payload.get('location') or {}
    hdg = location.get('eventPositionHeading')
    spd = location.get('eventSpeed')
    st = mgmt['stationType']
    aid = mgmt['actionId']
    cause = None
    if situation.get('eventType'):
        no, _, sub, _ = event_type_info(situation['eventType'], names)
        cause = [no, sub]
    return {
        'stationId': aid['originatingStationId'],
        'seq': aid['sequenceNumber'],
        'stationType': f'{st_names.get(st, "unknown")}({st})',
        'stationTypeNo': st,
        'eventType': denm_event_type(denm, names),
        'cause': cause,
        'terminated': 'termination' in mgmt,
        'eventPosition': {'lat': lat0 / COORD_SCALE, 'lon': lon0 / COORD_SCALE},
        'eventZone': ([{'lat': la, 'lon': lo} for la, lo in
                       cumulative_points(lat0, lon0, event_zone, 'eventPosition')]
                      if event_zone else []),
        'traces': traces,
        'points': sum(len(t) for t in traces),
        # eventPositionHeading (deg, None = absent / unavailable) and its confidence (0.1 deg, 127 = unavailable)
        'heading': (hdg['value'] / 10 if hdg and hdg['value'] != WGS84_ANGLE_UNAVAILABLE else None),
        'headingConf': hdg['confidence'] if hdg else None,
        'speed': (round(spd['speedValue'] * 0.036, 1) if spd and spd['speedValue'] != SPEED_UNAVAILABLE else None),
    }


def denm_update(cand: dict) -> dict:
    """Compact form of one DENM (first reception of a new detectionTime) for the real-time view."""
    r7 = lambda x: round(x, 7)
    return {
        'rx': cand['rx'], 'seq': cand['seq'],
        'lat': r7(cand['eventPosition']['lat']), 'lon': r7(cand['eventPosition']['lon']),
        'hdg': cand['heading'], 'hdgConf': cand['headingConf'], 'spd': cand['speed'],
        'term': cand['terminated'], 'cause': cand['cause'], 'eventType': cand['eventType'],
        'traces': [[[r7(q['lat']), r7(q['lon']), q['dt']] for q in t] for t in cand['traces']],
        'ez': [[r7(q['lat']), r7(q['lon'])] for q in cand['eventZone']],
    }


def collect(pcap_files: list, asn_dir: Path, cam_asn_dir) -> tuple:
    """Return (DENM stations, CAM stations); CAM stations is [] if cam_asn_dir is None."""
    print(f'Compiling ASN.1 definitions from: {asn_dir}')
    for name in ASN_FILES:
        print(f'  - {name}')
    db = compile_asn(asn_dir)
    print('ASN.1 compilation successful.')
    cam_db = None
    if cam_asn_dir is not None:
        print(f'Compiling CAM ASN.1 definitions from: {cam_asn_dir}')
        for name in CAM_ASN_FILES:
            print(f'  - {name}')
        cam_db = compile_cam_asn(cam_asn_dir)
        print('ASN.1 compilation successful.')
    names = load_cause_names(asn_dir)
    st_names = load_station_type_names(asn_dir)
    cams: dict = {}      # CAM stationId -> {'stationTypeNo', 'positions', 'incidents'}
    first_rx: dict = {}  # (stationId, seq, detectionTime) -> first reception time
    updates: dict = {}   # stationId -> DENM updates (first reception of every detectionTime)

    n_denms: dict = {}   # stationId -> number of received DENMs (incl. repetitions)
    st_type: dict = {}   # stationId -> (stationType number, text)
    for pcap_file in expand_pcaps(pcap_files):
        n_pkt = n_denm = n_cam = 0
        for rx, pkt in iter_its_packets_ts(pcap_file):
            n_pkt += 1
            denm, _ = extract_denm(pkt, db)
            if denm is None:
                cam = extract_cam(pkt, cam_db) if cam_db is not None else None
                if cam is not None:
                    n_cam += 1
                    sid, stype, row, incident = cam_record(cam, rx, names)
                    c = cams.setdefault(sid, {'stationTypeNo': stype, 'positions': [], 'incidents': {},
                                              'paths': []})
                    # row[5]: index into the station's incident list (None = no special vehicle container)
                    row.append(c['incidents'].setdefault(incident, len(c['incidents']))
                               if incident else None)
                    c['positions'].append(row)
                    path = cam_path_history(cam)
                    if path is not None:
                        # [rx, referencePosition lat, lon, pathHistory points]
                        c['paths'].append([row[0], row[1], row[2], path])
                continue
            n_denm += 1
            mgmt = denm['denm']['management']
            sid = mgmt['actionId']['originatingStationId']
            n_denms[sid] = n_denms.get(sid, 0) + 1
            # Reception time of the first DENM with this detectionTime = time of the
            # eventPosition (repetitions of the same DENM are received later)
            det_key = (sid, mgmt['actionId']['sequenceNumber'], mgmt['detectionTime'])
            if det_key in first_rx:
                continue
            first_rx[det_key] = rx
            cand = build_candidate(denm, names, st_names)
            cand['rx'] = round(rx, 3)
            st_type.setdefault(sid, (cand['stationTypeNo'], cand['stationType']))
            updates.setdefault(sid, []).append(denm_update(cand))
        print(f'\n{Path(pcap_file).name}: ITS-G5 packets {n_pkt} | DENMs {n_denm} | CAMs {n_cam}')

    result = []
    for sid in sorted(updates):
        ups = sorted(updates[sid], key=lambda u: u['rx'])
        # static actionIds: eventPosition, traces and eventZone the same in all DENMs of the actionId
        by_seq: dict = {}
        for u in ups:
            by_seq.setdefault(u['seq'], set()).add(json.dumps(
                [u['lat'], u['lon'], [[q[:2] for q in t] for t in u['traces']], u['ez']]))
        static = sorted(seq for seq, geo in by_seq.items() if len(geo) == 1)
        moving = [u for u in ups if u['seq'] not in static]
        rows = [[u['rx'], u['lat'], u['lon'], u['spd'], u['hdg'], None] for u in moving]
        smooth_track(rows)
        for u, r in zip(moving, rows):
            u['s'] = r[6:10]   # smoothed eventPosition lat, lon, velocity east, north (m/s)
        for u in ups:
            u.setdefault('s', [u['lat'], u['lon'], 0.0, 0.0])
        with_type = [u for u in ups if u['cause']]
        result.append({
            'stationId': sid, 'stationTypeNo': st_type[sid][0], 'stationType': st_type[sid][1],
            'eventType': (with_type[-1] if with_type else ups[-1])['eventType'],
            'seqs': sorted({u['seq'] for u in ups}), 'staticSeqs': static, 'denms': n_denms[sid], 'updates': ups,
        })

    print(f'\nUnique originatingStationIds: {len(result)}')
    for r in result:
        print(f'  {r["stationId"]:>12}  {r["stationType"]:<20}  DENMs {r["denms"]:>5}  '
              f'new detectionTimes {len(r["updates"]):>5}  static actionIds {len(r["staticSeqs"])}/{len(r["seqs"])}  '
              f'{r["eventType"]}  '
              f'(sequenceNumbers: {", ".join(map(str, r["seqs"]))})')

    cam_list = []
    for sid in sorted(cams):
        c = cams[sid]
        c['positions'].sort(key=lambda r: r[0])
        smooth_track(c['positions'])   # row[6..9]: smoothed lat, lon, velocity east, north
        c['paths'].sort(key=lambda p: p[0])
        cam_list.append({
            'stationId': sid,
            'stationTypeNo': c['stationTypeNo'],
            'stationType': f'{st_names.get(c["stationTypeNo"], "unknown")}({c["stationTypeNo"]})',
            'positions': c['positions'],
            'paths': c['paths'],
            'incidents': [list(i) for i in c['incidents']],   # in index order
        })
    if cam_db is not None:
        print(f'\nCAM stations: {len(cam_list)}')
        for c in cam_list:
            inc = ', '.join(sorted({f'{i[0]} {i[3]}'.strip() for i in c['incidents']})) or '-'
            print(f'  {c["stationId"]:>12}  {c["stationType"]:<20}  CAMs {len(c["positions"]):>5}  '
                  f'special vehicle container: {inc}')
    return result, cam_list


HTML_TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DENM Replay</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>
  :root { --bg:#f6f7f9; --panel:#ffffff; --text:#1d2330; --muted:#667085; --line:#d9dde5;
          --accent:#d92d20; --sel:#fde8e7;
          --c-denm:#ff3b30; --c-dtr:#ffb020; --c-cam:#2e90fa; --c-ph:#7cfc00; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171c; --panel:#1d2128; --text:#e6e8ec; --muted:#98a2b3; --line:#323844;
            --accent:#ff6b5e; --sel:#3a2321; }
  }
  * { box-sizing: border-box; }
  html, body { margin:0; height:100%; background:var(--bg); color:var(--text);
               font:14px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; }
  #app { display:grid; grid-template-columns: 360px 1fr; grid-template-rows: 1fr auto; height:100%; }
  #side { grid-row: 1 / 3; background:var(--panel); border-right:1px solid var(--line);
          overflow:auto; padding:12px 14px; }
  #map { min-height:300px; }
  #controls { background:var(--panel); border-top:1px solid var(--line); padding:10px 16px; }
  h1 { font-size:16px; margin:0 0 4px; }
  h2 { font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:16px 0 6px; }
  .muted { color:var(--muted); font-size:12px; }
  .station { border:1px solid var(--line); border-radius:6px; padding:8px 10px; margin-bottom:6px; cursor:pointer; }
  .station.sel { border-color:var(--accent); background:var(--sel); }
  .station b { font-variant-numeric: tabular-nums; }
  label.opt { display:block; padding:3px 0; cursor:pointer; }
  .row { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .row + .row { margin-top:8px; }
  button { font:inherit; padding:5px 12px; border:1px solid var(--line); border-radius:4px;
           background:var(--bg); color:var(--text); cursor:pointer; min-width:70px; }
  #timeline-wrap { position:relative; flex:1; min-width:200px; }
  #timeline { width:100%; margin:0; }
  #ticks { position:relative; height:8px; margin:0 8px; }
  #ticks span { position:absolute; top:0; width:1px; height:8px; background:var(--muted); }
  #status { font-variant-numeric: tabular-nums; min-width:260px; }
  /* point labels in the layer colour */
  .tl { color:#fff; border:none; box-shadow:none; font-size:11px; padding:1px 4px; text-shadow:0 0 2px #000, 0 0 2px #000; }
  .tl::before { display:none; }
  .lbl-denm { background:var(--c-denm); } .lbl-dtr { background:var(--c-dtr); }
  .lbl-cam { background:var(--c-cam); } .lbl-ph { background:var(--c-ph); }
  .layer { border:1px solid var(--line); border-left:4px solid var(--lc); border-radius:6px; padding:5px 8px; margin-bottom:6px; }
  .layer .lhead { display:flex; align-items:center; gap:6px; }
  .layer .lhead label { display:flex; align-items:center; gap:6px; font-weight:600; cursor:pointer; white-space:nowrap; }
  .layer input[type=color] { width:20px; height:18px; padding:0; border:1px solid var(--line); border-radius:4px;
                             background:none; cursor:pointer; flex:none; }
  .layer .lbody { margin-top:5px; }
  .layer.off .lbody { opacity:.5; }
  .chips { display:flex; flex-wrap:wrap; gap:4px; }
  .chip { position:relative; display:inline-flex; align-items:center; gap:4px; padding:1px 8px; font-size:12px;
          border:1px solid var(--line); border-radius:10px; cursor:pointer; user-select:none; color:var(--muted); }
  .chip input[type=checkbox] { position:absolute; opacity:0; width:0; height:0; margin:0; }
  .chip:has(input:checked) { color:var(--text); border-color:var(--lc); background:color-mix(in srgb, var(--lc) 22%, transparent); }
  .chip:has(input:focus-visible) { outline:2px solid var(--lc); outline-offset:1px; }
  .chip input[type=color] { width:14px; height:12px; border-radius:3px; }
  .layer .minrow { display:flex; align-items:center; gap:6px; margin-top:5px; font-size:12px; }
  .layer .minrow input[type=range] { flex:1; min-width:60px; }
  .layer .minrow input[type=range]:disabled { opacity:.35; }
  .layer .nval { min-width:40px; text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); }
  .hdg-ico { background:none; border:none; }
  #ppflash { position:absolute; top:50%; left:50%; width:64px; height:64px; margin:-32px 0 0 -32px; z-index:1000;
             border-radius:50%; background:rgba(0,0,0,.35); pointer-events:none; opacity:0;
             display:flex; align-items:center; justify-content:center; }
  #ppflash svg { width:28px; height:28px; fill:rgba(255,255,255,.9); }
  #ppflash.go { animation:ppflash .7s ease-out; }
  @keyframes ppflash { 0% { opacity:1; transform:scale(.85); } 100% { opacity:0; transform:scale(1.25); } }
  #phwarn { position:absolute; top:10px; left:50%; transform:translateX(-50%); z-index:1000; display:none;
            max-width:calc(100% - 120px); background:#b42318; color:#fff; border-radius:6px; padding:6px 12px;
            font-size:13px; box-shadow:0 2px 8px rgba(0,0,0,.4); pointer-events:none; }
  #phwarn b { display:block; }
  .cam { display:block; border:1px solid var(--line); border-radius:6px; padding:6px 8px; margin-bottom:6px;
         cursor:pointer; color:var(--text); }
  .cam .score { float:right; font-weight:600; font-variant-numeric: tabular-nums; }
  .cam small { display:block; color:var(--muted); }
  .swatch { display:inline-block; width:10px; height:10px; border-radius:50%; vertical-align:middle; margin-right:4px; }
  @media (max-width: 760px) {
    #app { grid-template-columns: 1fr; grid-template-rows: auto 55vh auto; }
    #side { grid-row:auto; max-height:40vh; border-right:none; border-bottom:1px solid var(--line); }
  }
</style>
</head>
<body>
<div id="app">
  <div id="side">
    <h1>DENM Replay</h1>
    <div class="muted" id="src"></div>
    <h2>stationType filter</h2>
    <div id="stfilter"></div>
    <h2>originatingStationId</h2>
    <div id="stations"></div>
    <div id="staticSel" style="display:none">
      <h2>Static DENM (sequenceNumber)</h2>
      <div id="staticList"></div>
    </div>
    <h2>CAM match</h2>
    <div id="cams" class="muted"></div>
    <h2>Visualize</h2>
    <label class="opt" title="DENM traces and CAM pathHistory: also the points passed before the replay start">
      <input type="checkbox" id="showOld"> show points older than replay</label>
    <div id="layercards"></div>
    <button id="resetView" title="Layer options and colours back to the defaults">Reset view</button>
    <h2>Info</h2>
    <div id="info" class="muted"></div>
  </div>
  <div id="map"></div>
  <div id="controls">
    <div class="row">
      <button id="play">Play</button>
      <button id="restart">Restart</button>
      <div id="timeline-wrap">
        <input type="range" id="timeline" min="0" max="10000" value="0">
        <div id="ticks"></div>
      </div>
    </div>
    <div class="row">
      <span>Speed</span>
      <input type="range" id="speed" min="-1" max="1.699" step="0.001" value="0" style="width:200px">
      <span id="speedval" style="min-width:50px">1.0x</span>
      <span id="status" class="muted"></span>
    </div>
  </div>
</div>
<script>
const DATA = __DATA__;
const RSU = __RSU__;
const CAM_MAX_GAP = __CAM_MAX_GAP__;   // s; no CAM position is interpolated across larger gaps
const stFilter = new Set();
const $ = id => document.getElementById(id);
$('src').textContent = DATA.source;

const map = L.map('map', { zoomControl: true });
L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
  maxZoom: 21, maxNativeZoom: 19,
  attribution: 'Imagery &copy; Esri, Maxar, Earthstar Geographics, and the GIS User Community'
}).addTo(map);
map.setView([50, 10], 5);
map.createPane('previewPane').style.zIndex = 390;   // previews below the replayed tracks

function haversine(a, b) {
  const R = 6371000, r = Math.PI / 180;
  const dLa = (b.lat - a.lat) * r, dLo = (b.lon - a.lon) * r;
  const h = Math.sin(dLa / 2) ** 2 + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dLo / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}
const lastIdx = (arr, t, get = x => x[0]) => {   // index of the last element with time <= t, -1 if none
  let lo = -1, hi = arr.length;
  while (hi - lo > 1) { const m = (lo + hi) >> 1; if (get(arr[m]) <= t) lo = m; else hi = m; }
  return lo;
};
const tStr = t => new Date(t * 1000).toISOString().slice(11, 23);

// ─── Visualized layers ─────────────────────────────────────────────────────
// denm: eventPositions of all DENMs of the station; dtr: trace of the latest DENM;
// cam: positions of the matched CAM station; ph: pathHistory of its latest CAM.
// Every layer: show, colour, points (off = line only), time labels, full preview,
// minimal view (only the last n points); extras per layer.
const LAYERS = {
  denm: { title: 'DENM', sub: 'eventPositions of all DENMs', lblText: 'time to prev. DENM',
          def: { show: true, color: '#ff3b30', points: true, labels: false, preview: false, minimal: true, n: 8,
                 ez: true, ezColor: '#12b76a', heading: false, smooth: true } },
  dtr:  { title: 'DENM traces', sub: 'latest DENM, from replay start', lblText: 'pathDeltaTime',
          def: { show: true, color: '#ffb020', points: true, labels: true, preview: false, minimal: true, n: 8 } },
  cam:  { title: 'CAM', sub: 'positions of the matched CAM station', lblText: 'time to prev. CAM',
          def: { show: true, color: '#2e90fa', points: true, labels: false, preview: false, minimal: true, n: 15,
                 smooth: true, heading: false } },
  ph:   { title: 'CAM pathHistory', sub: 'latest CAM, from replay start', lblText: 'pathDeltaTime',
          def: { show: true, color: '#7cfc00', points: true, labels: false, preview: false, minimal: true, n: 15 } },
};
const MINIMAL_MAX = 40;
const opts = Object.fromEntries(Object.entries(LAYERS).map(([k, d]) => [k, { ...d.def }]));

// Heading arrow (degrees clockwise from north) just ahead of a point
function arrowIcon(deg, color) {
  return L.divIcon({ className: 'hdg-ico', iconSize: [24, 24], iconAnchor: [12, 12],
    html: `<svg width="24" height="24" viewBox="-12 -12 24 24" style="transform:rotate(${deg}deg)">` +
          `<path d="M0,-11 L5,-1 L0,-3.5 L-5,-1 Z" fill="${color}" stroke="#fff" stroke-width="1.2"/></svg>` });
}

class Track {
  constructor(k) {
    this.k = k;
    this.group = L.layerGroup().addTo(map);
    this.previewGroup = L.layerGroup().addTo(map);
    this.line = L.polyline([], { weight: 4 }).addTo(this.group);
    // traces / pathHistory: faint dotted connector from the latest pathPoint to the eventPosition /
    // referencePosition (the anchor), which is not a recorded point of the path itself
    this.link = L.polyline([], { weight: 3, opacity: .5, dashArray: '1 7', lineCap: 'round' }).addTo(this.group);
    this.markers = new Map();
    this.previewLL = [];
    this.restyle();
  }
  get color() { return opts[this.k].color; }
  restyle() {
    this.line.setStyle({ color: this.color });
    this.link.setStyle({ color: this.color });
    this.reset();
    this.setPreview(this.previewLL);
  }
  reset() {
    for (const m of this.markers.values()) this.group.removeLayer(m);
    this.markers.clear();
  }
  // pts: chronological [{id, lat, lon, lbl, popup, hdg, anchor, via, mlat, mlon}], head: {lat, lon} | null.
  // Anchors (eventPosition, CAM referencePosition) and curve samples (via) are part of the line,
  // get no marker and are not counted in the minimal view.
  update(pts, head, o) {
    let vis = pts;
    if (o.minimal) {
      let c = 0, i = pts.length;
      while (i > 0) {
        const p = pts[i - 1];
        if (!p.anchor && !p.via) { if (c >= o.n) break; c++; }
        else if (p.via && c >= o.n) break;
        i--;
      }
      vis = pts.slice(i);
    }
    const ll = [...vis.map(p => [p.lat, p.lon]), ...(head ? [[head.lat, head.lon]] : [])];
    const last = vis[vis.length - 1];
    if (!head && last && last.anchor) {   // anchor at the end: connected by the dotted link only
      this.line.setLatLngs(ll.slice(0, -1));
      this.link.setLatLngs(ll.length > 1 ? ll.slice(-2) : []);
    } else {
      this.line.setLatLngs(ll);
      this.link.setLatLngs([]);
    }
    const marked = p => !p.anchor && !p.via && (o.points || o.labels || (o.heading && p.hdg != null));
    const want = new Set(vis.filter(marked).map(p => p.id));
    for (const [id, m] of this.markers) if (!want.has(id)) { this.group.removeLayer(m); this.markers.delete(id); }
    for (const p of vis) {
      if (!want.has(p.id) || this.markers.has(p.id)) continue;
      const ll = [p.mlat ?? p.lat, p.mlon ?? p.lon];   // marker position (received CAM position for a smoothed CAM track)
      const g = L.layerGroup();
      if (o.heading && p.hdg != null)
        L.marker(ll, { icon: arrowIcon(p.hdg, this.color), interactive: false, keyboard: false }).addTo(g);
      const m = o.points
        ? L.circleMarker(ll, { radius: 4.5, color: '#fff', weight: 1.5, fillColor: this.color, fillOpacity: 1 })
        : L.circleMarker(ll, { radius: 2, stroke: false, fillOpacity: 0 });
      if (p.popup) m.bindPopup(p.popup);
      if (o.labels && p.lbl) m.bindTooltip(p.lbl, { permanent: true, direction: 'right', className: `tl lbl-${this.k}`, offset: [6, 0] });
      m.addTo(g);
      this.group.addLayer(g);
      this.markers.set(p.id, g);
    }
  }
  setPreview(latlngs) {
    this.previewLL = latlngs;
    this.previewGroup.clearLayers();
    if (latlngs.length > 1) {
      L.polyline(latlngs, { color: this.color, weight: 2, opacity: .6, dashArray: '4 6', pane: 'previewPane' })
        .addTo(this.previewGroup);
    }
  }
}
const tracks = Object.fromEntries(Object.keys(LAYERS).map(k => [k, new Track(k)]));
const ezLayer = L.layerGroup().addTo(map);   // eventZone of the latest DENM
const mover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillOpacity: 1 });
const camMover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillOpacity: 1 })
  .bindTooltip('', { permanent: true, direction: 'left', className: 'tl lbl-cam', offset: [-8, 0] });

function setMover(m, pos) {
  if (pos) { m.setLatLng([pos.lat, pos.lon]); if (!map.hasLayer(m)) m.addTo(map); }
  else if (map.hasLayer(m)) map.removeLayer(m);
}

// Warning banner on the map for an inconsistent / broken CAM pathHistory
const phWarn = document.createElement('div');
phWarn.id = 'phwarn';
map.getContainer().appendChild(phWarn);
function showPhWarning(text) {
  if (!text) { phWarn.style.display = 'none'; return; }
  phWarn.innerHTML = '<b>&#9888; CAM pathHistory inconsistent / broken</b>';
  phWarn.appendChild(document.createTextNode(text));
  phWarn.style.display = 'block';
}

// t0abs: capture time (s) of replay time 0 (just before the first DENM of the station).
// ref: what the CAMs are matched against ({pts: [{lat, lon, t}], t0, t1, cause, stationId, stationTypeNo})
const st = { showOld: false, station: null, U: [], staticAll: [], staticSel: null, staticDenms: [], denmPts: [], denmPtsSmooth: [], denmRows: [], t: 0, total: 0, playing: false, speed: 1, last: null,
             t0abs: 0, cam: null, camRank: [], ref: null, ezIdx: null };

// ─── Station selection ─────────────────────────────────────────────────────
function renderFilter() {
  const types = new Map();
  for (const s of DATA.stations) types.set(s.stationTypeNo, { name: s.stationType, n: (types.get(s.stationTypeNo)?.n || 0) + 1 });
  const box = $('stfilter');
  box.innerHTML = '';
  for (const [no, t] of [...types].sort((a, b) => a[0] - b[0])) {
    if (no !== RSU) stFilter.add(no);
    const lab = document.createElement('label');
    lab.className = 'opt';
    lab.innerHTML = `<input type="checkbox" data-st="${no}" ${no !== RSU ? 'checked' : ''}> ${t.name} – ${t.n} station(s)`;
    lab.querySelector('input').onchange = ev => {
      ev.target.checked ? stFilter.add(no) : stFilter.delete(no);
      renderStations();
    };
    box.appendChild(lab);
  }
}

function renderStations() {
  const box = $('stations');
  box.innerHTML = '';
  const list = DATA.stations.filter(s => stFilter.has(s.stationTypeNo));
  if (!list.length) { box.textContent = 'No stations for the selected stationType(s).'; return; }
  for (const s of list) {
    const div = document.createElement('div');
    div.className = 'station' + (st.station === s ? ' sel' : '');
    div.innerHTML = `<b>${s.stationId}</b> &middot; ${s.stationType}<br>
      <span class="muted">${s.eventType}<br>${s.updates.length} DENM(s) with a new detectionTime
      &middot; sequenceNumber(s) ${s.seqs.join(', ')}${s.staticSeqs.length ? ` (${s.staticSeqs.length === s.seqs.length ? 'all' : s.staticSeqs.length} static)` : ''}</span>`;
    div.onclick = () => selectStation(s);
    box.appendChild(div);
  }
}

// Every new detectionTime of the station (first reception) is one DENM update with its
// eventPosition, eventPositionHeading, eventSpeed, traces and eventZone.
function selectStation(s, staticSeq = null) {
  pause();
  st.station = s;
  renderStations();
  const A = s.updates;
  // Static actionIds (eventPosition, traces and eventZone never change): every sequenceNumber is its own
  // message; the selected one is shown with its most recent DENM for the whole replay. The replay itself
  // uses the DENMs of the moving actionIds (st.U).
  const stat = new Set(s.staticSeqs);
  const U = st.U = A.filter(u => !stat.has(u.seq));
  st.staticAll = s.staticSeqs.map(seq => {
    const us = A.filter(u => u.seq === seq);
    return { ...us[us.length - 1], n: us.length, from: us[0].rx, updates: us };
  });
  st.staticSel = stat.has(staticSeq) ? staticSeq : (s.staticSeqs.length ? s.staticSeqs[0] : null);
  st.staticDenms = st.staticAll.filter(u => u.seq === st.staticSel);
  renderStaticList();
  // Time span and CAM matching: all DENMs of the station; only static ones: the selected message
  const T = U.length || !st.staticDenms.length ? A : st.staticDenms[0].updates;
  st.t0abs = T[0].rx - 1;
  st.total = T[T.length - 1].rx + 1 - st.t0abs;
  st.ezIdx = null;
  const causes = T.filter(u => u.cause).map(u => u.cause);
  st.ref = { pts: T.map(u => ({ lat: u.lat, lon: u.lon, t: u.rx })), t0: T[0].rx, t1: T[T.length - 1].rx,
             cause: causes.length ? causes[causes.length - 1] : null, stationId: s.stationId, stationTypeNo: s.stationTypeNo };
  st.denmRows = U.map(u => [u.rx, u.lat, u.lon, u.spd, u.hdg, null, ...u.s]);
  st.denmPts = U.map((u, i) => {
    const prev = i ? U[i - 1] : null, newSeq = !prev || prev.seq !== u.seq;
    return { id: i, t: u.rx, lat: u.lat, lon: u.lon, hdg: u.hdg,
             lbl: newSeq ? `seq ${u.seq}` : `${(u.rx - prev.rx).toFixed(2)} s`,
             popup: denmPopup(s.stationId, u, prev) +
                    `<br>smoothed position ${haversine(u, { lat: u.s[0], lon: u.s[1] }).toFixed(1)} m from the received one` };
  });
  // smoothed track: curve samples ('via') between the DENMs, markers stay at the received eventPositions
  st.denmPtsSmooth = [];
  st.denmRows.forEach((row, i) => {
    const prev = st.denmRows[i - 1];
    if (prev && row[0] - prev[0] <= CAM_MAX_GAP) {
      for (let ts = prev[0] + CAM_SAMPLE; ts < row[0] - CAM_SAMPLE / 2; ts += CAM_SAMPLE)
        st.denmPtsSmooth.push({ id: `v${ts}`, t: ts, via: true, ...hermite(prev, row, ts) });
    }
    st.denmPtsSmooth.push({ ...st.denmPts[i], lat: row[6], lon: row[7], mlat: row[1], mlon: row[2] });
  });
  Object.values(tracks).forEach(tr => tr.reset());
  ezLayer.clearLayers();

  // Ticks at the start of every (moving) sequenceNumber
  const ticks = $('ticks');
  ticks.innerHTML = '';
  U.forEach((u, i) => {
    if (i && U[i - 1].seq === u.seq) return;
    const sp = document.createElement('span');
    sp.style.left = `${((u.rx - st.t0abs) / st.total) * 100}%`;
    sp.title = `seq ${u.seq}`;
    ticks.appendChild(sp);
  });

  const seqs = [];
  A.forEach(u => {
    let q = seqs[seqs.length - 1];
    if (!q || q.seq !== u.seq) seqs.push(q = { seq: u.seq, n: 0, from: u.rx, to: u.rx, term: false });
    q.n++; q.to = u.rx; q.term = q.term || u.term;
  });
  $('info').innerHTML = `originatingStationId ${s.stationId}<br>stationType ${s.stationType}<br>
    ${A.length} DENMs with a new detectionTime from ${tStr(A[0].rx)} to ${tStr(A[A.length - 1].rx)} UTC
    (capture clock)<br>` + seqs.map(q => `seq ${q.seq}: ${q.n} DENM(s), ${(q.to - q.from).toFixed(1)} s${q.term ? ', terminated' : ''}` +
    (stat.has(q.seq) ? ' – static' : '')).join('<br>');

  st.t = 0;
  rankCams();   // selects the CAM, updates the previews and renders
  const bounds = L.latLngBounds([...U, ...st.staticDenms].map(u => [u.lat, u.lon]));
  for (const u of st.staticDenms) {
    u.traces.forEach(tr => tr.forEach(q => bounds.extend([q[0], q[1]])));
    u.ez.forEach(q => bounds.extend(q));
  }
  map.fitBounds(bounds, { padding: [40, 40], maxZoom: 19 });
}

// List of the static messages (one per sequenceNumber) of the station; one is shown at a time
function renderStaticList() {
  const box = $('staticList');
  box.innerHTML = '';
  $('staticSel').style.display = st.staticAll.length ? '' : 'none';
  for (const u of st.staticAll) {
    const lab = document.createElement('label');
    lab.className = 'opt';
    lab.innerHTML = `<input type="radio" name="staticSeq" ${u.seq === st.staticSel ? 'checked' : ''}> <b>seq ${u.seq}</b>
      <span class="muted">${u.eventType} &middot; ${u.n} DENM(s) &middot; traces ${u.traces.map(t => t.length).join('/') || '-'}
      &middot; eventZone ${u.ez.length ? u.ez.length + ' pts' : '-'}${u.term ? ' &middot; terminated' : ''}</span>`;
    lab.querySelector('input').onchange = () => selectStation(st.station, u.seq);
    box.appendChild(lab);
  }
}

function denmPopup(sid, u, prev) {
  return `<b>DENM ${sid}/${u.seq}</b>${u.term ? ' (termination)' : ''}<br>received ${tStr(u.rx)} UTC` +
    (prev ? `<br>time to previous DENM: ${(u.rx - prev.rx).toFixed(3)} s` : '') +
    `<br>${u.eventType}<br>eventPositionHeading ${u.hdg ?? 'n/a'}°` +
    (u.hdg != null ? ` (confidence ${u.hdgConf === 127 ? 'unavailable' : (u.hdgConf / 10) + '°'})` : '') +
    `<br>eventSpeed ${u.spd ?? 'n/a'} km/h<br>traces: ${u.traces.map(t => t.length).join('/') || '-'} PathPoints`;
}

// Static DENMs: eventPosition (DENM card), all traces (DENM traces card) and eventZone of the most
// recent DENM of every static actionId, shown for the whole replay
const staticLayers = { denm: L.layerGroup(), dtr: L.layerGroup(), ez: L.layerGroup() };
function buildStatic() {
  Object.values(staticLayers).forEach(g => g.clearLayers());
  if (!st.station) return;
  const sid = st.station.stationId, od = opts.denm, ot = opts.dtr;
  for (const u of st.staticDenms) {
    drawEventZone(u, staticLayers.ez);
    u.traces.forEach((tr, ti) => {
      if (!tr.length) return;
      L.polyline(tr.map(q => [q[0], q[1]]), { color: ot.color, weight: 3 }).addTo(staticLayers.dtr);
      L.polyline([[u.lat, u.lon], [tr[0][0], tr[0][1]]], { color: ot.color, weight: 3, opacity: .5, dashArray: '1 7', lineCap: 'round' })
        .addTo(staticLayers.dtr);
      if (!ot.points && !ot.labels) return;
      tr.forEach((q, k) => {
        const m = ot.points
          ? L.circleMarker([q[0], q[1]], { radius: 4, color: '#fff', weight: 1.5, fillColor: ot.color, fillOpacity: 1 })
          : L.circleMarker([q[0], q[1]], { radius: 2, stroke: false, fillOpacity: 0 });
        const dtTxt = q[2] != null ? `${(q[2] / 100).toFixed(2)} s` : 'n/a';
        m.bindPopup(`<b>DENM ${sid}/${u.seq} trace ${ti + 1} point ${k + 1}</b><br>pathDeltaTime: ${q[2] ?? 'n/a'}` +
                    (q[2] != null ? ` (${dtTxt})` : ''));
        if (ot.labels && q[2] != null)   // no 'n/a' labels on static traces (often without pathDeltaTime)
          m.bindTooltip(dtTxt, { permanent: true, direction: 'right', className: 'tl lbl-dtr', offset: [6, 0] });
        m.addTo(staticLayers.dtr);
      });
    });
    if (od.heading && u.hdg != null)
      L.marker([u.lat, u.lon], { icon: arrowIcon(u.hdg, od.color), interactive: false, keyboard: false }).addTo(staticLayers.denm);
    const m = L.circleMarker([u.lat, u.lon], { radius: 7, color: '#fff', weight: 2, fillColor: od.color, fillOpacity: 1 })
      .bindPopup(denmPopup(sid, u, null) +
                 `<br><i>static: eventPosition, traces and eventZone the same in all ${u.n} DENM(s) of this actionId; most recent DENM shown</i>`);
    if (od.labels) m.bindTooltip(`seq ${u.seq}`, { permanent: true, direction: 'top', className: 'tl lbl-denm', offset: [0, -8] });
    m.addTo(staticLayers.denm);
  }
}

// ─── CAM matching ──────────────────────────────────────────────────────────
// CAM positions are rows [rx time s, lat, lon, speed km/h, heading deg, incident index,
// smoothed lat, lon, velocity east, north m/s]. DENMs and CAMs share the capture (receiver) clock.
const CAM_WINDOW = 5;       // s added before/after the DENM time span
const CAM_AUTO_SELECT = 50; // minimum score for the automatic CAM selection
// Special vehicle containers that fit a DENM cause code (no incidentIndication match)
const PLAUSIBLE_CONTAINER = {
  95: ['emergencyContainer', 'rescueContainer', 'safetyCarContainer'],   // emergencyVehicleApproaching
  15: ['emergencyContainer', 'rescueContainer'],                          // rescueAndRecoveryWorkInProgress
  3: ['roadWorksContainerBasic'],                                          // roadworks
  26: ['roadWorksContainerBasic', 'specialTransportContainer', 'safetyCarContainer'],  // slowVehicle
};

// Between two CAMs on the smoothed track: cubic Hermite interpolation with the smoothed velocities
const M_PER_DEG = 111320;
function hermite(a, b, t) {
  const dt = b[0] - a[0];
  if (dt <= 0) return { lat: a[6], lon: a[7] };
  const ky = M_PER_DEG, kx = M_PER_DEG * Math.cos(a[6] * Math.PI / 180);
  const bx = (b[7] - a[7]) * kx, by = (b[6] - a[6]) * ky;
  const s = (t - a[0]) / dt, s2 = s * s, s3 = s2 * s;
  const h10 = s3 - 2 * s2 + s, h01 = -2 * s3 + 3 * s2, h11 = s3 - s2;
  const x = h10 * dt * a[8] + h01 * bx + h11 * dt * b[8];
  const y = h10 * dt * a[9] + h01 * by + h11 * dt * b[9];
  return { lat: a[6] + y / ky, lon: a[7] + x / kx };
}
// Position at time t on rows [t, lat, lon, speed, heading, -, smoothed lat, lon, velocity east, north]
// (CAM positions, DENM eventPositions); smooth = false: received positions, linear interpolation
// (also used for the CAM matching)
const camPosAt = (c, t, smooth = false) => posAt(c.positions, t, smooth);
function posAt(P, t, smooth = false) {
  if (!P.length || t < P[0][0] - 1 || t > P[P.length - 1][0] + 1) return null;
  let lo = 0, hi = P.length - 1;
  while (hi - lo > 1) { const m = (lo + hi) >> 1; if (P[m][0] <= t) lo = m; else hi = m; }
  const a = P[lo], b = P[hi], iLat = smooth ? 6 : 1, iLon = smooth ? 7 : 2;
  if (t <= a[0]) return { lat: a[iLat], lon: a[iLon], row: a };
  if (t >= b[0]) return { lat: b[iLat], lon: b[iLon], row: b };
  if (b[0] - a[0] > CAM_MAX_GAP) return null;
  const row = (t - a[0]) < (b[0] - t) ? a : b;
  if (smooth) return { ...hermite(a, b, t), row };
  const f = (t - a[0]) / (b[0] - a[0]);
  return { lat: a[1] + (b[1] - a[1]) * f, lon: a[2] + (b[2] - a[2]) * f, row };
}
const CAM_SAMPLE = 0.1;   // s between the curve points of the smoothed CAM track

const clamp01 = x => Math.max(0, Math.min(1, x));
const median = arr => { const s = [...arr].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

function scoreCam(c) {
  const e = st.ref, P = e.pts, t0 = e.t0, t1 = e.t1;
  const win = c.positions.filter(r => r[0] >= t0 - CAM_WINDOW && r[0] <= t1 + CAM_WINDOW);
  if (!win.length) return null;

  // Track: distance between each eventPosition and the CAM position at the same time
  const dists = [];
  P.forEach(p => { const q = camPosAt(c, p.t); if (q) dists.push(haversine(p, q)); });
  let trace, traceTxt;
  if (dists.length >= 2) {
    const med = median(dists);
    trace = clamp01((50 - med) / 45);               // <= 5 m: 1, >= 50 m: 0
    traceTxt = `eventPositions ${med.toFixed(1)} m median (${dists.length} pts at same time)`;
  } else {
    const near = P.map(p => Math.min(...win.map(r => haversine(p, { lat: r[1], lon: r[2] }))));
    const med = median(near);
    trace = 0.5 * clamp01((50 - med) / 45);         // spatial only: half weight
    traceTxt = `eventPositions ${med.toFixed(1)} m median (spatial only)`;
  }

  // Timing: share of the DENM time span covered by CAMs of this station
  const N = 100;
  let covered = 0;
  for (let i = 0; i <= N; i++) if (camPosAt(c, t0 + (t1 - t0) * i / N)) covered++;
  const timing = covered / (N + 1);

  // Cause: incidentIndication of the special vehicle container in the time window
  let cause = 0, causeTxt = 'no cause information';
  const incs = [...new Set(win.map(r => r[5]).filter(i => i !== null))].map(i => c.incidents[i]);
  if (e.cause && incs.length) {
    const [cno, csub] = e.cause;
    const exact = incs.find(i => i[1] === cno && i[2] === csub);
    const same = incs.find(i => i[1] === cno);
    const plaus = incs.find(i => (PLAUSIBLE_CONTAINER[cno] || []).includes(i[0]));
    if (exact) { cause = 1; causeTxt = `${exact[0]}: ${exact[3]} (same cause and sub cause)`; }
    else if (same) { cause = 0.8; causeTxt = `${same[0]}: ${same[3]} (same cause)`; }
    else if (plaus) { cause = 0.5; causeTxt = `${plaus[0]}${plaus[3] ? ': ' + plaus[3] : ''} (fits the cause)`; }
    else causeTxt = `${incs.map(i => i[0] + (i[3] ? ': ' + i[3] : '')).join(', ')} (does not fit)`;
  }

  // Station: same stationId, or at least the same stationType
  const station = c.stationId === e.stationId ? 1 : c.stationTypeNo === e.stationTypeNo ? 0.3 : 0;
  const stationTxt = station === 1 ? 'same stationId' : station ? 'same stationType' : 'other station';

  const score = 40 * trace + 25 * timing + 20 * cause + 15 * station;
  return { c, score, win, details: [traceTxt, `time coverage ${Math.round(timing * 100)} %`, causeTxt, stationTxt] };
}

function rankCams() {
  st.camRank = DATA.cams.map(scoreCam).filter(Boolean).sort((a, b) => b.score - a.score);
  const box = $('cams');
  box.innerHTML = '';
  if (!DATA.cams.length) { box.textContent = 'No CAMs decoded.'; selectCam(null); return; }
  if (!st.camRank.length) { box.textContent = 'No CAMs in the time window of the DENMs.'; selectCam(null); return; }
  const best = st.camRank[0].score >= CAM_AUTO_SELECT ? st.camRank[0] : null;
  const mk = r => {
    const lab = document.createElement('label');
    lab.className = 'cam';
    lab.innerHTML = r
      ? `<input type="radio" name="cam" ${r === best ? 'checked' : ''}> <span class="swatch" style="background:var(--c-cam)"></span>
         <b>${r.c.stationId}</b> &middot; ${r.c.stationType}<span class="score">${r.score.toFixed(0)}/100</span>
         <small>${r.details.join('<br>')}<br>${r.win.length} CAM(s) in the time window</small>`
      : `<input type="radio" name="cam" ${best ? '' : 'checked'}> no CAM` +
        (best ? '' : `<small>no candidate reaches ${CAM_AUTO_SELECT}/100, none preselected</small>`);
    lab.querySelector('input').onchange = () => selectCam(r);
    box.appendChild(lab);
  };
  st.camRank.forEach(mk);
  mk(null);
  selectCam(best);
}

function selectCam(r) {
  st.cam = r;
  if (r) {
    // rowsRaw: received positions; rowsSmooth: smoothed track with curve samples ('via') between the
    // CAMs, the markers stay at the received positions (mlat/mlon)
    const P = r.c.positions, i0 = P.indexOf(r.win[0]);
    r.rowsRaw = []; r.rowsSmooth = [];
    r.win.forEach((row, i) => {
      const prev = P[i0 + i - 1];
      const dt = prev ? row[0] - prev[0] : null;
      if (prev && dt <= CAM_MAX_GAP) {
        for (let ts = prev[0] + CAM_SAMPLE; ts < row[0] - CAM_SAMPLE / 2; ts += CAM_SAMPLE)
          r.rowsSmooth.push({ id: `v${ts}`, t: ts, via: true, ...hermite(prev, row, ts) });
      }
      const pt = { id: row[0], t: row[0], lat: row[1], lon: row[2], row, hdg: row[4],
                   lbl: dt !== null ? `${dt.toFixed(2)} s` : 'n/a',
                   popup: `<b>CAM ${r.c.stationId}</b><br>received ${tStr(row[0])} UTC` +
                          `<br>time to previous CAM: ${dt !== null ? dt.toFixed(3) + ' s' : 'n/a'}` +
                          `<br>speed ${row[3] ?? 'n/a'} km/h, heading ${row[4] ?? 'n/a'}°` +
                          `<br>smoothed position ${haversine({ lat: row[1], lon: row[2] }, { lat: row[6], lon: row[7] }).toFixed(1)} m from the received one` };
      r.rowsRaw.push(pt);
      r.rowsSmooth.push({ ...pt, lat: row[6], lon: row[7], mlat: row[1], mlon: row[2] });
    });
  }
  tracks.cam.reset(); tracks.ph.reset();
  updatePreviews();
  applyDisplay();
  render();
}
const camRows = r => opts.cam.smooth ? r.rowsSmooth : r.rowsRaw;

// ─── Recorded paths: DENM traces and CAM pathHistory ───────────────────────
// Both are shown for the latest message that has one, only the part from the replay start
// (st.t0abs) on. pathDeltaTime (10 ms) is the time to the previous point (the eventPosition /
// referencePosition for the first one), so point i was passed at rx - sum(pathDeltaTime 1..i).
function recordedPoints(rx, refLat, refLon, path, idPrefix, title) {
  const out = [];
  let acc = 0;
  path.forEach((p, i) => {
    if (p[2] !== null) acc += p[2] / 100;
    if (rx - acc < st.t0abs && !st.showOld) return;   // passed before the replay start
    out.push({ id: `${idPrefix}:${i}`, lat: p[0], lon: p[1],
               lbl: p[2] !== null ? `${(p[2] / 100).toFixed(2)} s` : 'n/a',
               popup: `<b>${title} point ${i + 1}</b><br>pathDeltaTime: ${p[2] ?? 'n/a'}` +
                      (p[2] !== null ? ` (${(p[2] / 100).toFixed(2)} s)` : '') + `<br>${acc.toFixed(2)} s before the message` });
  });
  out.reverse();
  if (rx >= st.t0abs) out.push({ id: `${idPrefix}:ref`, lat: refLat, lon: refLon, anchor: true });
  return out;
}

// DENM traces: first trace of the latest (moving) DENM with a trace (the station's own path)
function dtrPoints(absT) {
  const U = st.U;
  let j = lastIdx(U, absT, u => u.rx);
  while (j >= 0 && !(U[j].traces.length && U[j].traces[0].length)) j--;
  if (j < 0) return { pts: [], u: null };
  const u = U[j];
  return { pts: recordedPoints(u.rx, u.lat, u.lon, u.traces[0], `${j}`, `DENM ${st.station.stationId}/${u.seq} trace 1`), u };
}

// CAM pathHistory entries: [rx, referencePosition lat, lon, [[lat, lon, pathDeltaTime], ...]]
// Plausibility of a received pathHistory (the full one, not only the part shown):
//  - pathDeltaTime 0: two points at the same time
//  - a step of more than PH_JUMP_MIN m at more than PH_MAX_SPEED km/h
//    (short steps are ignored, GNSS jitter gives e.g. 2 m in 0.01 s)
const PH_MAX_SPEED = 250, PH_JUMP_MIN = 50;
function ranges(nums) {   // [2, 5, 6, 7] -> "2, 5–7"
  const out = [];
  for (let i = 0; i < nums.length; i++) {
    let j = i;
    while (j + 1 < nums.length && nums[j + 1] === nums[j] + 1) j++;
    out.push(j > i ? `${nums[i]}–${nums[j]}` : `${nums[i]}`);
    i = j;
  }
  return out.join(', ');
}
function phIssues(ph) {
  if (ph.issues) return ph.issues;
  const zero = [], fast = [];
  let prev = { lat: ph[1], lon: ph[2] };
  ph[3].forEach((p, i) => {
    const cur = { lat: p[0], lon: p[1] }, d = haversine(prev, cur);
    if (p[2] === 0) zero.push(i + 1);
    else if (p[2] && d > PH_JUMP_MIN && d / (p[2] / 100) * 3.6 > PH_MAX_SPEED)
      fast.push(`point ${i + 1}: ${d.toFixed(0)} m in ${(p[2] / 100).toFixed(2)} s (${(d / (p[2] / 100) * 3.6).toFixed(0)} km/h)`);
    prev = cur;
  });
  ph.issues = [...(zero.length ? [`${zero.length} point(s) with pathDeltaTime 0 (point ${ranges(zero)})`] : []), ...fast];
  return ph.issues;
}
function phPoints(r, absT) {
  const paths = r.c.paths || [];
  const j = lastIdx(paths, absT);
  if (j < 0) return { pts: [], ph: null };
  const ph = paths[j];
  return { pts: recordedPoints(ph[0], ph[1], ph[2], ph[3], `${ph[0]}`, `CAM ${r.c.stationId} pathHistory`), ph };
}

// Full previews = what each layer shows at the end of the replay
function updatePreviews() {
  const r = st.cam, t1 = st.ref ? st.ref.t1 : 0;
  tracks.denm.setPreview(!st.station ? [] : opts.denm.smooth ? st.denmPtsSmooth.map(p => [p.lat, p.lon])
                                                             : st.U.map(u => [u.lat, u.lon]));
  tracks.dtr.setPreview(st.station ? dtrPoints(t1).pts.map(p => [p.lat, p.lon]) : []);
  tracks.cam.setPreview(r ? camRows(r).map(p => [p.lat, p.lon]) : []);
  tracks.ph.setPreview(r ? phPoints(r, t1).pts.map(p => [p.lat, p.lon]) : []);
}

// ─── Rendering at replay time t ────────────────────────────────────────────
function renderEventZone(i) {   // eventZone of DENM update i
  if (i === st.ezIdx) return;
  st.ezIdx = i;
  ezLayer.clearLayers();
  const u = i >= 0 ? st.U[i] : null;
  if (u) drawEventZone(u, ezLayer);
}

// eventZone of DENM u: line from the eventPosition through the eventZone points; with the DENM
// option "points" also the eventZone points themselves (popup with the point number and position)
function drawEventZone(u, group) {
  if (!u.ez.length) return;
  const col = opts.denm.ezColor, sid = st.station.stationId;
  L.polyline([[u.lat, u.lon], ...u.ez], { color: col, weight: 4, opacity: .85 }).addTo(group);
  if (!opts.denm.points) return;
  u.ez.forEach((q, k) => L.circleMarker(q, { radius: 4, color: '#fff', weight: 1.5, fillColor: col, fillOpacity: 1 })
    .bindPopup(`<b>DENM ${sid}/${u.seq} eventZone point ${k + 1} of ${u.ez.length}</b>` +
               `<br>${q[0].toFixed(7)}, ${q[1].toFixed(7)}<br>${haversine(u, { lat: q[0], lon: q[1] }).toFixed(1)} m from the eventPosition`)
    .addTo(group));
}

function renderCam(absT, denmPos) {
  const r = st.cam, oc = opts.cam, op = opts.ph;
  if (!r) {
    tracks.cam.update([], null, oc); tracks.ph.update([], null, op);
    showPhWarning(null);
    setMover(camMover, null);
    return '';
  }
  let txt = '';
  // CAM track up to absT. Smoothing on: smoothed track (curve samples included), head = smoothed
  // position at absT. Off: received positions, head = linear interpolation (minimal view: the
  // marker stays on the latest received CAM).
  const rows = camRows(r), sm = oc.smooth;
  const pts = rows.slice(0, lastIdx(rows, absT, x => x.t) + 1);
  const q = camPosAt(r.c, absT, sm);
  const latest = pts.length ? pts[pts.length - 1] : null;
  const head = sm || !oc.minimal ? q : null;
  tracks.cam.update(pts, head, oc);
  const cpos = head || (sm ? null : latest);
  setMover(camMover, oc.show ? cpos : null);
  if (oc.show) {
    if (cpos) {
      const row = head ? q.row : latest.row;
      const spd = row[3] !== null ? `${row[3].toFixed(0)} km/h` : '';
      camMover.setTooltipContent(`CAM ${r.c.stationId} ${spd}`);
      txt += `  ·  CAM ${r.c.stationId} ${denmPos ? haversine(cpos, denmPos).toFixed(1) + ' m from DENM position' : ''}${spd ? ', ' + spd : ''}`;
    } else txt += `  ·  CAM ${r.c.stationId}: no CAM at this time`;
  }
  // pathHistory
  const php = phPoints(r, absT);
  tracks.ph.update(php.pts, null, op);
  const issues = op.show && php.ph ? phIssues(php.ph) : [];
  showPhWarning(issues.length ? `CAM ${r.c.stationId} received ${tStr(php.ph[0])} UTC: ` + issues.join('; ') : null);
  if (op.show) {
    const n = php.pts.filter(p => !p.anchor).length;
    txt += php.ph ? `  ·  pathHistory ${n} of ${php.ph[3].length} pts${st.showOld ? "" : " since replay start"}` : '  ·  pathHistory: none yet';
  }
  return txt;
}

function render() {
  if (!st.station) return;
  const U = st.U;
  const t = Math.min(Math.max(st.t, 0), st.total), absT = st.t0abs + t;
  const i = lastIdx(U, absT, u => u.rx);
  const u = i >= 0 ? U[i] : null;
  // DENM: eventPositions up to now; the marker is the latest eventPosition, with smoothing the
  // position on the smoothed track (curve samples included)
  let dpos = u;
  if (opts.denm.smooth) {
    const P = st.denmPtsSmooth;
    const q = u ? posAt(st.denmRows, absT, true) : null;
    tracks.denm.update(P.slice(0, lastIdx(P, absT, x => x.t) + 1), q, opts.denm);
    dpos = q || u;
  } else tracks.denm.update(st.denmPts.slice(0, i + 1), null, opts.denm);
  setMover(mover, opts.denm.show && dpos ? dpos : null);
  renderEventZone(i);
  // DENM traces of the latest DENM
  const dt = dtrPoints(absT);
  tracks.dtr.update(dt.pts, null, opts.dtr);

  $('timeline').value = st.total ? Math.round(t / st.total * 10000) : 0;
  const camTxt = renderCam(absT, dpos);
  let txt = `${t.toFixed(1)} / ${st.total.toFixed(1)} s  ·  ${tStr(absT)} UTC  ·  `;
  txt += u ? `DENM ${st.station.stationId}/${u.seq}${u.term ? ' TERMINATED' : ''}, ${(absT - u.rx).toFixed(1)} s ago, ` +
             `heading ${u.hdg ?? 'n/a'}°, ${u.spd ?? 'n/a'} km/h` : U.length ? 'no DENM yet' : 'no moving DENM';
  if (st.staticDenms.length) txt += `  ·  static DENM ${st.station.stationId}/${st.staticSel}: most recent of ${st.staticDenms[0].n} shown`;
  if (opts.dtr.show && U.length) {
    const n = dt.pts.filter(p => !p.anchor).length;
    txt += dt.u ? `  ·  trace ${n} of ${dt.u.traces[0].length} pts${st.showOld ? "" : " since replay start"}` : '  ·  trace: none yet';
  }
  $('status').textContent = txt + camTxt;
}

function applyDisplay() {
  for (const [k, tr] of Object.entries(tracks)) {
    const o = opts[k];
    o.show ? tr.group.addTo(map) : map.removeLayer(tr.group);
    o.show && o.preview ? tr.previewGroup.addTo(map) : map.removeLayer(tr.previewGroup);
  }
  const d = opts.denm;   // the minimal DENM view hides the eventZone
  d.show && !d.minimal && d.ez ? ezLayer.addTo(map) : map.removeLayer(ezLayer);
  buildStatic();
  d.show ? staticLayers.denm.addTo(map) : map.removeLayer(staticLayers.denm);
  opts.dtr.show ? staticLayers.dtr.addTo(map) : map.removeLayer(staticLayers.dtr);
  d.show && d.ez ? staticLayers.ez.addTo(map) : map.removeLayer(staticLayers.ez);
  document.querySelectorAll('.layer').forEach(el => el.classList.toggle('off', !opts[el.dataset.layer].show));
}

// Layer colours: CSS variables for labels and swatches, tracks, markers, eventZone
function applyColors() {
  for (const k of Object.keys(LAYERS)) {
    document.documentElement.style.setProperty(`--c-${k}`, opts[k].color);
    tracks[k].restyle();
  }
  mover.setStyle({ fillColor: opts.denm.color });
  camMover.setStyle({ fillColor: opts.cam.color });
  st.ezIdx = null;
}

// ─── Layer option cards ────────────────────────────────────────────────────
function renderLayerCards() {
  const box = $('layercards');
  box.innerHTML = '';
  for (const [k, d] of Object.entries(LAYERS)) {
    const o = opts[k], div = document.createElement('div');
    div.className = 'layer';
    div.dataset.layer = k;
    div.style.setProperty('--lc', `var(--c-${k})`);
    // option chips: short text, the full meaning in the tooltip
    const chip = (opt, text, tip, extra = '') =>
      `<label class="chip" title="${tip}"><input type="checkbox" data-opt="${opt}" ${o[opt] ? 'checked' : ''}>${text}${extra}</label>`;
    const extras = k === 'denm'
      ? chip('ez', 'eventZone', 'eventZone of the latest DENM (hidden in the minimal view)',
             `<input type="color" data-opt="ezColor" value="${o.ezColor}" title="eventZone colour">`) +
        chip('heading', 'heading', 'eventPositionHeading arrows') +
        chip('smooth', 'smooth', 'smoothed eventPosition track (Kalman + RTS)')
      : k === 'cam' ? chip('heading', 'heading', 'CAM heading arrows') +
                      chip('smooth', 'smooth', 'smoothed CAM track (Kalman + RTS)') : '';
    div.innerHTML = `
      <div class="lhead" title="${d.sub}">
        <label><input type="checkbox" data-opt="show" ${o.show ? 'checked' : ''}>${d.title}</label>
        <input type="color" data-opt="color" value="${o.color}" title="colour">
      </div>
      <div class="lbody">
        <div class="chips">
          ${chip('points', 'points', 'points (off: line only)')}${chip('labels', 'labels', 'labels: ' + d.lblText)}
          ${chip('preview', 'preview', 'full preview: faint dashed line of the whole replay')}${extras}
        </div>
        <div class="minrow">${chip('minimal', 'minimal', 'minimal view: only the last n points')}
          <input type="range" data-opt="n" min="1" max="${MINIMAL_MAX}" value="${o.n}" ${o.minimal ? '' : 'disabled'}>
          <span class="nval">${o.n} pts</span></div>
      </div>`;
    div.querySelectorAll('input').forEach(inp => inp.oninput = () => {
      const opt = inp.dataset.opt;
      if (opt === 'n') { o.n = +inp.value; div.querySelector('.nval').textContent = `${o.n} pts`; }
      else if (opt === 'color' || opt === 'ezColor') { o[opt] = inp.value; applyColors(); }
      else o[opt] = inp.checked;
      if (opt === 'minimal') div.querySelector('input[data-opt=n]').disabled = !o.minimal;
      if (['points', 'labels', 'smooth', 'heading'].includes(opt)) tracks[k].reset();
      if (k === 'denm' && opt === 'points') st.ezIdx = null;   // redraw the eventZone with/without points
      if (opt === 'smooth') updatePreviews();
      applyDisplay();
      render();
    });
    box.appendChild(div);
  }
}

// ─── Playback ──────────────────────────────────────────────────────────────
function frame(ts) {
  if (!st.playing) return;
  if (st.last !== null) st.t += (ts - st.last) / 1000 * st.speed;
  st.last = ts;
  if (st.t >= st.total) { st.t = st.total; render(); pause(); return; }
  render();
  requestAnimationFrame(frame);
}
function play() {
  if (!st.total) return;
  if (st.t >= st.total) st.t = 0;
  st.playing = true; st.last = null; $('play').textContent = 'Pause';
  requestAnimationFrame(frame);
}
function pause() { st.playing = false; $('play').textContent = 'Play'; }

$('play').onclick = () => st.playing ? pause() : play();

// A single click on the map toggles play / pause, with a short, faint play / pause sign on the map.
// Not on a click on a point (popup), not on the click that closes an open popup, not on a double click
// (zoom): the single click is only acted on after the double click time.
const ppFlash = document.createElement('div');
ppFlash.id = 'ppflash';
map.getContainer().appendChild(ppFlash);
function flashPlayPause(playing) {
  ppFlash.innerHTML = playing ? '<svg viewBox="0 0 24 24"><path d="M7 4.5v15l12.5-7.5z"/></svg>'
                              : '<svg viewBox="0 0 24 24"><path d="M6 4.5h4.2v15H6zM13.8 4.5H18v15h-4.2z"/></svg>';
  ppFlash.classList.remove('go');
  void ppFlash.offsetWidth;   // restart the animation
  ppFlash.classList.add('go');
}
let popupOpen = 0, popupWasOpen = false, clickTimer = null;
map.on('popupopen', () => popupOpen++);
map.on('popupclose', () => popupOpen = Math.max(0, popupOpen - 1));
map.on('preclick', () => popupWasOpen = popupOpen > 0);   // before Leaflet closes the popup
map.on('click', e => {
  const tgt = e.originalEvent && e.originalEvent.target;
  if (popupWasOpen || (tgt && tgt.classList && tgt.classList.contains('leaflet-interactive')) || !st.total) return;
  clearTimeout(clickTimer);
  clickTimer = setTimeout(() => {
    st.playing ? pause() : play();
    flashPlayPause(st.playing);
  }, 250);
});
map.on('dblclick', () => clearTimeout(clickTimer));
$('restart').onclick = () => { st.t = 0; render(); };
$('timeline').oninput = () => { st.t = $('timeline').value / 10000 * st.total; render(); };
$('speed').oninput = () => {
  st.speed = Math.pow(10, +$('speed').value);
  $('speedval').textContent = (st.speed < 10 ? st.speed.toFixed(1) : st.speed.toFixed(0)) + 'x';
};
// Show points older than replay: DENM traces and CAM pathHistory also show the points passed before
// the replay start (e.g. a DENM whose whole trace lies before its first reception)
function setShowOld(on) {
  st.showOld = $('showOld').checked = on;
  tracks.dtr.reset();
  tracks.ph.reset();
}
$('showOld').onchange = () => { setShowOld($('showOld').checked); updatePreviews(); render(); };

// Reset view: layer options and colours back to the defaults (selection and replay time are kept)
$('resetView').onclick = () => {
  for (const [k, d] of Object.entries(LAYERS)) Object.assign(opts[k], d.def);
  setShowOld(false);
  renderLayerCards();
  applyColors();
  updatePreviews();
  applyDisplay();
  render();
};

renderLayerCards();
applyColors();
renderFilter();
renderStations();
const pre = DATA.preselect && DATA.stations.find(s => s.stationId === DATA.preselect);
if (pre) {
  if (!stFilter.has(pre.stationTypeNo)) {
    stFilter.add(pre.stationTypeNo);
    $('stfilter').querySelector(`input[data-st="${pre.stationTypeNo}"]`).checked = true;
  }
  selectStation(pre);
} else {
  const first = DATA.stations.find(s => stFilter.has(s.stationTypeNo));
  if (first) selectStation(first);
}
</script>
</body>
</html>
'''


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Replay the DENMs of a station with the matching CAMs on a satellite map (self-contained HTML page).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s); wildcards such as *.pcap are expanded')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Output HTML file (default: named after the PCAP, <pcap name>_denm_replay.html '
                             'in the current directory; several PCAPs: <first pcap name>_and_<n>_more_denm_replay.html)')
    parser.add_argument('--station', type=int, metavar='ID',
                        help='Preselect this originatingStationId in the page')
    parser.add_argument('--no-open', action='store_true',
                        help='Do not open the page in the browser')
    parser.add_argument('--asn-dir', type=Path, default=DEFAULT_ASN_DIR, metavar='DIR',
                        help=f'Directory with ASN.1 files (default: {DEFAULT_ASN_DIR})')
    parser.add_argument('--cam-asn-dir', type=Path, default=DEFAULT_CAM_ASN_DIR, metavar='DIR',
                        help=f'Directory with CAM ASN.1 files (default: {DEFAULT_CAM_ASN_DIR})')
    parser.add_argument('--no-cam', action='store_true',
                        help='Do not decode CAMs (no CAM matching / parallel view)')
    args = parser.parse_args()
    try:
        stations, cams = collect(args.pcap, args.asn_dir,
                                 None if args.no_cam else args.cam_asn_dir)
    except (FileNotFoundError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)

    pcaps = expand_pcaps(args.pcap)
    data = {
        'source': ', '.join(Path(p).name for p in pcaps),
        'stations': stations,
        'cams': cams,
        'preselect': args.station,
    }
    if args.output:
        out = args.output if args.output.endswith('.html') else args.output + '.html'
    else:   # named after the PCAP(s)
        out = Path(pcaps[0]).stem + (f'_and_{len(pcaps) - 1}_more' if len(pcaps) > 1 else '') + '_denm_replay.html'
    html = (HTML_TEMPLATE.replace('__RSU__', str(RSU_STATION_TYPE))
            .replace('__CAM_MAX_GAP__', str(CAM_MAX_GAP))
            .replace('__DATA__', json.dumps(data).replace('</', '<\\/')))
    Path(out).write_text(html, encoding='utf-8')
    print(f'\nOutput written to: {out}')
    if not args.no_open:
        webbrowser.open(Path(out).resolve().as_uri())


if __name__ == '__main__':
    main()
