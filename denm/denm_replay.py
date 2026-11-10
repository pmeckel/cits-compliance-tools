#!/usr/bin/env python3
"""
DENM Trace Replay

Reads one or more PCAP files, decodes all DENMs and writes a self-contained
HTML page (Leaflet + Esri World Imagery satellite map, online) with two views:

  - all DENMs of a station in real time (default): every new DENM (first
    reception of a new detectionTime, any sequenceNumber) on the capture clock
    with its eventPosition, eventPositionHeading, eventSpeed, trace and eventZone
  - trace replay of a single DENM: the trace (location.detectionZonesToEventPosition)
    from its last PathPoint towards the eventPosition (described below)

Heading arrows (option): DENM eventPositionHeading, CAM heading.

Selection:
  - stationType filter: checkboxes for all stationTypes found in the capture;
    by default all are selected except 15 (roadSideUnit)
  - one entry per originatingStationId; the default is the DENM with the
    highest number of trace points (tie: highest sequenceNumber)
  - the other sequenceNumbers of that station can still be selected (per
    sequenceNumber the DENM with the most trace points is kept; tie: the one
    received last, i.e. the most recent trace)
  - all traces of the selected DENM are listed with their number of PathPoints

Replay:
  - starts at the last PathPoint and moves point by point to the eventPosition;
    the line is drawn as it goes and every reached PathPoint is marked with its
    pathDeltaTime
  - pathDeltaTime (unit 10 ms) is the travel time between a PathPoint and the
    previous one (the eventPosition for the first PathPoint). A missing
    pathDeltaTime is estimated from the median speed of the other segments
    and labeled "n/a"
  - modes: real time; real time with compressed pauses (segments longer than an
    adjustable cap are shortened to the cap); point by point (every segment
    takes 1 s at 1x)
  - timeline slider to move back and forth, speed slider (0.1x .. 50x)

The trace is drawn on a satellite map (Esri World Imagery, needs internet).

CAM in parallel (ASN.1 in ../cam/ASN, disable with --no-cam):
  - all CAMs of the capture are decoded; DENM and CAMs are put on the common
    capture (receiver) clock: the eventPosition is placed at the reception time
    of the first DENM with that detectionTime, every PathPoint pathDeltaTime
    earlier (the station clocks themselves may be far off)
  - every CAM station with CAMs in the time window of the selected trace is
    scored (0..100) and listed:
      40  trace  - median distance between trace points and the CAM position
                   at the same time (<= 5 m: full, >= 50 m: none)
      25  timing - share of the trace time span covered by CAMs
      20  cause  - incidentIndication of the CAM special vehicle container:
                   same cause and sub cause / same cause / container fits
      15  station - same stationId (or at least the same stationType)
  - the best candidate is selected automatically if it reaches 50/100; the
    CAM track (blue) and position are replayed in parallel with the DENM,
    with the distance between both shown in the status line

Visualize: three layers (DENM trace, CAM track, CAM pathHistory), shown
individually or together, each with the options points (off = line only),
time labels, full preview and a minimal view (only the last n points, slider
1..40). The CAM pathHistory is the one of the latest CAM with low
frequency container, limited to the part from the replay start on.
Optional (CAM option, off by default): the CAM track is smoothed (Kalman filter + RTS smoother on position, time and,
weakly, speed/heading) and interpolated between CAMs with a cubic curve along the
smoothed velocity; the CAM points stay at the received positions.
A warning banner "CAM pathHistory inconsistent / broken" is shown while the
received pathHistory has a point with pathDeltaTime 0 or a step of more than
50 m at more than 250 km/h; the pathHistory is still drawn as received.

Reuses PCAP parsing, ASN.1 compilation and DENM extraction from denm_count.py,
the event type text from denm_common.py and the delta position helper from
denm_to_kml.py.

Usage:
    python denm_replay.py TrafficManager.pcap
    python denm_replay.py TrafficManager.pcap --station 10101004 --seq 42 --view trace
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


# CAM track smoothing (Kalman filter + Rauch-Tung-Striebel smoother, constant velocity model).
# The received referencePositions jitter by about 1-1.5 m between CAMs; the reported heading is
# often off (e.g. at low speed), so speed/heading only weakly support the positions.
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


def smooth_cam_track(positions: list) -> None:
    """Append [smoothed lat, lon, velocity east, north (m/s)] to every (time sorted) position row."""
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
    (the caller appends the incident index as row[5], smooth_cam_track the smoothed
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

    best: dict = {}      # (stationId, seq) -> candidate with most trace points (tie: latest)
    n_denms: dict = {}   # (stationId, seq) -> number of DENMs
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
            cand = build_candidate(denm, names, st_names)
            # Reception time of the first DENM with this detectionTime = time of the
            # eventPosition (repetitions of the same DENM are received later)
            det_key = (cand['stationId'], cand['seq'], denm['denm']['management']['detectionTime'])
            if det_key not in first_rx:
                first_rx[det_key] = rx
                cand['rx'] = round(rx, 3)
                updates.setdefault(cand['stationId'], []).append(denm_update(cand))
            cand['rx'] = round(first_rx[det_key], 3)
            key = (cand['stationId'], cand['seq'])
            n_denms[key] = n_denms.get(key, 0) + 1
            if key not in best or cand['points'] >= best[key]['points']:
                best[key] = cand
        print(f'\n{Path(pcap_file).name}: ITS-G5 packets {n_pkt} | DENMs {n_denm} | CAMs {n_cam}')

    stations: dict = {}
    for key, cand in best.items():
        cand['denms'] = n_denms[key]
        stations.setdefault(key[0], []).append(cand)

    result = []
    for sid in sorted(stations):
        entries = sorted(stations[sid], key=lambda c: -c['seq'])
        default = max(entries, key=lambda c: (c['points'], c['seq']))
        result.append({'stationId': sid, 'default': default['seq'],
                       'stationTypeNo': default['stationTypeNo'],
                       'stationType': default['stationType'], 'entries': entries,
                       'updates': sorted(updates[sid], key=lambda u: u['rx'])})

    print(f'\nUnique originatingStationIds: {len(result)}')
    for st in result:
        d = next(e for e in st['entries'] if e['seq'] == st['default'])
        print(f'  {st["stationId"]:>12}  {d["stationType"]:<20}  seq {d["seq"]:>5}  '
              f'traces {"/".join(str(len(t)) for t in d["traces"]) or "-":<10}  '
              f'{d["eventType"]}  (sequenceNumbers: {", ".join(str(e["seq"]) for e in st["entries"])})')

    cam_list = []
    for sid in sorted(cams):
        c = cams[sid]
        c['positions'].sort(key=lambda r: r[0])
        smooth_cam_track(c['positions'])   # row[6..9]: smoothed lat, lon, velocity east, north
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
          --accent:#d92d20; --sel:#fde8e7; }
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
  select, input[type=number] { width:100%; padding:4px; background:var(--panel); color:var(--text);
                               border:1px solid var(--line); border-radius:4px; font:inherit; }
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
  .lbl { background:rgba(0,0,0,.65); color:#fff; border:none; box-shadow:none; font-size:11px; padding:1px 4px; }
  .lbl::before { display:none; }
  .ep-lbl { background:#d92d20; color:#fff; border:none; font-weight:600; }
  .ep-lbl::before { display:none; }
  .cam-lbl { background:#1570ef; color:#fff; border:none; font-size:11px; padding:1px 4px; }
  .cam-lbl::before { display:none; }
  .ph-lbl { background:#3f9c0a; color:#fff; border:none; font-size:11px; padding:1px 4px; }
  .ph-lbl::before { display:none; }
  .campt-lbl { background:#1570ef; color:#fff; border:none; font-size:11px; padding:1px 4px; }
  .campt-lbl::before { display:none; }
  .layer { border:1px solid var(--line); border-radius:6px; padding:6px 8px; margin-bottom:6px; }
  .layer .lhead { display:flex; align-items:center; gap:6px; font-weight:600; cursor:pointer; }
  .layer .lhead .muted { font-weight:400; margin-left:auto; }
  .layer .lopts { display:grid; grid-template-columns:1fr 1fr; gap:2px 10px; margin-top:4px; padding-left:22px; font-size:13px; }
  .layer .lopts label { cursor:pointer; white-space:nowrap; }
  .layer .minrow { grid-column:1 / -1; display:flex; align-items:center; gap:6px; }
  .layer .minrow input[type=range] { flex:1; min-width:60px; }
  .layer .nval { min-width:22px; text-align:right; font-variant-numeric:tabular-nums; }
  .layer.off .lopts { opacity:.45; }
  .hdg-ico { background:none; border:none; }
  .hidden { display:none; }
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
    <h2>View</h2>
    <label class="opt"><input type="radio" name="view" value="station"> All DENMs of the station in real time</label>
    <label class="opt"><input type="radio" name="view" value="trace"> Trace replay of a single DENM</label>
    <div id="traceSel">
      <h2>sequenceNumber</h2>
      <select id="seq"></select>
      <div class="muted" id="seqinfo"></div>
      <h2>Trace</h2>
      <div id="traces"></div>
    </div>
    <h2>CAM match</h2>
    <div id="cams" class="muted"></div>
    <h2>Visualize</h2>
    <div id="layercards"></div>
    <button id="resetView" title="Layer options and replay mode back to the defaults">Reset view</button>
    <div id="modeSel">
    <h2>Replay mode</h2>
    <label class="opt"><input type="radio" name="mode" value="real" checked> Real time (pathDeltaTime)</label>
    <label class="opt"><input type="radio" name="mode" value="compress"> Real time, compress pauses</label>
    <div class="row" style="padding-left:22px"><span class="muted">cap per segment (s)</span>
      <input type="number" id="cap" value="5" min="0.1" step="0.5" style="width:70px"></div>
    <label class="opt"><input type="radio" name="mode" value="points"> Point by point (1 s per point at 1x)</label>
    </div>
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
const stFilter = new Set();

const map = L.map('map', { zoomControl: true });
L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
  maxZoom: 21, maxNativeZoom: 19,
  attribution: 'Imagery &copy; Esri, Maxar, Earthstar Geographics, and the GIS User Community'
}).addTo(map);
map.setView([50, 10], 5);

// Previews below the replayed tracks
map.createPane('previewPane').style.zIndex = 390;
// ez: eventZone; static: eventPosition marker (trace view); epHdg: its heading arrow (trace view);
// cur: trace of the current DENM (real-time view)
const layers = { ez: L.layerGroup().addTo(map), static: L.layerGroup().addTo(map),
                 epHdg: L.layerGroup().addTo(map), cur: L.layerGroup().addTo(map) };
const mover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillColor: '#ff3b30', fillOpacity: 1 });
const camMover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillColor: '#1570ef', fillOpacity: 1 })
  .bindTooltip('', { permanent: true, direction: 'left', className: 'cam-lbl', offset: [-8, 0] });

// ─── Visualized layers: DENM trace, CAM track, CAM pathHistory ─────────────
// Every layer has the same options: show, points (off = line only), time labels,
// full preview, minimal view (only the last n points).
const LAYERS = {
  denm: { title: 'DENM', sub: 'trace PathPoints', color: '#ff3b30', fill: '#ffb020', preview: '#ffffff',
          lblClass: 'lbl', lblText: 'pathDeltaTime',
          def: { show: true, points: true, labels: true, preview: false, minimal: true, n: 8, ez: true, heading: false } },
  cam:  { title: 'CAM', sub: 'positions of the matched CAM station', color: '#2e90fa', fill: '#84caff', preview: '#84caff',
          lblClass: 'campt-lbl', lblText: 'time to prev. CAM',
          def: { show: true, points: true, labels: false, preview: false, minimal: true, n: 15, smooth: false, heading: false } },
  ph:   { title: 'CAM pathHistory', sub: 'from replay start', color: '#7cfc00', fill: '#3f9c0a', preview: '#c5f6a0',
          lblClass: 'ph-lbl', lblText: 'pathDeltaTime',
          def: { show: true, points: true, labels: false, preview: false, minimal: true, n: 15 } },
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
  constructor(d) {
    this.d = d;
    this.group = L.layerGroup().addTo(map);
    this.previewGroup = L.layerGroup().addTo(map);
    this.line = L.polyline([], { color: d.color, weight: 4 }).addTo(this.group);
    this.markers = new Map();
  }
  reset() {
    for (const m of this.markers.values()) this.group.removeLayer(m);
    this.markers.clear();
  }
  // pts: chronological [{id, lat, lon, lbl, popup, anchor}], head: {lat, lon} | null.
  // Anchors (eventPosition, CAM referencePosition) are part of the line but get no marker
  // and are not counted in the minimal view.
  update(pts, head, o) {
    let vis = pts;
    if (o.minimal) {
      // count only real points; anchors at the end are kept, curve samples ('via') only between kept points
      let c = 0, i = pts.length;
      while (i > 0) {
        const p = pts[i - 1];
        if (!p.anchor && !p.via) { if (c >= o.n) break; c++; }
        else if (p.via && c >= o.n) break;
        i--;
      }
      vis = pts.slice(i);
    }
    this.line.setLatLngs([...vis.map(p => [p.lat, p.lon]), ...(head ? [[head.lat, head.lon]] : [])]);
    const marked = p => !p.anchor && !p.via && (o.points || o.labels || (o.heading && p.hdg != null));
    const want = new Set(vis.filter(marked).map(p => p.id));
    for (const [id, m] of this.markers) if (!want.has(id)) { this.group.removeLayer(m); this.markers.delete(id); }
    for (const p of vis) {
      if (!want.has(p.id) || this.markers.has(p.id)) continue;
      const ll = [p.mlat ?? p.lat, p.mlon ?? p.lon];   // marker position (received CAM position for the CAM track)
      const g = L.layerGroup();
      if (o.heading && p.hdg != null)
        L.marker(ll, { icon: arrowIcon(p.hdg, this.d.color), interactive: false, keyboard: false }).addTo(g);
      const m = o.points
        ? L.circleMarker(ll, { radius: 4.5, color: '#fff', weight: 1.5, fillColor: this.d.fill, fillOpacity: 1 })
        : L.circleMarker(ll, { radius: 2, stroke: false, fillOpacity: 0 });
      if (p.popup) m.bindPopup(p.popup);
      if (o.labels && p.lbl) m.bindTooltip(p.lbl, { permanent: true, direction: 'right', className: this.d.lblClass, offset: [6, 0] });
      m.addTo(g);
      this.group.addLayer(g);
      this.markers.set(p.id, g);
    }
  }
  setPreview(latlngs) {
    this.previewGroup.clearLayers();
    if (latlngs.length > 1) {
      L.polyline(latlngs, { color: this.d.preview, weight: 2, opacity: .7, dashArray: '4 6', pane: 'previewPane' })
        .addTo(this.previewGroup);
    }
  }
}
const tracks = Object.fromEntries(Object.entries(LAYERS).map(([k, d]) => [k, new Track(d)]));

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

function setMover(m, pos) {
  if (pos) { m.setLatLng([pos.lat, pos.lon]); if (!map.hasLayer(m)) m.addTo(map); }
  else if (map.hasLayer(m)) map.removeLayer(m);
}

// t0abs: capture time (s) of replay time 0. Trace view: time of the last trace point, so that the
// eventPosition is at the DENM reception time. Real-time view: just before the first DENM.
// ref: what the CAMs are matched against ({pts: [{lat, lon, t}], t0, t1, cause, stationId, stationTypeNo, what})
const st = { station: null, entry: null, traceIdx: 0, seqPts: [], denmPts: [], T: [], realT: [],
             t: 0, total: 0, playing: false, speed: 1, last: null, t0abs: 0, cam: null, camRank: [],
             ref: null, curIdx: -1 };
const view = () => document.querySelector('input[name=view]:checked').value;

const $ = id => document.getElementById(id);
$('src').textContent = DATA.source;

function haversine(a, b) {
  const R = 6371000, r = Math.PI / 180;
  const dLa = (b.lat - a.lat) * r, dLo = (b.lon - a.lon) * r;
  const h = Math.sin(dLa / 2) ** 2 + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dLo / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

// ─── Selection UI ──────────────────────────────────────────────────────────
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
    const d = s.entries.find(e => e.seq === s.default);
    const div = document.createElement('div');
    div.className = 'station' + (st.station === s ? ' sel' : '');
    div.innerHTML = `<b>${s.stationId}</b> &middot; ${d.stationType}<br>
      <span class="muted">${d.eventType}<br>${s.updates.length} DENM update(s) in ${s.entries.length} sequenceNumber(s)
      &middot; best trace: seq ${d.seq}, ${d.points} points</span>`;
    div.onclick = () => selectStation(s);
    box.appendChild(div);
  }
}

function selectStation(s) {
  st.station = s;
  renderStations();
  if (view() === 'station') { selectStationRealtime(); return; }
  const sel = $('seq');
  sel.innerHTML = '';
  for (const e of s.entries) {
    const o = document.createElement('option');
    o.value = e.seq;
    o.textContent = `${e.seq} – ${e.points} points in ${e.traces.length} trace(s)${e.terminated ? ' (termination)' : ''}`;
    sel.appendChild(o);
  }
  sel.value = s.default;
  selectEntry(s.entries.find(e => e.seq === s.default));
}

$('seq').onchange = () => selectEntry(st.station.entries.find(e => e.seq === +$('seq').value));

function selectEntry(e) {
  st.entry = e;
  $('seqinfo').textContent = `${e.denms} DENM(s) with this actionId; replay uses the one with most trace points.`;
  const box = $('traces');
  box.innerHTML = '';
  if (!e.traces.length) { box.textContent = 'No traces in this DENM.'; }
  e.traces.forEach((t, i) => {
    const lab = document.createElement('label');
    lab.className = 'opt';
    lab.innerHTML = `<input type="radio" name="trace" value="${i}" ${i === 0 ? 'checked' : ''}>
      trace ${i + 1} – ${t.length} PathPoint(s)`;
    lab.querySelector('input').onchange = () => selectTrace(i);
    box.appendChild(lab);
  });
  selectTrace(0);
}

// ─── Real-time view: all DENMs of the station on the capture clock ─────────
// Every new detectionTime of the station (first reception) is one update with its eventPosition,
// eventPositionHeading, eventSpeed, traces and eventZone.
function selectStationRealtime() {
  pause();
  st.entry = null;
  const s = st.station, U = s.updates;
  st.t0abs = U[0].rx - 1;
  st.total = U[U.length - 1].rx + 1 - st.t0abs;
  st.curIdx = -1;
  const causes = U.filter(u => u.cause).map(u => u.cause);
  st.ref = { pts: U.map(u => ({ lat: u.lat, lon: u.lon, t: u.rx })), t0: U[0].rx, t1: U[U.length - 1].rx,
             cause: causes.length ? causes[causes.length - 1] : null, stationId: s.stationId,
             stationTypeNo: s.stationTypeNo, what: 'eventPositions' };
  const tStr = t => new Date(t * 1000).toISOString().slice(11, 23);
  st.denmPts = U.map((u, i) => {
    const prev = i ? U[i - 1] : null, newSeq = !prev || prev.seq !== u.seq;
    return { id: i, t: u.rx, lat: u.lat, lon: u.lon, hdg: u.hdg,
             lbl: newSeq ? `seq ${u.seq}` : `${(u.rx - prev.rx).toFixed(2)} s`,
             popup: `<b>DENM ${s.stationId}/${u.seq}</b>${u.term ? ' (termination)' : ''}<br>received ${tStr(u.rx)} UTC` +
                    (prev ? `<br>time to previous DENM update: ${(u.rx - prev.rx).toFixed(3)} s` : '') +
                    `<br>${u.eventType}<br>eventPositionHeading ${u.hdg ?? 'n/a'}°` +
                    (u.hdg != null ? ` (confidence ${u.hdgConf === 127 ? 'unavailable' : (u.hdgConf / 10) + '°'})` : '') +
                    `<br>eventSpeed ${u.spd ?? 'n/a'} km/h<br>traces: ${u.traces.map(t => t.length).join('/') || '-'} PathPoints` };
  });
  Object.values(tracks).forEach(tr => tr.reset());
  layers.static.clearLayers(); layers.epHdg.clearLayers(); layers.cur.clearLayers(); layers.ez.clearLayers();

  // Ticks at the start of every sequenceNumber
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
  U.forEach(u => {
    let q = seqs[seqs.length - 1];
    if (!q || q.seq !== u.seq) seqs.push(q = { seq: u.seq, n: 0, from: u.rx, to: u.rx, term: false });
    q.n++; q.to = u.rx; q.term = q.term || u.term;
  });
  $('info').innerHTML = `originatingStationId ${s.stationId}<br>stationType ${s.stationType}<br>
    ${U.length} DENM updates (new detectionTime) from ${tStr(U[0].rx)} to ${tStr(U[U.length - 1].rx)} UTC
    (capture clock)<br>` + seqs.map(q => `seq ${q.seq}: ${q.n} update(s), ${(q.to - q.from).toFixed(1)} s${q.term ? ', terminated' : ''}`).join('<br>');

  updatePreviews();
  applyDisplay();
  st.t = 0;
  rankCams();
  const bounds = L.latLngBounds(U.map(u => [u.lat, u.lon]));
  map.fitBounds(bounds, { padding: [40, 40], maxZoom: 19 });
}

// Current DENM (latest update up to the replay time): its first trace and its eventZone
function renderCurrentDenm(i) {
  if (i === st.curIdx) return;
  st.curIdx = i;
  layers.cur.clearLayers(); layers.ez.clearLayers();
  if (i < 0) return;
  const u = st.station.updates[i];
  for (const tr of u.traces) {
    if (!tr.length) continue;
    L.polyline([[u.lat, u.lon], ...tr.map(q => [q[0], q[1]])], { color: '#ff8a80', weight: 2, opacity: .9, dashArray: '3 5' })
      .addTo(layers.cur);
    tr.forEach(q => L.circleMarker([q[0], q[1]], { radius: 2, stroke: false, fillColor: '#ff8a80', fillOpacity: .9 }).addTo(layers.cur));
  }
  if (u.ez.length) {
    L.polyline([[u.lat, u.lon], ...u.ez], { color: '#12b76a', weight: 4, opacity: .85 }).addTo(layers.ez);
  }
}

function renderStationRealtime() {
  const U = st.station.updates;
  const t = Math.min(Math.max(st.t, 0), st.total), absT = st.t0abs + t;
  const i = lastIdx(U, absT, u => u.rx);
  tracks.denm.update(st.denmPts.slice(0, i + 1), null, opts.denm);
  renderCurrentDenm(i);
  const u = i >= 0 ? U[i] : null;
  setMover(mover, opts.denm.show && u ? u : null);
  $('timeline').value = st.total ? Math.round(t / st.total * 10000) : 0;
  const camTxt = renderCam(absT, u || U[0]);
  const denmTxt = u
    ? `DENM ${st.station.stationId}/${u.seq}${u.term ? ' TERMINATED' : ''}, ${(absT - u.rx).toFixed(1)} s ago, ` +
      `heading ${u.hdg ?? 'n/a'}°, ${u.spd ?? 'n/a'} km/h`
    : 'no DENM yet';
  $('status').textContent = `${t.toFixed(1)} / ${st.total.toFixed(1)} s  ·  ${new Date(absT * 1000).toISOString().slice(11, 23)} UTC  ·  ` +
    denmTxt + camTxt;
}

function selectTrace(i) {
  st.traceIdx = i;
  build();
  rankCams();
  const bounds = L.latLngBounds(st.seqPts.map(p => [p.lat, p.lon]));
  st.entry.eventZone.forEach(p => bounds.extend([p.lat, p.lon]));
  map.fitBounds(bounds, { padding: [40, 40], maxZoom: 19 });
}

// ─── Timeline construction ─────────────────────────────────────────────────
function mode() { return document.querySelector('input[name=mode]:checked').value; }

function build() {
  pause();
  const e = st.entry, ep = e.eventPosition;
  const trace = e.traces[st.traceIdx] || [];
  // PathPoint i (1-based) has pathDeltaTime = travel time to PathPoint i-1 (eventPosition for i = 1).
  // Replay order: PathPoint N ... PathPoint 1, eventPosition.
  const seq = [];
  for (let i = trace.length - 1; i >= 0; i--) seq.push({ ...trace[i], name: `PathPoint ${i + 1}` });
  seq.push({ lat: ep.lat, lon: ep.lon, dt: null, name: 'eventPosition', isEp: true });

  // Estimate missing pathDeltaTimes from the median speed of the known segments.
  const speeds = [];
  for (let k = 0; k < seq.length - 1; k++) {
    const d = haversine(seq[k], seq[k + 1]);
    if (seq[k].dt) speeds.push(d / (seq[k].dt / 100));
  }
  speeds.sort((a, b) => a - b);
  const vMed = speeds.length ? Math.max(speeds[Math.floor(speeds.length / 2)], 0.5) : 10;

  const m = mode(), cap = Math.max(+$('cap').value || 5, 0.1);
  const T = [0], realT = [0];
  for (let k = 0; k < seq.length - 1; k++) {
    const dist = haversine(seq[k], seq[k + 1]);
    seq[k].dist = dist;
    const real = seq[k].dt ? seq[k].dt / 100 : dist / vMed;
    const dur = m === 'points' ? 1 : m === 'compress' ? Math.min(real, cap) : real;
    T.push(T[k] + Math.max(dur, 0.001));
    realT.push(realT[k] + real);
  }
  st.seqPts = seq; st.T = T; st.realT = realT; st.total = T[T.length - 1];
  st.t0abs = e.rx - realT[realT.length - 1];
  st.ref = { pts: seq.map((p, k) => ({ lat: p.lat, lon: p.lon, t: st.t0abs + realT[k] })), t0: st.t0abs, t1: e.rx,
             cause: e.cause, stationId: e.stationId, stationTypeNo: e.stationTypeNo, what: 'trace' };

  // Static layers (shown with the DENM, hidden in its minimal view)
  layers.ez.clearLayers(); layers.static.clearLayers(); layers.epHdg.clearLayers(); layers.cur.clearLayers();
  if (e.heading != null) {
    L.marker([ep.lat, ep.lon], { icon: arrowIcon(e.heading, '#ff3b30'), interactive: false, keyboard: false })
      .addTo(layers.epHdg);
  }
  if (e.eventZone.length) {
    L.polyline([[ep.lat, ep.lon], ...e.eventZone.map(p => [p.lat, p.lon])],
               { color: '#12b76a', weight: 4, opacity: .85 }).addTo(layers.ez);
  }
  L.circleMarker([ep.lat, ep.lon], { radius: 9, color: '#fff', weight: 2, fillColor: '#d92d20', fillOpacity: 1 })
    .bindTooltip(`${e.stationId}/${e.seq} | ${e.eventType}`, { permanent: true, direction: 'top', className: 'ep-lbl', offset: [0, -8] })
    .bindPopup(`<b>eventPosition ${e.stationId}/${e.seq}</b><br>eventPositionHeading ${e.heading ?? 'n/a'}°` +
               (e.heading != null ? ` (confidence ${e.headingConf === 127 ? 'unavailable' : (e.headingConf / 10) + '°'})` : '') +
               `<br>eventSpeed ${e.speed ?? 'n/a'} km/h`)
    .addTo(layers.static);

  st.denmPts = seq.map((p, k) => p.isEp
    ? { id: k, lat: p.lat, lon: p.lon, anchor: true }
    : { id: k, lat: p.lat, lon: p.lon, lbl: p.dt ? `${(p.dt / 100).toFixed(2)} s` : 'n/a',
        popup: `<b>${p.name}</b><br>pathDeltaTime: ${p.dt ?? 'n/a'}${p.dt ? ` (${(p.dt / 100).toFixed(2)} s)` : ' (estimated)'}<br>
                to next point: ${p.dist.toFixed(1)} m${p.dt ? `, ${(p.dist / (p.dt / 100) * 3.6).toFixed(1)} km/h` : ''}` });
  Object.values(tracks).forEach(tr => tr.reset());

  // Ticks
  const ticks = $('ticks');
  ticks.innerHTML = '';
  if (st.total > 0) T.forEach(t => {
    const s = document.createElement('span');
    s.style.left = `${(t / st.total) * 100}%`;
    ticks.appendChild(s);
  });

  const nDt = trace.filter(p => p.dt).length;
  $('info').innerHTML = `actionId ${e.stationId}/${e.seq}<br>stationType ${e.stationType}<br>
    event type ${e.eventType}<br>trace ${st.traceIdx + 1}: ${trace.length} PathPoints,
    ${nDt} with pathDeltaTime<br>recorded travel time ${realT[realT.length - 1].toFixed(1)} s
    ${nDt < trace.length ? '(incl. estimated segments)' : ''}<br>
    replay length at 1x: ${st.total.toFixed(1)} s<br>
    DENM received ${new Date(e.rx * 1000).toISOString().replace('T', ' ').slice(0, 23)} UTC
    (capture clock; the eventPosition is placed at this time)`;

  updatePreviews();
  applyDisplay();
  st.t = 0;
  render();
}

// ─── CAM matching ──────────────────────────────────────────────────────────
// CAM positions are rows [rx time s, lat, lon, speed km/h, heading deg, incident index].
// DENM trace and CAMs share the capture (receiver) clock: the eventPosition is
// placed at the DENM reception time, every PathPoint pathDeltaTime earlier.
const CAM_MAX_GAP = __CAM_MAX_GAP__;   // s; no CAM position is interpolated across larger gaps
const CAM_WINDOW = 5;       // s added before/after the DENM trace time span
const CAM_AUTO_SELECT = 50; // minimum score for the automatic CAM selection
// Special vehicle containers that fit a DENM cause code (no incidentIndication match)
const PLAUSIBLE_CONTAINER = {
  95: ['emergencyContainer', 'rescueContainer', 'safetyCarContainer'],   // emergencyVehicleApproaching
  15: ['emergencyContainer', 'rescueContainer'],                          // rescueAndRecoveryWorkInProgress
  3: ['roadWorksContainerBasic'],                                          // roadworks
  26: ['roadWorksContainerBasic', 'specialTransportContainer', 'safetyCarContainer'],  // slowVehicle
};

// CAM position at time t on the smoothed track (row[6..9]: smoothed lat, lon, velocity
// east, north in m/s, computed in Python); between two CAMs cubic Hermite interpolation
// with the smoothed velocities, so position and direction change continuously.
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
// smooth = false: received positions, linear interpolation (also used for the CAM matching)
function camPosAt(c, t, smooth = false) {
  const P = c.positions;
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
const CAM_SAMPLE = 0.1;   // s between the curve points of the drawn CAM track

const clamp01 = x => Math.max(0, Math.min(1, x));
const median = arr => { const s = [...arr].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

function scoreCam(c) {
  const e = st.ref, P = e.pts;
  const t1 = e.t1, t0 = e.t0;
  const win = c.positions.filter(r => r[0] >= t0 - CAM_WINDOW && r[0] <= t1 + CAM_WINDOW);
  if (!win.length) return null;

  // Trace: distance between each trace point and the CAM position at the same time
  const dists = [];
  P.forEach(p => { const q = camPosAt(c, p.t); if (q) dists.push(haversine(p, q)); });
  let trace, traceTxt;
  if (dists.length >= 2) {
    const med = median(dists);
    trace = clamp01((50 - med) / 45);               // <= 5 m: 1, >= 50 m: 0
    traceTxt = `${e.what} ${med.toFixed(1)} m median (${dists.length} pts at same time)`;
  } else {
    const near = P.map(p => Math.min(...win.map(r => haversine(p, { lat: r[1], lon: r[2] }))));
    const med = median(near);
    trace = 0.5 * clamp01((50 - med) / 45);         // spatial only: half weight
    traceTxt = `${e.what} ${med.toFixed(1)} m median (spatial only)`;
  }

  // Timing: share of the DENM trace time span covered by CAMs of this station
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
  if (!st.camRank.length) { box.textContent = 'No CAMs in the time window of the DENM(s).'; selectCam(null); return; }
  const best = st.camRank[0].score >= CAM_AUTO_SELECT ? st.camRank[0] : null;
  const mk = r => {
    const lab = document.createElement('label');
    lab.className = 'cam';
    lab.innerHTML = r
      ? `<input type="radio" name="cam" ${r === best ? 'checked' : ''}> <span class="swatch" style="background:#1570ef"></span>
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
    // CAM points of the time window with the time to the previous CAM of the station
    const P = r.c.positions, i0 = P.indexOf(r.win[0]);
    // rowsRaw: received positions; rowsSmooth: smoothed track with curve samples ('via') between the
    // CAMs, the markers stay at the received positions (mlat/mlon)
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
               popup: `<b>CAM ${r.c.stationId}</b><br>received ${new Date(row[0] * 1000).toISOString().slice(11, 23)} UTC` +
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

const lastIdx = (arr, t, get = x => x[0]) => {   // index of the last element with time <= t, -1 if none
  let lo = -1, hi = arr.length;
  while (hi - lo > 1) { const m = (lo + hi) >> 1; if (get(arr[m]) <= t) lo = m; else hi = m; }
  return lo;
};

// pathHistory of the latest CAM with low frequency container received up to absT, only the
// part from the replay start (st.t0abs) on. Path entries: [rx, referencePosition lat, lon,
// [[lat, lon, pathDeltaTime], ...]]; pathDeltaTime (10 ms) is the time to the previous point
// (the referencePosition for the first one), so point i was passed at rx - sum(pathDeltaTime 1..i).
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
  const ph = paths[j], out = [];
  let acc = 0;
  ph[3].forEach((p, i) => {
    if (p[2] !== null) acc += p[2] / 100;
    if (ph[0] - acc < st.t0abs) return;
    out.push({ id: `${ph[0]}:${i}`, lat: p[0], lon: p[1],
               lbl: p[2] !== null ? `${(p[2] / 100).toFixed(2)} s` : 'n/a',
               popup: `<b>CAM ${r.c.stationId} pathHistory point ${i + 1}</b><br>pathDeltaTime: ${p[2] ?? 'n/a'}` +
                      (p[2] !== null ? ` (${(p[2] / 100).toFixed(2)} s)` : '') + `<br>${acc.toFixed(2)} s before the CAM` });
  });
  out.reverse();
  if (ph[0] >= st.t0abs) out.push({ id: `${ph[0]}:ref`, lat: ph[1], lon: ph[2], anchor: true });
  return { pts: out, ph };
}

const camRows = r => opts.cam.smooth ? r.rowsSmooth : r.rowsRaw;

// Full previews = what each layer shows at the end of the replay
function updatePreviews() {
  const r = st.cam;
  tracks.denm.setPreview(view() === 'station' && st.station ? st.station.updates.map(u => [u.lat, u.lon])
                                                         : st.seqPts.map(p => [p.lat, p.lon]));
  tracks.cam.setPreview(r ? camRows(r).map(p => [p.lat, p.lon]) : []);
  tracks.ph.setPreview(r && st.ref ? phPoints(r, st.ref.t1).pts.map(p => [p.lat, p.lon]) : []);
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
      txt += `  ·  CAM ${r.c.stationId} ${haversine(cpos, denmPos).toFixed(1)} m from DENM position${spd ? ', ' + spd : ''}`;
    } else txt += `  ·  CAM ${r.c.stationId}: no CAM at this time`;
  }
  // pathHistory
  const php = phPoints(r, absT);
  tracks.ph.update(php.pts, null, op);
  const issues = op.show && php.ph ? phIssues(php.ph) : [];
  showPhWarning(issues.length ? `CAM ${r.c.stationId} received ${new Date(php.ph[0] * 1000).toISOString().slice(11, 23)} UTC: ` +
                                issues.join('; ') : null);
  if (op.show) {
    const n = php.pts.filter(p => !p.anchor).length;
    txt += php.ph ? `  ·  pathHistory ${n} of ${php.ph[3].length} pts since replay start` : '  ·  pathHistory: none yet';
  }
  return txt;
}

// ─── Rendering at replay time t ────────────────────────────────────────────
function render() {
  if (view() === 'station') { if (st.station) renderStationRealtime(); return; }
  const { seqPts: P, T } = st;
  if (!P.length) return;
  const t = Math.min(Math.max(st.t, 0), st.total);
  let k = 0;
  while (k < T.length - 2 && T[k + 1] <= t) k++;
  const f = T[k + 1] > T[k] ? Math.min((t - T[k]) / (T[k + 1] - T[k]), 1) : 1;
  const done = t >= st.total;
  const a = P[k], b = P[Math.min(k + 1, P.length - 1)];
  const pos = done ? b : { lat: a.lat + (b.lat - a.lat) * f, lon: a.lon + (b.lon - a.lon) * f };
  const reached = done ? P.length - 1 : k;

  tracks.denm.update(st.denmPts.slice(0, reached + 1), done ? null : pos, opts.denm);
  setMover(mover, opts.denm.show ? pos : null);

  const realNow = st.realT[k] + (st.realT[Math.min(k + 1, st.realT.length - 1)] - st.realT[k]) * (done ? 1 : f);
  $('timeline').value = st.total ? Math.round(t / st.total * 10000) : 0;
  const camTxt = renderCam(st.t0abs + realNow, pos);
  $('status').textContent = `replay ${t.toFixed(1)} / ${st.total.toFixed(1)} s  ·  recorded ${realNow.toFixed(1)} s  ·  ` +
    (done ? 'eventPosition reached' : `${a.name} → ${b.name}`) + camTxt;
}

function applyDisplay() {
  for (const [k, tr] of Object.entries(tracks)) {
    const o = opts[k];
    o.show ? tr.group.addTo(map) : map.removeLayer(tr.group);
    o.show && o.preview ? tr.previewGroup.addTo(map) : map.removeLayer(tr.previewGroup);
  }
  // minimal DENM view: no eventPosition marker / current trace / eventZone
  const d = opts.denm, full = d.show && !d.minimal, rt = view() === 'station';
  full && !rt ? layers.static.addTo(map) : map.removeLayer(layers.static);
  full && !rt && d.heading ? layers.epHdg.addTo(map) : map.removeLayer(layers.epHdg);
  full && rt ? layers.cur.addTo(map) : map.removeLayer(layers.cur);
  full && d.ez ? layers.ez.addTo(map) : map.removeLayer(layers.ez);
  $('traceSel').classList.toggle('hidden', rt);
  $('modeSel').classList.toggle('hidden', rt);
  document.querySelectorAll('.layer').forEach(el => el.classList.toggle('off', !opts[el.dataset.layer].show));
}

// ─── Layer option cards ────────────────────────────────────────────────────
function renderLayerCards() {
  const box = $('layercards');
  box.innerHTML = '';
  for (const [k, d] of Object.entries(LAYERS)) {
    const o = opts[k], div = document.createElement('div');
    div.className = 'layer';
    div.dataset.layer = k;
    const cb = (opt, text) => `<label><input type="checkbox" data-opt="${opt}" ${o[opt] ? 'checked' : ''}> ${text}</label>`;
    const rt = k === 'denm' && view() === 'station';
    const sub = rt ? 'eventPositions of all DENMs' : d.sub, lbl = rt ? 'time to prev. DENM' : d.lblText;
    const extras = k === 'denm' ? cb('ez', 'eventZone') + cb('heading', 'eventPositionHeading')
                 : k === 'cam' ? cb('smooth', 'smoothing') + cb('heading', 'heading') : '';
    div.innerHTML = `
      <label class="lhead"><input type="checkbox" data-opt="show" ${o.show ? 'checked' : ''}>
        <span class="swatch" style="background:${d.color}"></span>${d.title}<span class="muted">${sub}</span></label>
      <div class="lopts">
        ${cb('points', 'points')}${cb('labels', lbl)}
        ${cb('preview', 'full preview')}${extras}
        <div class="minrow">${cb('minimal', 'minimal: last')}
          <input type="range" data-opt="n" min="1" max="${MINIMAL_MAX}" value="${o.n}" ${o.minimal ? '' : 'disabled'}>
          <span class="nval">${o.n}</span> points</div>
      </div>`;
    div.querySelectorAll('input').forEach(inp => inp.oninput = () => {
      const opt = inp.dataset.opt;
      if (opt === 'n') { o.n = +inp.value; div.querySelector('.nval').textContent = o.n; }
      else o[opt] = inp.checked;
      if (opt === 'minimal') div.querySelector('input[data-opt=n]').disabled = !o.minimal;
      if (['points', 'labels', 'smooth', 'heading'].includes(opt)) tracks[k].reset();
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
$('restart').onclick = () => { st.t = 0; render(); };
$('timeline').oninput = () => { st.t = $('timeline').value / 10000 * st.total; render(); };
$('speed').oninput = () => {
  st.speed = Math.pow(10, +$('speed').value);
  $('speedval').textContent = (st.speed < 10 ? st.speed.toFixed(1) : st.speed.toFixed(0)) + 'x';
};
document.querySelectorAll('input[name=mode]').forEach(r => r.onchange = () => {
  const frac = st.total ? st.t / st.total : 0;
  build(); st.t = frac * st.total; render();
});
$('cap').onchange = () => { if (mode() === 'compress') { const frac = st.t / st.total; build(); st.t = frac * st.total; render(); } };
// Reset view: layer options, replay mode and pause cap back to the defaults
$('resetView').onclick = () => {
  for (const [k, d] of Object.entries(LAYERS)) { Object.assign(opts[k], d.def); tracks[k].reset(); }
  renderLayerCards();
  const modeChanged = mode() !== 'real' || +$('cap').value !== 5;
  document.querySelector('input[name=mode][value=real]').checked = true;
  $('cap').value = 5;
  if (modeChanged && st.entry) { const frac = st.total ? st.t / st.total : 0; build(); st.t = frac * st.total; }
  applyDisplay();
  render();
};
document.querySelector(`input[name=view][value=${DATA.view}]`).checked = true;
document.querySelectorAll('input[name=view]').forEach(r => r.onchange = () => {
  pause();
  renderLayerCards();
  applyDisplay();
  if (st.station) selectStation(st.station);
});
renderLayerCards();
renderFilter();
renderStations();
const pre = DATA.preselect && DATA.stations.find(s => s.stationId === DATA.preselect.station);
if (pre) {
  if (!stFilter.has(pre.stationTypeNo)) {
    stFilter.add(pre.stationTypeNo);
    $('stfilter').querySelector(`input[data-st="${pre.stationTypeNo}"]`).checked = true;
  }
  selectStation(pre);
  if (view() === 'trace' && DATA.preselect.seq !== null && pre.entries.some(e => e.seq === DATA.preselect.seq)) {
    $('seq').value = DATA.preselect.seq;
    selectEntry(pre.entries.find(e => e.seq === DATA.preselect.seq));
  }
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
        description='Replay DENM traces on a satellite map (self-contained HTML page).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('pcap', nargs='+', metavar='PCAP',
                        help='Input PCAP file(s); wildcards such as *.pcap are expanded')
    parser.add_argument('-o', '--output', default='denm_replay.html', metavar='FILE',
                        help='Output HTML file (default: denm_replay.html)')
    parser.add_argument('--station', type=int, metavar='ID',
                        help='Preselect this originatingStationId in the page')
    parser.add_argument('--seq', type=int, metavar='N',
                        help='Preselect this sequenceNumber (with --station)')
    parser.add_argument('--view', choices=['station', 'trace'],
                        help='Initial view: all DENMs of the station in real time (default) or the '
                             'trace replay of a single DENM (default with --seq)')
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

    data = {
        'source': ', '.join(Path(p).name for p in expand_pcaps(args.pcap)),
        'stations': stations,
        'cams': cams,
        'preselect': ({'station': args.station, 'seq': args.seq}
                      if args.station is not None else None),
        'view': args.view or ('trace' if args.seq is not None else 'station'),
    }
    out = args.output if args.output.endswith('.html') else args.output + '.html'
    html = (HTML_TEMPLATE.replace('__RSU__', str(RSU_STATION_TYPE))
            .replace('__CAM_MAX_GAP__', str(CAM_MAX_GAP))
            .replace('__DATA__', json.dumps(data).replace('</', '<\\/')))
    Path(out).write_text(html, encoding='utf-8')
    print(f'\nOutput written to: {out}')
    if not args.no_open:
        webbrowser.open(Path(out).resolve().as_uri())


if __name__ == '__main__':
    main()
