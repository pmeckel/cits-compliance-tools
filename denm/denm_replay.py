#!/usr/bin/env python3
"""
DENM Trace Replay

Reads one or more PCAP files, decodes all DENMs and writes a self-contained
HTML page (Leaflet + Esri World Imagery satellite map, online) that replays a
DENM trace (location.detectionZonesToEventPosition) from its last PathPoint
towards the eventPosition.

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
A warning banner "CAM pathHistory inconsistent / broken" is shown while the
received pathHistory has a point with pathDeltaTime 0 or a step of more than
50 m at more than 250 km/h; the pathHistory is still drawn as received.

Reuses PCAP parsing, ASN.1 compilation and DENM extraction from denm_count.py,
the event type text from denm_common.py and the delta position helper from
denm_to_kml.py.

Usage:
    python denm_replay.py TrafficManager.pcap
    python denm_replay.py ../test-data/DENM*.pcap -o replay.html
    python denm_replay.py capture.pcap --no-open
"""

import argparse
import json
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
    (the caller appends the incident index as row[5])
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
            cand['rx'] = round(first_rx.setdefault(det_key, rx), 3)
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
                       'stationType': default['stationType'], 'entries': entries})

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
<title>DENM Trace Replay</title>
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
    <h1>DENM Trace Replay</h1>
    <div class="muted" id="src"></div>
    <h2>stationType filter</h2>
    <div id="stfilter"></div>
    <h2>originatingStationId</h2>
    <div id="stations"></div>
    <h2>sequenceNumber</h2>
    <select id="seq"></select>
    <div class="muted" id="seqinfo"></div>
    <h2>Trace</h2>
    <div id="traces"></div>
    <h2>CAM match</h2>
    <div id="cams" class="muted"></div>
    <h2>Visualize</h2>
    <div id="layercards"></div>
    <button id="resetView" title="Layer options and replay mode back to the defaults">Reset view</button>
    <h2>Replay mode</h2>
    <label class="opt"><input type="radio" name="mode" value="real" checked> Real time (pathDeltaTime)</label>
    <label class="opt"><input type="radio" name="mode" value="compress"> Real time, compress pauses</label>
    <div class="row" style="padding-left:22px"><span class="muted">cap per segment (s)</span>
      <input type="number" id="cap" value="5" min="0.1" step="0.5" style="width:70px"></div>
    <label class="opt"><input type="radio" name="mode" value="points"> Point by point (1 s per point at 1x)</label>
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
const layers = { ez: L.layerGroup().addTo(map), static: L.layerGroup().addTo(map) };
const mover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillColor: '#ff3b30', fillOpacity: 1 });
const camMover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillColor: '#1570ef', fillOpacity: 1 })
  .bindTooltip('', { permanent: true, direction: 'left', className: 'cam-lbl', offset: [-8, 0] });

// ─── Visualized layers: DENM trace, CAM track, CAM pathHistory ─────────────
// Every layer has the same options: show, points (off = line only), time labels,
// full preview, minimal view (only the last n points).
const LAYERS = {
  denm: { title: 'DENM', sub: 'trace PathPoints', color: '#ff3b30', fill: '#ffb020', preview: '#ffffff',
          lblClass: 'lbl', lblText: 'pathDeltaTime',
          def: { show: true, points: true, labels: true, preview: false, minimal: true, n: 8, ez: true } },
  cam:  { title: 'CAM', sub: 'positions of the matched CAM station', color: '#2e90fa', fill: '#84caff', preview: '#84caff',
          lblClass: 'campt-lbl', lblText: 'time to prev. CAM',
          def: { show: true, points: true, labels: false, preview: false, minimal: true, n: 15 } },
  ph:   { title: 'CAM pathHistory', sub: 'from replay start', color: '#7cfc00', fill: '#3f9c0a', preview: '#c5f6a0',
          lblClass: 'ph-lbl', lblText: 'pathDeltaTime',
          def: { show: true, points: true, labels: false, preview: false, minimal: true, n: 15 } },
};
const MINIMAL_MAX = 40;
const opts = Object.fromEntries(Object.entries(LAYERS).map(([k, d]) => [k, { ...d.def }]));

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
      let c = 0, i = pts.length;
      while (i > 0 && (pts[i - 1].anchor || c < o.n)) { if (!pts[i - 1].anchor) c++; i--; }
      vis = pts.slice(i);
    }
    this.line.setLatLngs([...vis.map(p => [p.lat, p.lon]), ...(head ? [[head.lat, head.lon]] : [])]);
    const want = new Set((o.points || o.labels) ? vis.filter(p => !p.anchor).map(p => p.id) : []);
    for (const [id, m] of this.markers) if (!want.has(id)) { this.group.removeLayer(m); this.markers.delete(id); }
    for (const p of vis) {
      if (!want.has(p.id) || this.markers.has(p.id)) continue;
      const m = o.points
        ? L.circleMarker([p.lat, p.lon], { radius: 4.5, color: '#fff', weight: 1.5, fillColor: this.d.fill, fillOpacity: 1 })
        : L.circleMarker([p.lat, p.lon], { radius: 2, stroke: false, fillOpacity: 0 });
      if (p.popup) m.bindPopup(p.popup);
      if (o.labels && p.lbl) m.bindTooltip(p.lbl, { permanent: true, direction: 'right', className: this.d.lblClass, offset: [6, 0] });
      this.group.addLayer(m);
      this.markers.set(p.id, m);
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

// t0abs: reception time (s) of the last trace point, so that the eventPosition is at the DENM reception time
const st = { station: null, entry: null, traceIdx: 0, seqPts: [], denmPts: [], T: [], realT: [],
             t: 0, total: 0, playing: false, speed: 1, last: null, t0abs: 0, cam: null, camRank: [] };

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
      <span class="muted">${d.eventType}<br>best: seq ${d.seq}, ${d.points} trace points
      &middot; ${s.entries.length} sequenceNumber(s)</span>`;
    div.onclick = () => selectStation(s);
    box.appendChild(div);
  }
}

function selectStation(s) {
  st.station = s;
  renderStations();
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

  // Static layers (shown with the DENM, hidden in its minimal view)
  layers.ez.clearLayers(); layers.static.clearLayers();
  if (e.eventZone.length) {
    L.polyline([[ep.lat, ep.lon], ...e.eventZone.map(p => [p.lat, p.lon])],
               { color: '#12b76a', weight: 4, opacity: .85 }).addTo(layers.ez);
  }
  L.circleMarker([ep.lat, ep.lon], { radius: 9, color: '#fff', weight: 2, fillColor: '#d92d20', fillOpacity: 1 })
    .bindTooltip(`${e.stationId}/${e.seq} | ${e.eventType}`, { permanent: true, direction: 'top', className: 'ep-lbl', offset: [0, -8] })
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
const CAM_MAX_GAP = 3;      // s; no CAM position is interpolated across larger gaps
const CAM_WINDOW = 5;       // s added before/after the DENM trace time span
const CAM_AUTO_SELECT = 50; // minimum score for the automatic CAM selection
// Special vehicle containers that fit a DENM cause code (no incidentIndication match)
const PLAUSIBLE_CONTAINER = {
  95: ['emergencyContainer', 'rescueContainer', 'safetyCarContainer'],   // emergencyVehicleApproaching
  15: ['emergencyContainer', 'rescueContainer'],                          // rescueAndRecoveryWorkInProgress
  3: ['roadWorksContainerBasic'],                                          // roadworks
  26: ['roadWorksContainerBasic', 'specialTransportContainer', 'safetyCarContainer'],  // slowVehicle
};

function camPosAt(c, t) {
  const P = c.positions;
  if (!P.length || t < P[0][0] - 1 || t > P[P.length - 1][0] + 1) return null;
  let lo = 0, hi = P.length - 1;
  while (hi - lo > 1) { const m = (lo + hi) >> 1; if (P[m][0] <= t) lo = m; else hi = m; }
  const a = P[lo], b = P[hi];
  if (t <= a[0]) return { lat: a[1], lon: a[2], row: a };
  if (t >= b[0]) return { lat: b[1], lon: b[2], row: b };
  if (b[0] - a[0] > CAM_MAX_GAP) return null;
  const f = (t - a[0]) / (b[0] - a[0]);
  return { lat: a[1] + (b[1] - a[1]) * f, lon: a[2] + (b[2] - a[2]) * f, row: f < .5 ? a : b };
}

const clamp01 = x => Math.max(0, Math.min(1, x));
const median = arr => { const s = [...arr].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

function scoreCam(c) {
  const e = st.entry, P = st.seqPts;
  const t1 = e.rx, t0 = st.t0abs;
  const win = c.positions.filter(r => r[0] >= t0 - CAM_WINDOW && r[0] <= t1 + CAM_WINDOW);
  if (!win.length) return null;

  // Trace: distance between each trace point and the CAM position at the same time
  const dists = [];
  P.forEach((p, k) => { const q = camPosAt(c, t0 + st.realT[k]); if (q) dists.push(haversine(p, q)); });
  let trace, traceTxt;
  if (dists.length >= 2) {
    const med = median(dists);
    trace = clamp01((50 - med) / 45);               // <= 5 m: 1, >= 50 m: 0
    traceTxt = `trace ${med.toFixed(1)} m median (${dists.length} pts at same time)`;
  } else {
    const near = P.map(p => Math.min(...win.map(r => haversine(p, { lat: r[1], lon: r[2] }))));
    const med = median(near);
    trace = 0.5 * clamp01((50 - med) / 45);         // spatial only: half weight
    traceTxt = `trace ${med.toFixed(1)} m median (spatial only)`;
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
  if (!st.camRank.length) { box.textContent = 'No CAMs in the time window of this DENM trace.'; selectCam(null); return; }
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
    r.rows = r.win.map((row, i) => {
      const prev = P[i0 + i - 1];
      const dt = prev ? row[0] - prev[0] : null;
      return { id: row[0], lat: row[1], lon: row[2], row,
               lbl: dt !== null ? `${dt.toFixed(2)} s` : 'n/a',
               popup: `<b>CAM ${r.c.stationId}</b><br>received ${new Date(row[0] * 1000).toISOString().slice(11, 23)} UTC` +
                      `<br>time to previous CAM: ${dt !== null ? dt.toFixed(3) + ' s' : 'n/a'}` +
                      `<br>speed ${row[3] ?? 'n/a'} km/h, heading ${row[4] ?? 'n/a'}°` };
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

// Full previews = what each layer shows at the end of the replay
function updatePreviews() {
  const r = st.cam;
  tracks.denm.setPreview(st.seqPts.map(p => [p.lat, p.lon]));
  tracks.cam.setPreview(r ? r.win.map(p => [p[1], p[2]]) : []);
  tracks.ph.setPreview(r && st.entry ? phPoints(r, st.entry.rx).pts.map(p => [p.lat, p.lon]) : []);
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
  // CAM track: received CAMs up to absT; head = interpolated position (minimal view: latest received CAM)
  const pts = r.rows.slice(0, lastIdx(r.rows, absT, x => x.id) + 1);
  const q = camPosAt(r.c, absT);
  tracks.cam.update(pts, oc.minimal ? null : q, oc);
  const latest = pts.length ? pts[pts.length - 1] : null;
  const cpos = oc.minimal ? latest : q;
  setMover(camMover, oc.show ? cpos : null);
  if (oc.show) {
    if (cpos) {
      const row = oc.minimal ? latest.row : q.row;
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
  const d = opts.denm, full = d.show && !d.minimal;   // minimal DENM view: no eventPosition / eventZone
  full ? layers.static.addTo(map) : map.removeLayer(layers.static);
  full && d.ez ? layers.ez.addTo(map) : map.removeLayer(layers.ez);
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
    div.innerHTML = `
      <label class="lhead"><input type="checkbox" data-opt="show" ${o.show ? 'checked' : ''}>
        <span class="swatch" style="background:${d.color}"></span>${d.title}<span class="muted">${d.sub}</span></label>
      <div class="lopts">
        ${cb('points', 'points')}${cb('labels', d.lblText)}
        ${cb('preview', 'full preview')}${k === 'denm' ? cb('ez', 'eventZone') : '<span></span>'}
        <div class="minrow">${cb('minimal', 'minimal: last')}
          <input type="range" data-opt="n" min="1" max="${MINIMAL_MAX}" value="${o.n}" ${o.minimal ? '' : 'disabled'}>
          <span class="nval">${o.n}</span> points</div>
      </div>`;
    div.querySelectorAll('input').forEach(inp => inp.oninput = () => {
      const opt = inp.dataset.opt;
      if (opt === 'n') { o.n = +inp.value; div.querySelector('.nval').textContent = o.n; }
      else o[opt] = inp.checked;
      if (opt === 'minimal') div.querySelector('input[data-opt=n]').disabled = !o.minimal;
      if (opt === 'points' || opt === 'labels') tracks[k].reset();
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
  if (!st.entry) return;
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
  if (DATA.preselect.seq !== null && pre.entries.some(e => e.seq === DATA.preselect.seq)) {
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
    }
    out = args.output if args.output.endswith('.html') else args.output + '.html'
    html = (HTML_TEMPLATE.replace('__RSU__', str(RSU_STATION_TYPE))
            .replace('__DATA__', json.dumps(data).replace('</', '<\\/')))
    Path(out).write_text(html, encoding='utf-8')
    print(f'\nOutput written to: {out}')
    if not args.no_open:
        webbrowser.open(Path(out).resolve().as_uri())


if __name__ == '__main__':
    main()
