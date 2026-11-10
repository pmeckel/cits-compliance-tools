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
The eventZone is shown in green, the full trace faintly as a preview.

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
  - optional (toggle): the pathHistory of the low frequency container of the
    latest CAM received up to the current replay time (purple)

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
  .ph-lbl { background:#7a5af8; color:#fff; border:none; font-size:11px; padding:1px 4px; }
  .ph-lbl::before { display:none; }
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
    <label class="opt"><input type="checkbox" id="showCam" checked> show CAM in parallel</label>
    <label class="opt"><input type="checkbox" id="showCamPreview" checked> full CAM track in the DENM time window</label>
    <label class="opt"><input type="checkbox" id="showCamPath"> CAM pathHistory (latest low frequency container)</label>
    <h2>Replay mode</h2>
    <label class="opt"><input type="radio" name="mode" value="real" checked> Real time (pathDeltaTime)</label>
    <label class="opt"><input type="radio" name="mode" value="compress"> Real time, compress pauses</label>
    <div class="row" style="padding-left:22px"><span class="muted">cap per segment (s)</span>
      <input type="number" id="cap" value="5" min="0.1" step="0.5" style="width:70px"></div>
    <label class="opt"><input type="radio" name="mode" value="points"> Point by point (1 s per point at 1x)</label>
    <h2>Display</h2>
    <label class="opt"><input type="checkbox" id="showLabels" checked> pathDeltaTime labels</label>
    <label class="opt"><input type="checkbox" id="showPreview" checked> full trace preview</label>
    <label class="opt"><input type="checkbox" id="showEz" checked> eventZone</label>
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

const layers = { preview: L.layerGroup().addTo(map), ez: L.layerGroup().addTo(map),
                 points: L.layerGroup().addTo(map), static: L.layerGroup().addTo(map) };
let drawn = L.polyline([], { color: '#ff3b30', weight: 4 }).addTo(map);
let mover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillColor: '#ff3b30', fillOpacity: 1 });

const camLayers = { preview: L.layerGroup().addTo(map), path: L.layerGroup().addTo(map) };
let camPathShown = null;   // pathHistory entry currently drawn
const camDrawn = L.polyline([], { color: '#2e90fa', weight: 4 }).addTo(map);
const camMover = L.circleMarker([0, 0], { radius: 7, color: '#fff', weight: 2, fillColor: '#1570ef', fillOpacity: 1 })
  .bindTooltip('', { permanent: true, direction: 'left', className: 'cam-lbl', offset: [-8, 0] });

// t0abs: reception time (s) of the last trace point, so that the eventPosition is at the DENM reception time
const st = { station: null, entry: null, traceIdx: 0, seqPts: [], T: [], realT: [], markers: [],
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

  // Static layers
  layers.preview.clearLayers(); layers.ez.clearLayers(); layers.points.clearLayers(); layers.static.clearLayers();
  L.polyline(seq.map(p => [p.lat, p.lon]), { color: '#ffffff', weight: 2, opacity: .6, dashArray: '4 6' })
    .addTo(layers.preview);
  if (e.eventZone.length) {
    L.polyline([[ep.lat, ep.lon], ...e.eventZone.map(p => [p.lat, p.lon])],
               { color: '#12b76a', weight: 4, opacity: .85 }).addTo(layers.ez);
  }
  L.circleMarker([ep.lat, ep.lon], { radius: 9, color: '#fff', weight: 2, fillColor: '#d92d20', fillOpacity: 1 })
    .bindTooltip(`${e.stationId}/${e.seq} | ${e.eventType}`, { permanent: true, direction: 'top', className: 'ep-lbl', offset: [0, -8] })
    .addTo(layers.static);

  st.markers = seq.map((p, k) => {
    if (p.isEp) return null;
    const label = p.dt ? `${(p.dt / 100).toFixed(2)} s` : 'n/a';
    return L.circleMarker([p.lat, p.lon], { radius: 5, color: '#fff', weight: 1.5, fillColor: '#ffb020', fillOpacity: 1 })
      .bindTooltip(label, { permanent: true, direction: 'right', className: 'lbl', offset: [6, 0] })
      .bindPopup(`<b>${p.name}</b><br>pathDeltaTime: ${p.dt ?? 'n/a'}${p.dt ? ` (${(p.dt / 100).toFixed(2)} s)` : ' (estimated)'}<br>
                  to next point: ${p.dist.toFixed(1)} m${p.dt ? `, ${(p.dist / (p.dt / 100) * 3.6).toFixed(1)} km/h` : ''}`);
  });

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
  camLayers.preview.clearLayers();
  camLayers.path.clearLayers(); camPathShown = null;
  if (r) {
    L.polyline(r.win.map(p => [p[1], p[2]]), { color: '#84caff', weight: 2, opacity: .8, dashArray: '2 6' })
      .addTo(camLayers.preview);
  }
  applyDisplay();
  render();
}

// pathHistory of the latest CAM with low frequency container received up to absT.
// Entries: [rx, referencePosition lat, lon, [[lat, lon, pathDeltaTime], ...]].
// pathDeltaTime (10 ms) is the time to the previous point (the referencePosition for the first one).
function renderCamPath(absT) {
  const r = st.cam;
  const paths = r && $('showCam').checked && $('showCamPath').checked ? (r.c.paths || []) : [];
  let lo = -1, hi = paths.length;
  while (hi - lo > 1) { const m = (lo + hi) >> 1; if (paths[m][0] <= absT) lo = m; else hi = m; }
  const ph = lo >= 0 ? paths[lo] : null;
  if (ph !== camPathShown) {
    camPathShown = ph;
    camLayers.path.clearLayers();
    if (ph) {
      const pts = [[ph[1], ph[2]], ...ph[3].map(p => [p[0], p[1]])];
      L.polyline(pts, { color: '#9e77ed', weight: 3, opacity: .95 }).addTo(camLayers.path);
      let acc = 0;
      ph[3].forEach((p, i) => {
        if (p[2] !== null) acc += p[2] / 100;
        L.circleMarker([p[0], p[1]], { radius: 4, color: '#fff', weight: 1, fillColor: '#7a5af8', fillOpacity: 1 })
          .bindPopup(`<b>CAM ${r.c.stationId} pathHistory point ${i + 1}</b><br>pathDeltaTime: ${p[2] ?? 'n/a'}` +
                     (p[2] !== null ? ` (${(p[2] / 100).toFixed(2)} s)` : '') +
                     `<br>${acc.toFixed(2)} s before the CAM`)
          .addTo(camLayers.path);
      });
      if (ph[3].length) {
        const lastP = ph[3][ph[3].length - 1];
        L.circleMarker([lastP[0], lastP[1]], { radius: 0, opacity: 0 })
          .bindTooltip(`pathHistory ${ph[3].length} pts, ${acc.toFixed(1)} s`,
                       { permanent: true, direction: 'right', className: 'ph-lbl', offset: [6, 0] })
          .addTo(camLayers.path);
      }
    }
  }
  return ph ? `  ·  pathHistory ${ph[3].length} pts from CAM ${(absT - ph[0]).toFixed(1)} s ago` : '';
}

function renderCam(absT, denmPos) {
  const r = st.cam, show = r && $('showCam').checked;
  const phTxt = renderCamPath(absT);
  if (!show) {
    camDrawn.setLatLngs([]);
    if (map.hasLayer(camMover)) map.removeLayer(camMover);
    return '';
  }
  const past = r.win.filter(p => p[0] <= absT).map(p => [p[1], p[2]]);
  const q = camPosAt(r.c, absT);
  if (q) past.push([q.lat, q.lon]);
  camDrawn.setLatLngs(past);
  if (!q) {
    if (map.hasLayer(camMover)) map.removeLayer(camMover);
    return `  ·  CAM ${r.c.stationId}: no CAM at this time` + phTxt;
  }
  camMover.setLatLng([q.lat, q.lon]);
  if (!map.hasLayer(camMover)) camMover.addTo(map);
  const spd = q.row[3] !== null ? `${q.row[3].toFixed(0)} km/h` : '';
  camMover.setTooltipContent(`CAM ${r.c.stationId} ${spd}`);
  return `  ·  CAM ${r.c.stationId} ${haversine(q, denmPos).toFixed(1)} m from DENM position${spd ? ', ' + spd : ''}` + phTxt;
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

  drawn.setLatLngs([...P.slice(0, reached + 1).map(p => [p.lat, p.lon]), [pos.lat, pos.lon]]);
  mover.setLatLng([pos.lat, pos.lon]);
  if (!map.hasLayer(mover)) mover.addTo(map);

  st.markers.forEach((mk, i) => {
    if (!mk) return;
    const show = i <= reached;
    if (show && !layers.points.hasLayer(mk)) layers.points.addLayer(mk);
    if (!show && layers.points.hasLayer(mk)) layers.points.removeLayer(mk);
  });

  const realNow = st.realT[k] + (st.realT[Math.min(k + 1, st.realT.length - 1)] - st.realT[k]) * (done ? 1 : f);
  $('timeline').value = st.total ? Math.round(t / st.total * 10000) : 0;
  const camTxt = renderCam(st.t0abs + realNow, pos);
  $('status').textContent = `replay ${t.toFixed(1)} / ${st.total.toFixed(1)} s  ·  recorded ${realNow.toFixed(1)} s  ·  ` +
    (done ? 'eventPosition reached' : `${a.name} → ${b.name}`) + camTxt;
}

function applyDisplay() {
  const lbl = $('showLabels').checked;
  st.markers.forEach(mk => mk && (lbl ? mk.openTooltip() : mk.closeTooltip()));
  document.querySelectorAll('.lbl').forEach(el => el.style.display = lbl ? '' : 'none');
  $('showPreview').checked ? layers.preview.addTo(map) : map.removeLayer(layers.preview);
  $('showEz').checked ? layers.ez.addTo(map) : map.removeLayer(layers.ez);
  $('showCam').checked && $('showCamPreview').checked ? camLayers.preview.addTo(map) : map.removeLayer(camLayers.preview);
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
['showLabels', 'showPreview', 'showEz', 'showCamPreview'].forEach(id => $(id).onchange = applyDisplay);
$('showCam').onchange = () => { applyDisplay(); render(); };
$('showCamPath').onchange = () => render();
layers.points.on('layeradd', ev => { if (!$('showLabels').checked) ev.layer.closeTooltip(); });

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
