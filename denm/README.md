# DENM Tools

Python tools for parsing, counting and visualizing **DENM** (Decentralized
Environmental Notification Message) captures from ITS-G5 PCAP files.

Applicable base specification:
- **ETSI EN 302 637-3** — DENM message format (release 2, `protocolVersion` 2)

> **Status:** basic DENM support and tooling only. Compliance checkers against
> C-ROADS / C2C-CC use cases (e.g. HLN-AZ, RWW) are *planned* and will live in
> their own use-case subfolders, like the IVIM checkers in [`../ivim/`](../ivim/).

The tools in this folder are **use-case-agnostic**: they work on any DENM,
regardless of which use case it implements.

---

## DENM geometry in a nutshell

The DENM counterpart of the IVIM `referencePosition` is the
`management.eventPosition`. All zones are delta positions, cumulative from the
eventPosition (the first point is relative to the eventPosition, every further
point relative to the previous one).

| Zone | DENM element | IVIM counterpart | One item is … |
|------|--------------|------------------|---------------|
| Detection zone | `location.detectionZonesToEventPosition` (**traces**) | detection zone | one *trace* = one `Path`; its points are the `Path` items |
| Relevance zone | `situation.eventZone` (only one) | relevance zone | one `EventPoint` |
| Awareness area | `management.awarenessDistance` | awareness zone | an upper bound `lessThanXm` around the eventPosition |

Three event types are distinguished:

| Event type | eventPosition | traces | eventZone | awarenessDistance |
|------------|---------------|--------|-----------|-------------------|
| Point event | present | present | absent | absent |
| Linear event | present | present | present | absent |
| Circular event | present | present | absent | present |

The **event type** (`situation.eventType`, optional `linkedCause`) is shown by all
tools as cause and sub cause, each as name and code, e.g.
`roadworks(3) shortTermStationaryRoadworks(4)`. The names are read directly from
`ASN/ETSI-ITS-CDD.asn` (see `denm_common.py`), so they follow the CDD version in
use. Sub cause codes without a name in the CDD are shown as `unknown(n)`; causes
without named sub causes (e.g. `aquaplaning(7)`) show `unnamed(n)`; DENMs
without situation container (terminations) show `n/a (no situation container)`.

A DENM is identified by its **actionId** (`originatingStationId` +
`sequenceNumber`). All tools deduplicate by actionId.

---

## Tools

### `denm_count.py` — DENM and actionId counter

Counts the DENMs in one or more PCAPs and the unique actionIds, with the
number of DENMs and the event type per actionId, plus a summary per event type.

```bash
python denm_count.py capture.pcap
python denm_count.py ../test-data/DENM1.pcap ../test-data/DENM2.pcap
```

```
  originatingStationId  sequenceNumber   DENMs  event type: cause(code) subcause(code)
  ------------------------------------------------------------------------------------------
               1021000             553     105  roadworks(3) shortTermStationaryRoadworks(4)
              10100194              99      63  roadworks(3) slowMovingRoadMaintenance(3)

  Event types:
   DENMs  actionIds  event type
    1182          7  roadworks(3) shortTermStationaryRoadworks(4)
```

Wildcards such as `*.pcap` are expanded by the script (also in Windows `cmd`).

---

### `denm_zones.py` — Trace and eventZone measurement

For every unique DENM, prints one row per trace and for the eventZone: the
number of points and the length in metres (the event type is shown on the first
row of each actionId). The length is a horizontal
polyline length (haversine, altitude ignored) and **includes the eventPosition**
as the start of the polyline. The complete output (including the list of
compiled ASN.1 files) is printed to the console and written to a text file.

```bash
python denm_zones.py capture.pcap
python denm_zones.py ../test-data/DENM1.pcap -o my_report.txt   # default: denm_zones_report.txt
```

```
  originatingStationId  sequenceNumber  zone        points  length incl. eventPos (m)  event type: cause(code) subcause(code)
  ----------------------------------------------------------------------------------------------------------------------------
               1021000             337  trace 1          4                      607.2  roadworks(3) unavailable(0)
                                        eventZone        8                      961.2
```

---

### `denm_to_kml.py` — PCAP → KML/KMZ Visualizer

DENM counterpart of [`../ivim/ivim_to_kml.py`](../ivim/ivim_to_kml.py) with the
same options. Plots every unique DENM for Google Earth, Google Maps, or any GIS tool:

- one folder per DENM, named `DENM <actionId> | <event type>` (e.g.
  `DENM 1021000/407 | roadworks(3) unavailable(0)`) for easy browsing
- eventPosition labeled `<actionId> | <event type>` (actionId = `originatingStationId/sequenceNumber`);
  its description states the event type, a linked cause if present, and the event geometry (point/linear/circular)
- traces (red, labeled `trace1`, `trace2`, …), eventZone (green, labeled `eventZone`)
- awareness circle (gold) for circular events; the circle shows the
  `awarenessDistance` upper bound (`over10km` is drawn as 10 km)
- point, linear and circular events are all drawn
- two output modes: zones as lines (default, starting at the eventPosition) or
  individual labeled points (`trace1-Item0`, `eventZone-Item3`, …), grouped in
  one sub-folder per zone so a zone can be switched off with a single click

```bash
python denm_to_kml.py capture.pcap
python denm_to_kml.py ../test-data/DENM1.pcap -o denm1.kml
python denm_to_kml.py ../test-data/DENM*.pcap --mode points -o denm_points.kml
python denm_to_kml.py capture.pcap --kmz -o output
```

---

### `denm_replay.py` — DENM / CAM replay on a satellite map

Writes a self-contained HTML page (`denm_replay.html`, opened in the browser)
that replays all DENMs of a station in real time, together with the matching
CAMs, on a satellite map (Leaflet + Esri World Imagery; needs an internet
connection for the map tiles):

- **stationType filter**: checkboxes for all stationTypes in the capture; all
  are selected by default except `roadSideUnit(15)`
- **one entry per originatingStationId**: only the station is selected. Every
  DENM of the station with a new `detectionTime` (first reception, any
  sequenceNumber) is one step of the replay, placed at its reception time on
  the capture (receiver) clock; DENMs and CAMs are aligned on this clock, since
  station clocks can be far off. In `TrafficManager.pcap`, 10101004 sends 485
  such DENMs in sequenceNumbers 40–43 over 139 s (every 0.25–1 s)
- **static DENMs**: if eventPosition, traces and eventZone are the same in all
  DENMs of an actionId (typical for roadside units), only its most recent DENM
  is shown, for the whole replay: eventPosition (DENM layer), all traces (DENM
  traces layer) and eventZone; the replay itself uses the moving actionIds. In
  `TrafficManager.pcap` all actionIds of the 4 roadSideUnits are static (e.g.
  1040017: 10 actionIds, 1,288 DENMs)
- **timeline slider** (ticks at the start of every sequenceNumber) to move back
  and forth, **speed slider** (0.1x … 50x); the status line shows the capture
  time, the current sequenceNumber (and termination), `eventPositionHeading`,
  `eventSpeed`, the distance to the CAM and the number of trace / pathHistory
  points shown
- **CAM matching**: all CAMs of the capture are decoded (ASN.1 in
  [`../cam/ASN/`](../cam/ASN/)) and the CAM station that matches the DENMs best
  is selected automatically. Every candidate gets a score out of 100 with the
  details listed:

  | Weight | Criterion | Full points |
  |--------|-----------|-------------|
  | 40 | track: median distance between the eventPositions and the CAM position at the same time | ≤ 5 m (none at ≥ 50 m) |
  | 25 | timing: share of the DENM time span covered by CAMs | 100 % |
  | 20 | cause: `incidentIndication` in the CAM special vehicle container | same cause and sub cause (same cause: 80 %, fitting container: 50 %) |
  | 15 | station | same stationId (same stationType: 30 %) |

  A candidate is only preselected from 50/100 on; any candidate (or none) can be
  chosen manually. In `TrafficManager.pcap` the CAMs of 10101004 are 1.4 m
  (median) from its eventPositions: 100/100.
- **Visualize**: four layers that can be shown individually or together:

  | Layer | Shows | Time label | Extra options |
  |-------|-------|------------|---------------|
  | DENM | eventPositions of all DENMs up to the replay time | time to the previous DENM (`seq n` at a new sequenceNumber) | eventZone of the latest DENM (own colour), `eventPositionHeading` arrows, smoothing |
  | DENM traces | first trace (`detectionZonesToEventPosition`) of the latest DENM, from its eventPosition backwards | `pathDeltaTime` | – |
  | CAM | received positions of the matched CAM station | time to the previous CAM | `heading` arrows, smoothing |
  | CAM pathHistory | `pathHistory` of the latest CAM with a low frequency container, from its referencePosition backwards | `pathDeltaTime` | – |

  DENM traces and CAM pathHistory show only the part from the replay start on,
  so they are empty at the start and build up during the replay. Point *i* was
  passed at the reception time minus the sum of `pathDeltaTime` 1…*i*
  (`pathDeltaTime` is the time to the previous point, to the eventPosition /
  referencePosition for the first one).

  Options per layer: **colour** (picker), **points** (off = line only), **time
  labels**, **full preview** (faint dashed line of what the layer shows at the
  end of the replay) and **minimal view** with a slider for the number of
  points (1–40): only the current position and the last n points. The minimal
  DENM view also hides the eventZone; the minimal CAM view without smoothing
  places the CAM marker on the latest received CAM. Every point has a popup
  with its details; heading arrows sit just ahead of the point.

  Defaults at start: all four layers shown with points, in the minimal view
  (DENM and DENM traces 8 points, CAM and CAM pathHistory 15 points), no full
  previews, no heading arrows, smoothing on (DENM and CAM); labels only for the DENM traces
  (`pathDeltaTime`); eventZone shown. The **Reset view** button restores these
  defaults and colours without changing the selection or the replay time.
- **Smoothing** (DENM and CAM option, on by default): the received CAM
  positions and DENM eventPositions jitter by about 1–1.5 m from message to
  message; with smoothing on, the track is smoothed (Kalman filter + RTS smoother, constant velocity model) using the
  positions, the time between the messages and speed/heading (DENM:
  `eventSpeed`, `eventPositionHeading`); speed/heading only
  weakly, since the heading is often off at low speed. Between two CAMs the
  position is interpolated with a cubic curve along the smoothed velocity, so
  the marker moves continuously. The points stay at the received positions
  (the popup gives the distance to the smoothed one; in `TrafficManager.pcap`
  CAM 0.5 m median, 2 m max; DENM 10101004 0.4 m median, 4.5 m max). The CAM matching always uses
  the received positions
- **pathHistory warning**: while the shown pathHistory is implausible, a red
  banner *CAM pathHistory inconsistent / broken* is shown on the map with the
  CAM and the reason (the pathHistory itself is drawn as received). Checked on
  the full received pathHistory: a point with `pathDeltaTime` 0, or a step of
  more than 50 m at more than 250 km/h (shorter steps are ignored because of
  GNSS jitter). In `TrafficManager.pcap`, four consecutive CAMs of 10101004
  contain such a pathHistory (20 points with `pathDeltaTime` 0 and a 1 km jump)

```bash
python denm_replay.py ../test-data/TrafficManager.pcap
python denm_replay.py ../test-data/TrafficManager.pcap --station 10101004
python denm_replay.py capture.pcap -o my_replay.html --no-open
python denm_replay.py capture.pcap --no-cam      # DENM only
```

The event type helper shared by the tools is in `denm_common.py`.
The tools reuse PCAP parsing from [`../ivim/ivim_zone_count.py`](../ivim/ivim_zone_count.py)
(Ethernet, raw 802.11 and 802.11 + Radiotap captures; `iter_its_packets_ts` also
returns the capture timestamps), the KML helpers from `../ivim/ivim_to_kml.py`
and, for `denm_replay.py`, the CAM ASN.1 files from [`../cam/ASN/`](../cam/ASN/),
so they must be run from within this repository tree.

---

## ASN.1 Files

The `ASN/` folder contains the ASN.1 schema files required to decode DENMs:

| File | Source |
|------|--------|
| `DENM-PDU-Descriptions.asn` | ETSI EN 302 637-3 — DENM PDU |
| `ETSI-ITS-CDD.asn` | ETSI TS 102 894-2 — Common Data Dictionary (same file as in [`../ivim/ASN/`](../ivim/ASN/)) |

---

## Test data

Example DENM captures (`DENM1.pcap`, `DENM2.pcap`) are in [`../test-data/`](../test-data/).
