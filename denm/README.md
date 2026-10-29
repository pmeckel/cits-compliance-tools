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
tools as cause code / sub cause code with their meaning, e.g.
`3 roadworks / 4 shortTermStationaryRoadworks`. The names are read directly from
`ASN/ETSI-ITS-CDD.asn` (see `denm_common.py`), so they follow the CDD version in
use. Sub cause codes without a name in the CDD are shown as `unknown`; causes
without named sub causes (e.g. `7 aquaplaning`) show the number only; DENMs
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
  originatingStationId  sequenceNumber   DENMs  event type (cause code / sub cause code)
  ------------------------------------------------------------------------------------------
               1021000             553     105  3 roadworks / 4 shortTermStationaryRoadworks
              10100194              99      63  3 roadworks / 3 slowMovingRoadMaintenance

  Event types:
   DENMs  actionIds  event type
    1182          7  3 roadworks / 4 shortTermStationaryRoadworks
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
  originatingStationId  sequenceNumber  zone        points  length incl. eventPos (m)  event type (cause code / sub cause code)
  ----------------------------------------------------------------------------------------------------------------------------
               1021000             337  trace 1          4                      607.2  3 roadworks / 0 unavailable
                                        eventZone        8                      961.2
```

---

### `denm_to_kml.py` — PCAP → KML/KMZ Visualizer

DENM counterpart of [`../ivim/ivim_to_kml.py`](../ivim/ivim_to_kml.py) with the
same options. Plots every unique DENM for Google Earth, Google Maps, or any GIS tool:

- eventPosition labeled with the actionId (`originatingStationId/sequenceNumber`);
  its description states the event type (cause code / sub cause code and
  meaning), a linked cause if present, and the event geometry (point/linear/circular)
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

The event type helper shared by the three tools is in `denm_common.py`.
The tools reuse PCAP parsing from [`../ivim/ivim_zone_count.py`](../ivim/ivim_zone_count.py)
(Ethernet, raw 802.11 and 802.11 + Radiotap captures) and the KML helpers from
`../ivim/ivim_to_kml.py`, so they must be run from within this repository tree.

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
