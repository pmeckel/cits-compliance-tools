# IVIM Tools

Python tools for parsing and visualizing **IVIM** (In-Vehicle Information Message)
captures from ITS-G5 PCAP files.

Applicable base specifications:
- **ISO TS 19321** — IVI (In-vehicle Information) data structures
- **ETSI TS 103 301** — IVIM message profile

The IVIM message carries several distinct C-ROADS use cases (see below). The
tools in this top-level folder (`ivim_to_kml.py`, `ivim_zone_count.py`) are
generic and work across all of them; use-case-specific compliance checkers
live in their own subfolder.

---

## Use Cases

| Folder | Use Case | Status | Spec |
|--------|----------|--------|------|
| [`ivs-ts/`](ivs-ts/) | IVS-TS (In-Vehicle Signage – Traffic Signs) | ✅ implemented | C-ROADS Release 3.2.0 |
| `ivs-ft/` | IVS-FT (In-Vehicle Signage – Free Text) | *(planned)* | C-ROADS Release 3.2.0 |

---

## Tools

### `ivim_to_kml.py` — PCAP → KML/KMZ Visualizer

Extracts IVIM messages from a PCAP capture and generates a KML/KMZ file
for visualization in Google Earth, Google Maps, or any GIS tool.

**Features**
- Decodes ITS-G5 / GeoNetworking / BTP-B / IVIM UPER payload without tshark
- Deduplicates by `iviIdentificationNumber` (one entry per IVIM regardless of repetitions)
- Colors zones by type from the GeneralIviContainer (GIV):
  red = detection, green = relevance, gold = awareness, gray = unassigned
- Two output modes: zones as lines (default) or individual labeled points

**Usage**
```bash
# Lines mode (default) — zones as LineStrings
python ivim_to_kml.py capture.pcap
python ivim_to_kml.py capture.pcap -o output.kml
python ivim_to_kml.py capture.pcap --kmz -o output

# Points mode — each delta position as a labeled point (Zone1-Item0, Zone1-Item1, …)
python ivim_to_kml.py capture.pcap --mode points -o output_points.kml

# Multiple input files
python ivim_to_kml.py file1.pcap file2.pcap -o combined.kml
```

---

### `ivim_zone_count.py` — Zone Counter

Quick summary of how many detection, awareness, and relevance zones each IVIM
carries, printed as a table.

**Usage**
```bash
python ivim_zone_count.py capture.pcap
python ivim_zone_count.py file1.pcap file2.pcap
```

**Example output**
```
ivi_id  status         detection  awareness  relevance
------------------------------------------------------
966     new                    2          0          1
------------------------------------------------------
TOTAL                          2          0          1
```

---

## Use-Case Compliance Checkers

Compliance checking against a specific C-ROADS use case profile (e.g. IVS-TS)
lives in its own subfolder, since each use case has its own set of
requirements, report format, and terminology. See [`ivs-ts/README.md`](ivs-ts/README.md)
for the currently implemented checker.

---

## ASN.1 Files

The `ASN/` folder contains the ASN.1 schema files required to decode IVIM messages,
shared by all tools and use-case checkers in this folder tree:

| File | Source |
|------|--------|
| `ETSI-ITS-CDD.asn` | ETSI EN 302 895 — Common Data Dictionary |
| `IVIM-PDU-Descriptions.asn` | ETSI TS 103 301 — IVIM PDU |
| `ISO19321IVIv3.1.asn` | ISO TS 19321 — IVI data structures |
| `ISO19321IVI-IS.asn` | ISO TS 19321 — information structures |
| `ISO_14823-1 ed1_AnnexE.asn` | ISO 14823-1 — graphic data dictionary |
| `ISO 17573-3 EfcDataDictionary V1.6.asn` | ISO 17573-3 — EFC data dictionary |

> **Note:** The scripts auto-generate `ISO19321IVIv3.1_patched.asn` on first run.
> This replaces `RELATIVE-OID` with `OBJECT IDENTIFIER` to work around a limitation
> in the `asn1tools` library. The patched file is excluded from version control.
