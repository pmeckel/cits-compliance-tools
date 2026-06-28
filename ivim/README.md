# IVIM Tools — IVS-TS (In-Vehicle Signage – Traffic Signs)

Python tools for parsing, visualizing, and compliance-checking
**IVIM** (In-Vehicle Information Message) captures from ITS-G5 PCAP files.

Applicable specifications:
- **ISO TS 19321** — IVI (In-vehicle Information) data structures
- **ETSI TS 103 301** — IVIM message profile
- **C-ROADS SUD02** v3.2.0 — Service and Use Case Definitions, IVS
- **C-ROADS MP** v3.2.0 — Message Profile, chapters 4.2.2.2, 4.2.2.3, 4.2.2.8

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

### `ivim_croads_check.py` — C-ROADS IVS Compliance Checker

Checks each unique IVIM against the C-ROADS IVS profile (Release 3.2.0) and
produces a structured text report with PASS / FAIL / WARN / N/A / SKIP per requirement.

**Covered chapters**
| Chapter | Content |
|---------|---------|
| MP 4.2.2.2 | IVIM general elements (IviManagementContainer, GLC, RCC) |
| MP 4.2.2.3 | IVS-specific requirements (GIV, zone lengths, RSCodes) |
| MP 4.2.2.8 | Cancellation IVIM profile (reduced requirement set) |
| SUD 2.2.1.1 | IVS-TS use case requirements |

**Usage**
```bash
python ivim_croads_check.py capture.pcap
python ivim_croads_check.py capture.pcap -o report.txt
python ivim_croads_check.py file1.pcap file2.pcap -o combined_report.txt
```

**Report structure**
```
OVERALL TOTALS
KEY FINDINGS  (most frequent FAIL / WARN across all IVIMs)
--- per IVIM ---
  [IviManagementContainer]
  [GeographicLocationContainer]
  [RoadConfigurationContainer]
  [GeneralIviContainer (IVS)]
  [SUD 2.2.1.1 Requirements]
  Summary: X PASS  Y FAIL  Z WARN  ...
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

## ASN.1 Files

The `ASN/` folder contains the ASN.1 schema files required to decode IVIM messages:

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
