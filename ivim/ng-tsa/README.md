# NG-TSA — Navigation Guidance – Toll Station Approaching

Compliance checker for the **NG-TSA** use case, one of several C-ROADS use
cases carried by the IVIM message (see [`../README.md`](../README.md) for
the full list of IVIM use cases).

NG-TSA reuses **every IVS-TS requirement** (see
[`../ivs-ts/README.md`](../ivs-ts/README.md)) and adds the NG-TSA-specific
requirements on top.

Applicable specifications:
- **C-ROADS Message Profile** v3.2.0 — chapters 4.2.2.2, 4.2.2.3, 4.2.2.8 (via IVS-TS)
- **C-ROADS Service and Use Case Definitions 07 (NG)** v3.2.0 — chapter 7.2.1.1

---

## `ng_tsa_croads_check.py` — C-ROADS NG-TSA Compliance Checker

Checks each unique IVIM in a PCAP file against the C-ROADS NG-TSA (Navigation
Guidance – Toll Station Approaching) profile (Release 3.2.0) and produces a
structured text report with PASS / FAIL / WARN / N/A / SKIP per requirement.

The script imports [`../ivs-ts/ivs_ts_croads_check.py`](../ivs-ts/ivs_ts_croads_check.py)
as a library module and runs its full IVS-TS check set first, then appends
the NG-TSA-specific checks below. Any future fix to the shared IVS-TS checks
is automatically picked up here too.

**Covered chapters**
| Chapter | Content |
|---------|---------|
| MP 4.2.2.2 / 4.2.2.3 / 4.2.2.8 | Full IVS-TS base profile (reused as-is) |
| SUD 2.2.1.1 | IVS-TS use case requirements (reused as-is) |
| SUD 7.2.1.1 | NG-TSA-specific requirements (this checker) |

**NG-TSA-specific requirements (SUD 7.2.1.1)**
| ID | Type | Summary |
|----|------|---------|
| SUD_NG_Req_0001 | REQ | Meta-requirement — IVIM based on MP 4.2.2.1 & 4.2.2.2 (4.2.2.2 covered via IVS-TS reuse) |
| SUD_NG_Req_0002 | REQ | `giv.relevanceZoneIds` mandatory; the relevance zone shall be a `segment-setOfLanes` leading to the toll island |
| SUD_NG_Req_0003 | REQ | Payment-option signage: main sign 8-33 ("Automatic toll gate") mandatory, up to 3 sub-signs from {6-81..6-85} |
| SUD_NG_Req_0004 | REC | Lane availability / traffic-restriction signage: main sign from {6-59, 6-60, 9-99, 9-98, 4-12}, sub-signs from {5-57, 5-11, 1-34} |
| SUD_NG_Req_0005 | REQ | `segmentWidthLeft` mandatory on the relevance zone if no RccPart covers it |
| SUD_NG_Rec_0006 | REC | `segmentWidthLeft` recommended on the relevance zone even if an RccPart covers it (provides `laneWidth`) |

Out of scope (per user request, not implemented): SUD chapters 7.2.1.2
(communication technology), 7.2.1.3 (IP-based), 7.2.1.4 (test/validation),
and other NG use cases (Smart Routing, Route Advice).

**Usage**
```bash
python ng_tsa_croads_check.py capture.pcap
python ng_tsa_croads_check.py capture.pcap -o report.txt
python ng_tsa_croads_check.py file1.pcap file2.pcap -o combined_report.txt
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
  [SUD 2.2.1.1 Requirements (IVS-TS base)]
  [NG-TSA (SUD 7.2.1.1)]
  Summary: X PASS  Y FAIL  Z WARN  ...
```

This script reuses PCAP parsing and ASN.1 compilation from
[`../ivim_to_kml.py`](../ivim_to_kml.py) (via the IVS-TS module) and the
shared ASN.1 files in [`../ASN/`](../ASN/).
