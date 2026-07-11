# IVS-TS — In-Vehicle Signage – Traffic Signs

Compliance checker for the **IVS-TS** use case, one of several C-ROADS use cases
carried by the IVIM message (see [`../README.md`](../README.md) for the full
list of IVIM use cases).

Applicable specifications:
- **C-ROADS Message Profile** v3.2.0 — chapters 4.2.2.2, 4.2.2.3, 4.2.2.8
- **C-ROADS Service and Use Case Definitions** v3.2.0 — chapter 2.2.1.1

---

## `ivs_ts_croads_check.py` — C-ROADS IVS-TS Compliance Checker

Checks each unique IVIM in a PCAP file against the C-ROADS IVS-TS (In-Vehicle
Signage – Traffic Signs) profile (Release 3.2.0) and produces a structured
text report with PASS / FAIL / WARN / N/A / SKIP per requirement.

**Covered chapters**
| Chapter | Content |
|---------|---------|
| MP 4.2.2.2 | IVIM general elements (IviManagementContainer, GLC, RCC) |
| MP 4.2.2.3 | IVS-TS-specific requirements (GIV, zone lengths, RSCodes) |
| MP 4.2.2.8 | Cancellation IVIM profile (reduced requirement set) |
| SUD 2.2.1.1 | IVS-TS use case requirements |

**Usage**
```bash
python ivs_ts_croads_check.py capture.pcap
python ivs_ts_croads_check.py capture.pcap -o report.txt
python ivs_ts_croads_check.py file1.pcap file2.pcap -o combined_report.txt
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

This script reuses PCAP parsing and ASN.1 compilation from
[`../ivim_to_kml.py`](../ivim_to_kml.py) and the shared ASN.1 files in
[`../ASN/`](../ASN/).
