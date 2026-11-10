# CAM Support

ASN.1 definitions for decoding **CAM** (Cooperative Awareness Message) captures
from ITS-G5 PCAP files.

Applicable base specification:
- **ETSI EN 302 637-2** — CAM message format (release 2, `protocolVersion` 2)

> **Status:** no standalone CAM tools yet. CAMs are currently decoded by
> [`../denm/denm_replay.py`](../denm/denm_replay.py), which matches the CAM
> station that fits a DENM trace best and replays it in parallel with the DENM.

CAMs are sent on BTP-B destination port 2001 with `messageId` 2. Decoding was
checked with [`../test-data/TrafficManager.pcap`](../test-data/): all 573 CAMs
decode (4 stations, high-frequency container in all, low-frequency container in
435, special vehicle container in 191).

---

## ASN.1 Files

The `ASN/` folder contains the ASN.1 schema files required to decode CAMs:

| File | Source |
|------|--------|
| `CAM-PDU-Descriptions.asn` | ETSI EN 302 637-2 — CAM PDU (module `camPduRelease2`, version 2.1) |
| `ETSI-ITS-CDD.asn` | ETSI TS 102 894-2 — Common Data Dictionary (module version 4.2, same file as in [`../denm/ASN/`](../denm/ASN/) and [`../ivim/ASN/`](../ivim/ASN/)) |

Compile both files together, e.g. with asn1tools:

```python
import asn1tools
db = asn1tools.compile_files(['ASN/ETSI-ITS-CDD.asn', 'ASN/CAM-PDU-Descriptions.asn'], codec='uper')
cam = db.decode('CAM', payload)   # payload starts after the 4-byte BTP-B header
```
