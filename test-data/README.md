# Test data

Example PCAP captures for trying out the tools. All files use the classic PCAP
format (not PCAPNG).

| File | Content | Link type | Tools |
|------|---------|-----------|-------|
| `SingleIVIM.pcap` | a single IVIM (`iviIdentificationNumber` 966) | Ethernet | [`ivim/`](../ivim/) |
| `AllCaptures_IVIM.pcap` | 7,410 IVIM transmissions, 50 unique `iviIdentificationNumber`s | Ethernet | [`ivim/`](../ivim/) |
| `KTC_IVIM.pcap` | 16,797 ITS-G5 packets with 3,256 IVIM transmissions, 2 unique IVIMs | IEEE 802.11 + Radiotap | [`ivim/`](../ivim/) |
| `DENM1.pcap` | CAMs and DENMs; 2,553 DENMs, 14 unique actionIds | Ethernet | [`denm/`](../denm/) |
| `DENM2.pcap` | CAMs and DENMs; 1,826 DENMs, 15 unique actionIds | Ethernet | [`denm/`](../denm/) |

Example:

```bash
python ivim/ivim_zone_count.py test-data/AllCaptures_IVIM.pcap
python denm/denm_count.py test-data/DENM1.pcap test-data/DENM2.pcap
```
