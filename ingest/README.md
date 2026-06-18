# ingest

The boundary with the attack labs: a directory, not a wire.

Telemetry exported from inter-domain-simlab, ics-access-simlab and
huginn-and-muninn is dropped here as bundle directories, one per attack. `./ctl
ingest` relays the routing bundles into OpenSearch (the feeder + the enrichment
pipeline); `./ctl detect` runs the Sigma rules and the correlation over them.

A bundle is a directory, `ingest/<bundle>/`, holding the raw artefacts and, if
wanted, a short brief alongside them. By substrate:

- routing (the current profile): `events.jsonl` (the BMP announce/withdraw
  stream), `roa-history.txt` (ROA changes), `vrps.json` (the validated-ROA set).
  Relayed by `feeders/routing.py` as observations, since BGP is not pcap-shaped.
- pcap (`*.pcap`, `*.pcapng`): read by Zeek and Suricata. OT Modbus traffic and
  any packet-level material. A later milestone; `sensors/` is parked for it.

The bundle directories are committed, so a fresh clone runs the scenarios out of
the box. The doctrine briefs live in blue, not here.
