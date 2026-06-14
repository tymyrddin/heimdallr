# ingest

The boundary with the attack labs: a directory, not a wire.

Captures and logs exported from inter-domain-simlab, ics-access-simlab and
huginn-and-muninn are dropped here, and the sensors read them in file mode when
you run `./ctl ingest`.

What goes where:

- `*.pcap`, `*.pcapng`: read by Zeek and Suricata. OT Modbus traffic and any
  packet-level material.
- host-event logs (JSON): tailed straight by the collector into Wazuh.
- routing artefacts (MRT / BMP / RPKI / JSON timeline): passed through
  `feeders/routing.py` first, since BGP is not pcap-shaped (M2).

The contents of this directory are gitignored: real captures stay out of git.
Small illustrative samples can live under `samples/`.
