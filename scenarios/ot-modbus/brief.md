# Scenario brief: ot-modbus

## The move

Unauthorised or anomalous Modbus activity against the OT estate: writes to
registers or coils from an unexpected source, scans across unit IDs, or function
codes that have no business on that segment.

## What to detect

Zeek's Modbus analyser gives the capture structure (function codes, unit and
register addresses) in modbus.log; Suricata adds signature alerts. The baseline
ruleset flags Modbus writes as a starting point. Tune against a real capture so
the genuine anomaly fires while routine polling stays quiet.

## Inputs

Pending the ics-access-simlab export adaptation (M3): a per-scenario pcap and
structured host-event logs. Until then this scenario has rules but nothing to
ingest.
