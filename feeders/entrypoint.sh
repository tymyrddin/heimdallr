#!/usr/bin/env sh
# heimdallr routing sensor: relay raw observations from /ingest and ship them to
# OpenSearch. The feeder emits observations only; the index's default pipeline
# does the enrichment. Parallel in spirit to the offline Zeek/Suricata sensors.
set -eu

OUT=/tmp/routing.json
python3 /opt/heimdallr/routing.py --ingest /ingest --out "$OUT" --inspect-dir /tmp/routing-inspect
exec python3 /opt/heimdallr/load.py "$OUT"
