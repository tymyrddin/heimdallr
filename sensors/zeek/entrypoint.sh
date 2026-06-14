#!/usr/bin/env bash
# Read every pcap under /ingest in file mode. Each capture's JSON logs are
# appended to the agent stream (/var/log/heimdallr/stream/zeek.json), which the
# collector tails, and also kept under zeek/ for inspection.
set -euo pipefail

STREAM=/var/log/heimdallr/stream
INSPECT=/var/log/heimdallr/zeek
mkdir -p "$STREAM" "$INSPECT"
shopt -s nullglob globstar

found=0
for pcap in /ingest/**/*.pcap /ingest/**/*.pcapng /ingest/*.pcap /ingest/*.pcapng; do
  found=1
  name="$(basename "${pcap%.*}")"
  work="$(mktemp -d)"
  echo "[zeek] reading $pcap"
  ( cd "$work" && zeek -C -r "$pcap" /opt/heimdallr/zeek/local.zeek 2>/dev/null || true )
  for log in "$work"/*.log; do
    [ -e "$log" ] || continue
    cat "$log" >> "$STREAM/zeek.json"
    cp "$log" "$INSPECT/${name}.$(basename "$log")"
  done
  rm -rf "$work"
done

[ "$found" = 1 ] || echo "[zeek] no pcaps found under /ingest"
echo "[zeek] done"
