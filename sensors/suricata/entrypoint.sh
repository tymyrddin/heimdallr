#!/usr/bin/env bash
# Read every pcap under /ingest in file mode. Each run's eve.json is appended to
# the agent stream (/var/log/heimdallr/stream/suricata.json), which the collector
# tails, and also kept under suricata/ for inspection.
set -euo pipefail

STREAM=/var/log/heimdallr/stream
INSPECT=/var/log/heimdallr/suricata
mkdir -p "$STREAM" "$INSPECT"
shopt -s nullglob globstar

found=0
for pcap in /ingest/**/*.pcap /ingest/**/*.pcapng /ingest/*.pcap /ingest/*.pcapng; do
  found=1
  echo "[suricata] reading $pcap"
  work="$(mktemp -d)"
  suricata -r "$pcap" -l "$work" -S /etc/suricata/heimdallr-rules/local.rules -k none 2>/dev/null || true
  if [ -f "$work/eve.json" ]; then
    cat "$work/eve.json" >> "$STREAM/suricata.json"
    cp "$work/eve.json" "$INSPECT/$(basename "${pcap%.*}").eve.json"
  fi
  rm -rf "$work"
done

[ "$found" = 1 ] || echo "[suricata] no pcaps found under /ingest"
echo "[suricata] done"
