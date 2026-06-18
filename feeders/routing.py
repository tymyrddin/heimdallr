#!/usr/bin/env python3
"""Routing feeder: turn raw routing telemetry into JSON observations for OpenSearch.

BGP is not pcap-shaped, so the routing substrate does not pass through Zeek or
Suricata. This feeder is heimdallr's routing sensor. It reads the raw telemetry
inter-domain-simlab exports under ingest/<bundle>/ and appends one JSON object
per line to the agent stream the collector tails. It runs as a container,
parallel to Zeek and Suricata, writing stream/routing.json into the
heimdallr_sensor-logs volume (pre-created empty by ctl's _ensure_stream). Nothing
is written to the host.

It emits OBSERVATIONS ONLY, never verdicts. Each line is what a monitor really
saw, tagged with its provenance (substrate, observer, bundle) and nothing more:

  - BMP events (events.jsonl), passed through field-for-field:
      {"substrate":"routing","observer":"bmp","bundle":"...","ts":"...",
       "type":"announce|withdraw","prefix":"203.0.113.0/25","origin_as":65020,
       "as_path":[...],"peer_as":65002,"policy":"post"}
  - ROA changes (roa-history.txt), one per ADD/REMOVE record:
      {"substrate":"routing","observer":"rpki","bundle":"...","ts":"...",
       "type":"roa-change","roa_action":"add|remove","prefix":"203.0.113.0/24",
       "max_length":24,"asn":65010}
  - VRPs (vrps.json), the validated-ROA payload set as observed:
      {"substrate":"routing","observer":"rpki","bundle":"...","ts":"...",
       "type":"vrp","prefix":"192.0.2.0/24","max_length":24,"asn":65001}

The feeder computes no more_specific / moas / validity / covering and reads no
scorer timeline or target/legitimate-origin answer key. heimdallr derives every
verdict in the detection layer (CDB baseline + rules), against telemetry the
feeder only relayed. See PLAN.md sections 5 and 9.

The RPKI observations (ROA changes, then the VRP snapshot) are emitted before the
BMP events of the same bundle, so a ROA removal is already on record when the
prefix later surfaces in an announcement, which is what the arm->hijack
correlation sequences on.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# A roa-history line: time::command::version::success, where the command we want
# adds or removes a ROA, e.g. "Update ROAs  REMOVE: 203.0.113.0/24-24 => 65010".
_ROA_CHANGE = re.compile(
    r"\b(ADD|REMOVE):\s*([0-9a-fA-F:.]+/\d+)-(\d+)\s*=>\s*(\d+)"
)


def _emit(stream, copy, obj) -> None:
    line = json.dumps(obj)
    stream.write(line + "\n")
    copy.write(line + "\n")


def iter_rpki(bundle: str, bundle_dir: Path):
    """Yield the RPKI observations for a bundle: every ROA change from
    roa-history.txt (timestamped, in file order), then the VRP snapshot from
    vrps.json. Observations only, no verdicts."""
    history = bundle_dir / "roa-history.txt"
    if history.exists():
        for line in history.read_text().splitlines():
            parts = line.split("::")
            if len(parts) < 2:
                continue
            ts, command = parts[0].strip(), parts[1]
            m = _ROA_CHANGE.search(command)
            if not m:
                continue
            action, prefix, max_length, asn = m.groups()
            yield {
                "substrate": "routing",
                "observer": "rpki",
                "bundle": bundle,
                "ts": ts,
                "type": "roa-change",
                "roa_action": action.lower(),
                "prefix": prefix,
                "max_length": int(max_length),
                "asn": int(asn),
            }

    vrps = bundle_dir / "vrps.json"
    if vrps.exists():
        try:
            data = json.loads(vrps.read_text())
        except ValueError:
            data = {}
        ts = data.get("metadata", {}).get("generatedTime")
        for roa in data.get("roas", []):
            asn = str(roa.get("asn", "")).removeprefix("AS")
            yield {
                "substrate": "routing",
                "observer": "rpki",
                "bundle": bundle,
                "ts": ts,
                "type": "vrp",
                "prefix": roa.get("prefix"),
                "max_length": roa.get("maxLength"),
                "asn": int(asn) if asn.isdigit() else None,
            }


def iter_bmp(bundle: str, bundle_dir: Path):
    """Yield each BMP event from events.jsonl, passed through field-for-field with
    only provenance tags added. Streamed line by line: the roa-poisoning bundle
    is ~80k events and is not pre-trimmed."""
    events = bundle_dir / "events.jsonl"
    if not events.exists():
        return
    with events.open() as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            event["substrate"] = "routing"
            event["observer"] = "bmp"
            event["bundle"] = bundle
            yield event


def iter_bundle(bundle_dir: Path):
    """Yield one ingest/<bundle>/ bundle as observations: RPKI first (so a ROA
    removal precedes the prefix surfacing), then the BMP event stream. The single
    source of truth for what the routing feeder relays; both the container CLI
    (feed_bundle) and the in-process loader (the Flask UI) consume it."""
    bundle = bundle_dir.name
    yield from iter_rpki(bundle, bundle_dir)
    yield from iter_bmp(bundle, bundle_dir)


def feed_bundle(bundle_dir: Path, stream, inspect_dir: Path) -> int:
    """Relay one bundle to the collector stream plus a per-bundle inspection copy
    (the container path used by `ctl ingest`). Returns the number of lines."""
    bundle = bundle_dir.name
    copy = (inspect_dir / f"{bundle}.json").open("w")
    n = 0
    try:
        for obj in iter_bundle(bundle_dir):
            _emit(stream, copy, obj)
            n += 1
    finally:
        copy.close()
    return n


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--ingest",
        default="/ingest",
        help="ingest root scanned for <bundle>/events.jsonl bundles",
    )
    parser.add_argument(
        "--out",
        default="/var/log/heimdallr/stream/routing.json",
        help="JSON-lines stream the collector tails",
    )
    parser.add_argument(
        "--inspect-dir",
        default="/var/log/heimdallr/routing",
        help="per-bundle copies kept for inspection (parity with the sensors)",
    )
    args = parser.parse_args(argv)

    ingest = Path(args.ingest)
    out = Path(args.out)
    inspect = Path(args.inspect_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    inspect.mkdir(parents=True, exist_ok=True)

    bundles = sorted({p.parent for p in ingest.glob("*/events.jsonl")})
    if not bundles:
        print(f"[routing] no routing bundles found under {ingest}")
        return 0

    total = 0
    with out.open("a") as stream:
        for bundle_dir in bundles:
            n = feed_bundle(bundle_dir, stream, inspect)
            print(f"[routing] relayed {bundle_dir.name} ({n} observations)")
            total += n

    print(f"[routing] wrote {total} observations to {out}")
    print("[routing] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())