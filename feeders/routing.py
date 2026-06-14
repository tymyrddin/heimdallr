#!/usr/bin/env python3
"""Routing feeder: turn routing artefacts into Wazuh-ready JSON log lines.

BGP is not pcap-shaped, so the routing substrate does not pass through Zeek or
Suricata. This feeder reads the artefacts inter-domain-simlab exports (MRT
dumps, BMP streams, a JSON event timeline, RPKI-validator state) and writes one
JSON object per line to /var/log/heimdallr/routing/, where the collector tails
it and Wazuh decodes it natively.

Output shape (the field names the baseline routing rules match on):

    {"substrate": "routing", "event_type": "announce", "timestamp": "...",
     "prefix": "...", "origin_asn": ..., "as_path": [...],
     "moas": true, "more_specific": false, "validity": "invalid", ...}

Status: stub. This is M2 work, and it waits on inter-domain-simlab producing an
exportable MRT seed plus a scorer timeline (its PLAN sections 8, 14, 15). The
CLI shape is sketched here so the wiring is obvious; the parsing is not written.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "artefact",
        help="path to an MRT dump, BMP stream, JSON timeline or RPKI state file",
    )
    parser.add_argument(
        "--kind",
        choices=["mrt", "bmp", "timeline", "rpki"],
        required=True,
        help="artefact type, since they parse differently",
    )
    parser.add_argument(
        "--out",
        default="/var/log/heimdallr/routing/feed.log",
        help="JSON-lines output the collector tails",
    )
    args = parser.parse_args(argv)

    raise SystemExit(
        f"routing feeder is not implemented yet (M2): asked to parse "
        f"{args.kind} artefact {args.artefact!r} to {args.out}"
    )


if __name__ == "__main__":
    sys.exit(main())
