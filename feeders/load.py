#!/usr/bin/env python3
"""Bulk-ship routing observations into OpenSearch.

Reads the feeder's JSON-lines output and bulk-indexes it into the routing index
in batches. The index's default pipeline (heimdallr's routing enrichment) runs on
ingest, so what lands is the raw observation plus the derived detection fields.
Pure stdlib; the feeder image carries no detection logic.
"""
import json
import os
import sys
import urllib.request

OS_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
INDEX = os.environ.get("ROUTING_INDEX", "routing")
BATCH = 5000


def post(path, body):
    req = urllib.request.Request(OS_URL + path, data=body.encode(), method="POST",
                                 headers={"Content-Type": "application/x-ndjson"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main(path):
    n = errors = 0
    buf = []

    def flush():
        nonlocal errors
        if not buf:
            return
        res = post(f"/{INDEX}/_bulk", "".join(buf))
        if res.get("errors"):
            for item in res["items"]:
                err = item.get("index", {}).get("error")
                if err:
                    errors += 1
                    if errors <= 3:
                        print("  err:", err, file=sys.stderr)
        buf.clear()

    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            buf.append('{"index":{}}\n')
            buf.append(line + "\n")
            n += 1
            if n % BATCH == 0:
                flush()
    flush()
    print(f"[load] indexed {n} observations into {INDEX} ({errors} errors)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/routing.json")
