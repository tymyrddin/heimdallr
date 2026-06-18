#!/usr/bin/env python3
"""Build and PUT heimdallr's routing ingest pipeline.

This pipeline is heimdallr's routing DETECTION CONTENT (the part the rule layer
cannot express), version-controlled and reviewable. It does two things, both in
the detection layer, never in the feeder:

  1. Normalise: split the raw `prefix` into an ip-typed `network_address` and an
     integer `network_prefix_length`.

  2. Derive (against heimdallr's own baseline and the observed VRP set):
       covering_aggregate / covering_prefix_length
                  the most-specific monitored block (rules/baseline/aggregates.json)
                  that contains the prefix. Set for announces AND roa-change records,
                  so the arm->hijack correlation can bucket both on the same key.
       more_specific      (announce) longer than its covering aggregate, with no
                          hardcoded length: a /23 under a /22 is caught.
       origin_authorised  (announce) announced by the aggregate's registered origin.
       rpki_validity      (announce) RFC 6811 origin validation against the bundle's
                          observed VRPs: covered + origin match + len <= maxLength
                          -> valid; covered otherwise -> invalid; uncovered -> notfound.

The baseline is heimdallr's authored ground truth (NOT from any scorer). The VRP
set is observation, read from each bundle's vrps.json and passed in as params, so
the Painless only does integer comparisons. Keep this script and the Painless well
commented: for the routing substrate, this enrichment is where the detection logic
lives (the routing Sigma rules just match the fields it produces).
"""
import glob
import json
import os
import sys
import urllib.request

OS_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")


def ip_to_long(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) + (b << 16) + (c << 8) + d


def cidr_range(cidr):
    net, length = cidr.split("/")
    length = int(length)
    base = ip_to_long(net) & (((1 << length) - 1) << (32 - length)) if length else 0
    return base, base + (1 << (32 - length)) - 1, length


def load_baseline(path):
    out = []
    for agg in json.load(open(path)):
        lo, hi, length = cidr_range(agg["prefix"])
        out.append({"prefix": agg["prefix"], "origin": agg["origin"],
                    "min": lo, "max": hi, "len": length})
    return out


def load_vrps(ingest_root):
    vrps = {}
    for vf in glob.glob(os.path.join(ingest_root, "*", "vrps.json")):
        bundle = os.path.basename(os.path.dirname(vf))
        entries = []
        for roa in json.load(open(vf)).get("roas", []):
            lo, hi, plen = cidr_range(roa["prefix"])
            asn = int(str(roa["asn"]).removeprefix("AS"))
            # RFC 6811: a ROA with no maxLength defaults to the prefix length.
            maxlen = roa.get("maxLength")
            if maxlen is None:
                maxlen = plen
            entries.append({"min": lo, "max": hi, "maxlen": maxlen, "origin": asn})
        vrps[bundle] = entries
    return vrps


PAINLESS = r"""
if (ctx.network_address == null) { return; }
String[] o = ctx.network_address.splitOnToken('.');
long addr = (Long.parseLong(o[0]) << 24) + (Long.parseLong(o[1]) << 16)
          + (Long.parseLong(o[2]) << 8) + Long.parseLong(o[3]);

// Most-specific (longest) monitored aggregate from heimdallr's baseline that
// contains this address. Set for announces and roa-change records alike, so the
// arm (a ROA removal) and the hijack bucket on the same covering_aggregate.
long bestlen = -1L;
long coveringOrigin = -1L;
for (def agg : params.aggregates) {
  long alen = ((Number) agg.len).longValue();
  if (addr >= agg.min && addr <= agg.max && alen > bestlen) {
    bestlen = alen;
    coveringOrigin = ((Number) agg.origin).longValue();
    ctx.covering_aggregate = agg.prefix;
    ctx.covering_prefix_length = alen;
  }
}

// The remaining signals are properties of an announcement.
if (ctx.type == 'announce' && ctx.covering_aggregate != null) {
  long len = ((Number) ctx.network_prefix_length).longValue();
  long origin = ctx.origin_as == null ? -1L : ((Number) ctx.origin_as).longValue();

  // size-generic: longer than its covering aggregate, no hardcoded /24 threshold.
  ctx.more_specific = len > bestlen;
  // single-sourced: the aggregate's registered origin, from the baseline.
  ctx.origin_authorised = origin == coveringOrigin;
}

// RFC 6811 origin validation against this bundle's observed VRP set.
if (ctx.type == 'announce') {
  long len = ((Number) ctx.network_prefix_length).longValue();
  long origin = ctx.origin_as == null ? -1L : ((Number) ctx.origin_as).longValue();
  def vrps = params.vrps.get(ctx.bundle);
  boolean covered = false; boolean valid = false;
  if (vrps != null) {
    for (def v : vrps) {
      if (addr >= v.min && addr <= v.max) {
        covered = true;
        if (origin == ((Number) v.origin).longValue()
            && len <= ((Number) v.maxlen).longValue()) { valid = true; }
      }
    }
  }
  ctx.rpki_validity = valid ? 'valid' : (covered ? 'invalid' : 'notfound');
}
"""


def build_pipeline_body(ingest_root, baseline_path):
    """Build the routing ingest-pipeline definition from heimdallr's baseline and
    the VRP sets observed under ingest_root. Returns the pipeline dict (no I/O), so
    both the CLI and the Flask UI can build it the same way."""
    baseline = load_baseline(baseline_path)
    vrps = load_vrps(ingest_root)
    pipeline = {
        "description": "heimdallr routing: normalise prefix + RFC6811 ROV/covering enrichment",
        "processors": [
            {"dissect": {"if": "ctx.prefix != null && ctx.prefix.contains('/')",
                         "field": "prefix",
                         "pattern": "%{network_address}/%{network_prefix_length}"}},
            {"convert": {"if": "ctx.network_prefix_length != null",
                         "field": "network_prefix_length", "type": "integer"}},
            {"script": {"lang": "painless", "source": PAINLESS,
                        "params": {"aggregates": baseline, "vrps": vrps}}},
        ],
    }
    return pipeline, baseline, vrps


def default_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    baseline_path = os.environ.get("HEIMDALLR_BASELINE",
                                   os.path.join(repo, "rules", "baseline", "aggregates.json"))
    return repo, baseline_path


def main():
    repo, baseline_path = default_paths()
    ingest_root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, "ingest")

    pipeline, baseline, vrps = build_pipeline_body(ingest_root, baseline_path)
    body = json.dumps(pipeline).encode()
    req = urllib.request.Request(f"{OS_URL}/_ingest/pipeline/routing", data=body,
                                 method="PUT", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        print("pipeline PUT:", json.load(r))
    print(f"baseline aggregates: {len(baseline)}; VRP bundles: {list(vrps)}")


if __name__ == "__main__":
    main()
