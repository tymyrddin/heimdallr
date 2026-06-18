#!/usr/bin/env python3
"""heimdallr routing detector.

Compiles the Sigma rules in /rules/sigma with pySigma into OpenSearch queries,
runs them against the routing index, and reports what they trigger, per bundle.
Then runs the engine-form arm->hijack correlation (/rules/correlation/arm-hijack.json,
a bucket-level aggregation) across the full event stream. This is the "compile
Sigma to queries and verify they fire" loop; for routing the detection logic lives
in the ingest-pipeline enrichment, and these Sigma rules match the fields it
derives.
"""
import glob
import json
import os
import urllib.request

from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend

OS_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
INDEX = os.environ.get("ROUTING_INDEX", "routing")
RULES = os.environ.get("SIGMA_DIR", "/rules/sigma")
CORRELATION = os.environ.get("CORRELATION", "/rules/correlation/arm-hijack.json")


def search(body):
    req = urllib.request.Request(f"{OS_URL}/{INDEX}/_search", method="POST",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def run_sigma():
    backend = OpensearchLuceneBackend()
    print("=== Sigma detections (compiled with pySigma) ===")
    for path in sorted(glob.glob(f"{RULES}/*.yml")):
        rules = SigmaCollection.load_ruleset([path])
        title = rules.rules[0].title
        for query in backend.convert(rules):
            res = search({
                "size": 0,
                "query": {"query_string": {"query": query}},
                "aggs": {"by_bundle": {"terms": {"field": "bundle", "size": 20},
                                         "aggs": {"by_prefix": {"terms": {"field": "prefix", "size": 5}}}}},
            })
            total = res["hits"]["total"]["value"]
            print(f"\n[{title}]  ({total} hits)")
            print(f"    query: {query}")
            for b in res["aggregations"]["by_bundle"]["buckets"]:
                pfx = ", ".join(f"{p['key']}x{p['doc_count']}" for p in b["by_prefix"]["buckets"])
                print(f"    {b['key']}: {b['doc_count']}  [{pfx}]")


def run_correlation():
    print("\n=== arm->hijack correlation (engine-form, full stream) ===")
    body = json.load(open(CORRELATION))
    body.pop("_comment", None)
    res = search(body)
    buckets = res["aggregations"]["armed_aggregates"]["buckets"]
    if not buckets:
        print("    no arm->hijack correlation")
    for b in buckets:
        k = b["key"]
        print(f"    {k['bundle']}: ROA pulled on {k['cover']} then a not-found announce "
              f"surfaced under it (arm->hijack), {b['hijack_notfound']['doc_count']} not-found announces")


if __name__ == "__main__":
    run_sigma()
    run_correlation()
