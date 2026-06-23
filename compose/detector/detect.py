#!/usr/bin/env python3
"""heimdallr detector: compile Sigma rules with pySigma and run them against OpenSearch."""
import glob
import json
import os
import urllib.request

from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend

OS_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
INDEX = os.environ.get("LOGS_INDEX", "logs")
RULES = os.environ.get("SIGMA_DIR", "/rules/sigma")


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
                "aggs": {"by_bundle": {"terms": {"field": "bundle", "size": 20}}},
            })
            total = res["hits"]["total"]["value"]
            print(f"\n[{title}]  ({total} hits)")
            print(f"    query: {query}")
            for b in res["aggregations"]["by_bundle"]["buckets"]:
                print(f"    {b['key']}: {b['doc_count']}")


if __name__ == "__main__":
    run_sigma()