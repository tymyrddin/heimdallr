"""Ensure heimdallr's indices and the routing detection content exist.

The UI may be the thing that brings detection content up (not just `ctl up`), so on
start it idempotently applies the routing index template + ingest pipeline (reusing
rules/pipeline/build_pipeline.py) and the templates for the two new indices the Run
spine needs: heimdallr-runs (the experiment ledger) and heimdallr-findings (the
detections, keyed by run_id).
"""
from __future__ import annotations

import json

import build_pipeline

from . import config, osclient

RUNS_TEMPLATE = {
    "index_patterns": [config.RUNS_INDEX + "*"],
    "template": {
        "settings": {"index.number_of_shards": 1, "index.number_of_replicas": 0},
        "mappings": {"properties": {
            "run_id": {"type": "keyword"},
            "created": {"type": "date"},
            "status": {"type": "keyword"},
            "bundles": {"type": "keyword"},
            "ruleset_sha256": {"type": "keyword"},
            "rules": {"type": "nested", "properties": {
                "file": {"type": "keyword"},
                "title": {"type": "keyword"},
                "sha256": {"type": "keyword"},
            }},
            "counts": {"properties": {
                "events": {"type": "long"},
                "findings": {"type": "long"},
                "matched_docs": {"type": "long"},
                "by_rule": {"type": "object", "enabled": False},
            }},
            "error": {"type": "text"},
        }},
    },
}

FINDINGS_TEMPLATE = {
    "index_patterns": [config.FINDINGS_INDEX + "*"],
    "template": {
        "settings": {"index.number_of_shards": 1, "index.number_of_replicas": 0},
        "mappings": {"properties": {
            "run_id": {"type": "keyword"},
            "kind": {"type": "keyword"},
            "rule": {"type": "keyword"},
            "rule_title": {"type": "keyword"},
            "bundle": {"type": "keyword"},
            "ts": {"type": "date"},
            "prefix": {"type": "keyword"},
            "origin_as": {"type": "long"},
            "as_path": {"type": "long"},
            "covering_aggregate": {"type": "keyword"},
            "more_specific": {"type": "boolean"},
            "origin_authorised": {"type": "boolean"},
            "rpki_validity": {"type": "keyword"},
            "matched_docs": {"type": "long"},
            "event": {"type": "object", "enabled": False},
        }},
    },
}


def ensure_routing_content() -> None:
    """Apply the routing index template and rebuild the ingest pipeline from the
    baseline + observed VRPs. Idempotent: safe to call on every startup."""
    with open(config.INDEX_TEMPLATE_PATH) as fh:
        osclient.put("/_index_template/routing", json.load(fh))
    pipeline, _, _ = build_pipeline.build_pipeline_body(config.INGEST_DIR, config.BASELINE_PATH)
    osclient.put("/_ingest/pipeline/routing", pipeline)


def ensure_spine() -> None:
    """Apply the templates for the run ledger and the findings index."""
    osclient.put(f"/_index_template/{config.RUNS_INDEX}", RUNS_TEMPLATE)
    osclient.put(f"/_index_template/{config.FINDINGS_INDEX}", FINDINGS_TEMPLATE)


_ensured = False


def ensure_all() -> bool:
    """Bring all detection content up if OpenSearch is reachable, once. Returns True
    once applied, False while the cluster is not answering (the UI still serves,
    showing the stack as down, and retries on the next request). The container can
    start before OpenSearch is ready, so this is lazy rather than start-only."""
    global _ensured
    if _ensured:
        return True
    if not osclient.ping():
        return False
    ensure_routing_content()
    ensure_spine()
    _ensured = True
    return True