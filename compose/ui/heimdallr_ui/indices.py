"""Ensure heimdallr's spine indices exist.

On startup the UI idempotently applies the templates for the two spine indices:
heimdallr-runs (the experiment ledger) and heimdallr-findings (the detections,
keyed by run_id).
"""
from __future__ import annotations

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
            "matched_docs": {"type": "long"},
            "event": {"type": "object", "enabled": False},
        }},
    },
}


def ensure_spine() -> None:
    """Apply the templates for the run ledger and the findings index."""
    osclient.put(f"/_index_template/{config.RUNS_INDEX}", RUNS_TEMPLATE)
    osclient.put(f"/_index_template/{config.FINDINGS_INDEX}", FINDINGS_TEMPLATE)


_ensured = False


def ensure_all() -> bool:
    """Bring all index templates up if OpenSearch is reachable, once. Returns True
    once applied, False while the cluster is not answering."""
    global _ensured
    if _ensured:
        return True
    if not osclient.ping():
        return False
    ensure_spine()
    _ensured = True
    return True