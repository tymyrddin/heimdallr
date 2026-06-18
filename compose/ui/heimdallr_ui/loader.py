"""Load bundles into the routing index, idempotently.

Reuses feeders/routing.py's iter_bundle (the single source of truth for what the
feeder relays) and bulk-indexes through the routing index's default pipeline, so the
enrichment runs exactly as it does for `ctl ingest`. Per-bundle load is a
delete-then-load: re-loading a bundle replaces its docs, it never duplicates them
(the re-ingest footgun the old append path had).
"""
from __future__ import annotations

import os
from pathlib import Path

import routing  # feeders/routing.py, on the image PYTHONPATH

from . import config, indices, osclient


def load_bundle(name: str) -> dict:
    bundle_dir = Path(config.INGEST_DIR) / name
    if not (bundle_dir / "events.jsonl").is_file():
        return {"bundle": name, "indexed": 0, "errors": 0, "ok": False,
                "message": "no events.jsonl"}
    osclient.delete_by_query(config.ROUTING_INDEX, {"term": {"bundle": name}})
    indexed, errors = osclient.bulk_index(config.ROUTING_INDEX, routing.iter_bundle(bundle_dir))
    osclient.refresh(config.ROUTING_INDEX)
    return {"bundle": name, "indexed": indexed, "errors": errors, "ok": errors == 0}


def load_bundles(names: list[str]) -> dict:
    """Refresh the pipeline (so VRP params match what is staged), then load each
    bundle idempotently. Returns a per-bundle summary."""
    indices.ensure_routing_content()
    results = [load_bundle(n) for n in names]
    return {
        "results": results,
        "indexed": sum(r["indexed"] for r in results),
        "errors": sum(r["errors"] for r in results),
    }


def unload_bundle(name: str) -> int:
    return osclient.delete_by_query(config.ROUTING_INDEX, {"term": {"bundle": name}})


def available_names() -> list[str]:
    root = config.INGEST_DIR
    if not os.path.isdir(root):
        return []
    return sorted(n for n in os.listdir(root)
                  if (Path(root) / n / "events.jsonl").is_file())