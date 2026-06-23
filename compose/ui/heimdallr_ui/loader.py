"""Load datasets into OpenSearch, idempotently.

Reads every .jsonl file in a bundle directory and bulk-indexes the events into
the logs index. Per-bundle load is a delete-then-load: re-loading a bundle
replaces its docs, it never duplicates them.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import config, indices, osclient


def _iter_bundle(bundle_dir: Path):
    for jsonl_file in sorted(bundle_dir.glob("*.jsonl")):
        with jsonl_file.open() as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except ValueError:
                    continue


def load_bundle(name: str) -> dict:
    bundle_dir = Path(config.INGEST_DIR) / name
    if not any(bundle_dir.glob("*.jsonl")):
        return {"bundle": name, "indexed": 0, "errors": 0, "ok": False,
                "message": "no .jsonl files found"}
    osclient.delete_by_query(config.LOGS_INDEX, {"term": {"bundle": name}})
    indexed, errors = osclient.bulk_index(config.LOGS_INDEX, _iter_bundle(bundle_dir))
    osclient.refresh(config.LOGS_INDEX)
    return {"bundle": name, "indexed": indexed, "errors": errors, "ok": errors == 0}


def load_bundles(names: list[str]) -> dict:
    indices.ensure_spine()
    results = [load_bundle(n) for n in names]
    return {
        "results": results,
        "indexed": sum(r["indexed"] for r in results),
        "errors": sum(r["errors"] for r in results),
    }


def unload_bundle(name: str) -> int:
    return osclient.delete_by_query(config.LOGS_INDEX, {"term": {"bundle": name}})


def available_names() -> list[str]:
    root = config.INGEST_DIR
    if not os.path.isdir(root):
        return []
    return sorted(
        n for n in os.listdir(root)
        if os.path.isdir(os.path.join(root, n))
        and any(Path(os.path.join(root, n)).glob("*.jsonl"))
    )