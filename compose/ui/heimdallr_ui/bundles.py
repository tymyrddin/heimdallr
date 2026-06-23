"""Dataset browser: list datasets in ingest/, their metadata, and event browsing."""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import config, osclient


def _bundle_dirs() -> list[str]:
    root = config.INGEST_DIR
    if not os.path.isdir(root):
        return []
    return sorted(
        n for n in os.listdir(root)
        if os.path.isdir(os.path.join(root, n))
        and any(Path(os.path.join(root, n)).glob("*.jsonl"))
    )


def _event_count(bundle_dir: Path) -> int:
    n = 0
    for jsonl_file in bundle_dir.glob("*.jsonl"):
        try:
            with jsonl_file.open() as fh:
                for _ in fh:
                    n += 1
        except OSError:
            pass
    return n


def list_bundles() -> list[dict]:
    """Every dataset in ingest/ with event count and loaded state."""
    loaded = osclient.loaded_bundles(config.LOGS_INDEX)
    out = []
    for name in _bundle_dirs():
        bundle_dir = Path(config.INGEST_DIR) / name
        out.append({
            "name": name,
            "events": _event_count(bundle_dir),
            "loaded": name in loaded,
            "loaded_docs": loaded.get(name, 0),
        })
    return out


def bundle_metadata(name: str) -> dict | None:
    bundle_dir = Path(config.INGEST_DIR) / name
    if not bundle_dir.is_dir():
        return None
    files = sorted(f for f in os.listdir(bundle_dir) if (bundle_dir / f).is_file())
    jsonl_files = [f for f in files if f.endswith(".jsonl")]
    if not jsonl_files:
        return None
    loaded = osclient.loaded_bundles(config.LOGS_INDEX)
    return {
        "name": name,
        "files": files,
        "jsonl_files": jsonl_files,
        "events": _event_count(bundle_dir),
        "loaded": name in loaded,
        "loaded_docs": loaded.get(name, 0),
    }


def browse_events(name: str, offset: int = 0, size: int = 50) -> dict:
    """A page of raw events for the explorer, read straight from the JSONL files."""
    bundle_dir = Path(config.INGEST_DIR) / name
    rows = []
    total = 0
    i = 0
    for jsonl_file in sorted(bundle_dir.glob("*.jsonl")):
        try:
            with jsonl_file.open() as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    total += 1
                    if offset <= i < offset + size:
                        try:
                            rows.append(json.loads(raw))
                        except ValueError:
                            rows.append({"_raw": raw})
                    i += 1
        except OSError:
            break
    return {"name": name, "rows": rows, "total": total, "offset": offset, "size": size}