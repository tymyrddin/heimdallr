"""Read-side of the Data page: list bundles in ingest/, their metadata, and the
bundle explorer (paged event browsing + raw JSON).

This reads the ingest artefacts directly, so the explorer works before a bundle is
loaded. "Why didn't my rule fire" is usually answered here: the data was not what
you thought. Loaded-state is layered on from the routing index.
"""
from __future__ import annotations

import json
import os

from . import config, osclient


def _bundle_dirs() -> list[str]:
    root = config.INGEST_DIR
    if not os.path.isdir(root):
        return []
    out = []
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if os.path.isdir(d) and os.path.isfile(os.path.join(d, "events.jsonl")):
            out.append(name)
    return out


def _event_count(name: str) -> int:
    path = os.path.join(config.INGEST_DIR, name, "events.jsonl")
    n = 0
    try:
        with open(path) as fh:
            for _ in fh:
                n += 1
    except OSError:
        return 0
    return n


def _extras(name: str) -> list[str]:
    """Substrate extras a bundle carries beyond plain routing: an AS_PATH on its
    events (+path), an IRR export (+IRR). Read from the artefacts, not assumed."""
    d = os.path.join(config.INGEST_DIR, name)
    extras = []
    events = os.path.join(d, "events.jsonl")
    try:
        with open(events) as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except ValueError:
                    continue
                # Decide on the first announce: withdraws carry no path.
                if ev.get("type") == "announce":
                    if ev.get("as_path"):
                        extras.append("path")
                    break
    except OSError:
        pass
    if os.path.isfile(os.path.join(d, "irr-routes.txt")):
        extras.append("IRR")
    return extras


def list_bundles() -> list[dict]:
    """Every bundle in ingest/ with event count, extras, and loaded state."""
    loaded = osclient.loaded_bundles(config.ROUTING_INDEX)
    out = []
    for name in _bundle_dirs():
        out.append({
            "name": name,
            "events": _event_count(name),
            "extras": _extras(name),
            "loaded": name in loaded,
            "loaded_docs": loaded.get(name, 0),
        })
    return out


def bundle_metadata(name: str) -> dict | None:
    d = os.path.join(config.INGEST_DIR, name)
    if not os.path.isdir(d):
        return None
    origins: set[int] = set()
    max_hops = 0
    announces = withdraws = 0
    events_path = os.path.join(d, "events.jsonl")
    try:
        with open(events_path) as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except ValueError:
                    continue
                if ev.get("type") == "announce":
                    announces += 1
                    if ev.get("origin_as") is not None:
                        origins.add(ev["origin_as"])
                    max_hops = max(max_hops, len(ev.get("as_path") or []))
                elif ev.get("type") == "withdraw":
                    withdraws += 1
    except OSError:
        return None

    vrp_count = 0
    vpath = os.path.join(d, "vrps.json")
    if os.path.isfile(vpath):
        try:
            vrp_count = len(json.load(open(vpath)).get("roas", []))
        except (OSError, ValueError):
            vrp_count = 0

    files = sorted(f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)))
    loaded = osclient.loaded_bundles(config.ROUTING_INDEX)
    return {
        "name": name,
        "events": announces + withdraws,
        "announces": announces,
        "withdraws": withdraws,
        "origins": sorted(origins),
        "max_hops": max_hops,
        "vrp_count": vrp_count,
        "extras": _extras(name),
        "files": files,
        "loaded": name in loaded,
        "loaded_docs": loaded.get(name, 0),
    }


def browse_events(name: str, offset: int = 0, size: int = 50) -> dict:
    """A page of raw BMP events for the explorer, read straight from the artefact."""
    path = os.path.join(config.INGEST_DIR, name, "events.jsonl")
    rows = []
    total = 0
    try:
        with open(path) as fh:
            for i, raw in enumerate(fh):
                raw = raw.strip()
                if not raw:
                    continue
                total += 1
                if offset <= i < offset + size:
                    try:
                        rows.append(json.loads(raw))
                    except ValueError:
                        rows.append({"_raw": raw})
    except OSError:
        return {"name": name, "rows": [], "total": 0, "offset": offset, "size": size}
    return {"name": name, "rows": rows, "total": total, "offset": offset, "size": size}