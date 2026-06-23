"""Thin OpenSearch HTTP helpers for the heimdallr UI.

Pure stdlib (urllib), in the same spirit as feeders/load.py and the detector: the
UI carries no heavy client. Everything the Flask app needs to read observations,
bulk-load bundles, and write run/finding records goes through here.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

OS_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")


class OpenSearchError(RuntimeError):
    pass


def _request(method: str, path: str, body=None, ndjson: bool = False):
    url = OS_URL + path
    data = None
    headers = {}
    if body is not None:
        if ndjson:
            data = body.encode() if isinstance(body, str) else body
            headers["Content-Type"] = "application/x-ndjson"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise OpenSearchError(f"{method} {path} -> {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise OpenSearchError(f"{method} {path} -> {e.reason}") from e


def get(path):
    return _request("GET", path)


def put(path, body):
    return _request("PUT", path, body)


def post(path, body=None):
    return _request("POST", path, body)


def delete(path):
    return _request("DELETE", path)


def ping() -> bool:
    """True if the cluster answers. Used by the UI to show stack state."""
    try:
        _request("GET", "/_cluster/health")
        return True
    except OpenSearchError:
        return False


def search(index: str, body: dict) -> dict:
    return _request("POST", f"/{index}/_search", body)


def count(index: str, query: dict | None = None) -> int:
    body = {"query": query} if query else None
    try:
        return _request("POST", f"/{index}/_count", body).get("count", 0)
    except OpenSearchError:
        return 0


def index_exists(index: str) -> bool:
    try:
        _request("GET", f"/{index}")
        return True
    except OpenSearchError:
        return False


def delete_by_query(index: str, query: dict) -> int:
    """Delete matching docs; returns how many. Quietly returns 0 if the index does
    not exist yet (nothing to replace)."""
    if not index_exists(index):
        return 0
    res = _request("POST", f"/{index}/_delete_by_query?refresh=true&conflicts=proceed",
                   {"query": query})
    return res.get("deleted", 0)


def refresh(index: str) -> None:
    try:
        _request("POST", f"/{index}/_refresh")
    except OpenSearchError:
        pass


def bulk_index(index: str, docs, batch: int = 5000) -> tuple[int, int]:
    """Bulk-index an iterable of dicts into `index`. Returns (indexed, errors)."""
    indexed = errors = 0
    buf: list[str] = []

    def flush():
        nonlocal errors
        if not buf:
            return
        res = _request("POST", f"/{index}/_bulk", "".join(buf), ndjson=True)
        if res.get("errors"):
            for item in res.get("items", []):
                if item.get("index", {}).get("error"):
                    errors += 1
        buf.clear()

    for doc in docs:
        buf.append('{"index":{}}\n')
        buf.append(json.dumps(doc) + "\n")
        indexed += 1
        if indexed % batch == 0:
            flush()
    flush()
    return indexed, errors


def index_doc(index: str, doc: dict, doc_id: str | None = None) -> None:
    path = f"/{index}/_doc/{doc_id}?refresh=true" if doc_id else f"/{index}/_doc?refresh=true"
    _request("POST", path, doc)


def loaded_bundles(index: str = "logs") -> dict[str, int]:
    """Distinct `bundle` values currently in the index, with their doc counts.
    This is the source of truth for what is 'loaded': derived, not stored separately."""
    if not index_exists(index):
        return {}
    res = search(index, {
        "size": 0,
        "aggs": {"by_bundle": {"terms": {"field": "bundle", "size": 100}}},
    })
    return {b["key"]: b["doc_count"]
            for b in res["aggregations"]["by_bundle"]["buckets"]}