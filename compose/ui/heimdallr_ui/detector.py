"""Detection runs: compile the selected Sigma rules with pySigma, run them over the
loaded bundles, and persist a Run plus its findings.

A Run is the spine object. Everything else (the Detections live view, the
Experiments ledger and diff) is a view over heimdallr-runs / heimdallr-findings.

A finding is a DISTINCT anomaly, not a raw document: matches are bucketed by
(bundle, prefix, origin_as), so the route-leak flood of 36k repeated announces
collapses to the handful of leaked prefixes a detection engineer actually cares
about. Each finding keeps a representative observation for the why-it-fired view and
a matched_docs count for the noise-vs-signal story.

The Run snapshots the body hash of every selected rule (ruleset_sha256), so the
Experiments diff stays honest when a rule is edited in place. There is deliberately
no expected-findings notion: findings are what fired, never a target.
"""
from __future__ import annotations

import datetime
import glob
import hashlib
import json
import os
import uuid

from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend

from . import config, osclient

_CORRELATION_NAME = "arm-hijack-correlation"
_FINDING_BUCKETS = 1000


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def available_rules() -> list[dict]:
    """Every selectable detection: the Sigma rules under rules/sigma plus the
    engine-form arm->hijack correlation."""
    out = []
    for path in sorted(glob.glob(os.path.join(config.SIGMA_DIR, "*.yml"))):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            title = SigmaCollection.load_ruleset([path]).rules[0].title
        except Exception:  # noqa: BLE001 - a broken rule still lists, flagged elsewhere
            title = name
        out.append({"name": name, "kind": "sigma", "title": title, "path": path})
    if os.path.isfile(config.CORRELATION_PATH):
        out.append({"name": _CORRELATION_NAME, "kind": "correlation",
                    "title": "arm->hijack correlation", "path": config.CORRELATION_PATH})
    return out


def validate_rule(text: str) -> dict:
    """Compile a Sigma rule body with pySigma. Returns {ok, query|error} for the
    editor's inline validate."""
    try:
        rules = SigmaCollection.from_yaml(text)
        queries = OpensearchLuceneBackend().convert(rules)
        return {"ok": True, "queries": queries}
    except Exception as exc:  # noqa: BLE001 - report the compile error to the editor
        return {"ok": False, "error": str(exc)}


def _bundle_filter(bundles: list[str]) -> dict:
    return {"terms": {"bundle": bundles}}


def _sigma_findings(run_id: str, rule: dict, bundles: list[str]) -> list[dict]:
    """Run one Sigma rule scoped to the selected bundles and collapse matches into
    distinct findings."""
    backend = OpensearchLuceneBackend()
    rules = SigmaCollection.load_ruleset([rule["path"]])
    title = rules.rules[0].title
    findings: list[dict] = []
    for query in backend.convert(rules):
        body = {
            "size": 0,
            "query": {"bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [_bundle_filter(bundles)],
            }},
            "aggs": {"f": {
                "composite": {"size": _FINDING_BUCKETS, "sources": [
                    {"bundle": {"terms": {"field": "bundle"}}},
                    {"prefix": {"terms": {"field": "prefix"}}},
                    {"origin_as": {"terms": {"field": "origin_as", "missing_bucket": True}}},
                ]},
                "aggs": {"rep": {"top_hits": {"size": 1}}},
            }},
        }
        res = osclient.search(config.ROUTING_INDEX, body)
        for bucket in res["aggregations"]["f"]["buckets"]:
            src = bucket["rep"]["hits"]["hits"][0]["_source"]
            findings.append({
                "run_id": run_id, "kind": "sigma",
                "rule": rule["name"], "rule_title": title,
                "bundle": bucket["key"]["bundle"],
                "ts": src.get("ts"),
                "prefix": src.get("prefix"),
                "origin_as": src.get("origin_as"),
                "as_path": src.get("as_path"),
                "covering_aggregate": src.get("covering_aggregate"),
                "more_specific": src.get("more_specific"),
                "origin_authorised": src.get("origin_authorised"),
                "rpki_validity": src.get("rpki_validity"),
                "matched_docs": bucket["doc_count"],
                "event": src,
            })
    return findings


def _correlation_findings(run_id: str, rule: dict, bundles: list[str]) -> list[dict]:
    """Run the engine-form arm->hijack correlation scoped to the selected bundles."""
    body = json.load(open(rule["path"]))
    body.pop("_comment", None)
    existing = body.setdefault("query", {}).setdefault("bool", {}).setdefault("filter", [])
    existing.append(_bundle_filter(bundles))
    res = osclient.search(config.ROUTING_INDEX, body)
    findings = []
    for bucket in res["aggregations"]["armed_aggregates"]["buckets"]:
        key = bucket["key"]
        findings.append({
            "run_id": run_id, "kind": "correlation",
            "rule": rule["name"], "rule_title": rule["title"],
            "bundle": key["bundle"],
            "covering_aggregate": key["cover"],
            "matched_docs": bucket["hijack_notfound"]["doc_count"],
            "event": {"arm": "roa-remove", "hijack": "notfound-announce",
                      "covering_aggregate": key["cover"]},
        })
    return findings


def run_detection(bundles: list[str], rule_names: list[str]) -> dict:
    """Execute a detection run and persist it. Returns the Run record."""
    from . import indices
    indices.ensure_spine()
    run_id = "run-" + uuid.uuid4().hex[:10]
    by_name = {r["name"]: r for r in available_rules()}
    selected = [by_name[n] for n in rule_names if n in by_name]

    snapshot = []
    for r in selected:
        try:
            body = open(r["path"]).read()
        except OSError:
            body = ""
        snapshot.append({"file": os.path.basename(r["path"]), "title": r["title"],
                         "sha256": _sha256(body)})
    ruleset_sha = _sha256("".join(sorted(s["sha256"] for s in snapshot)))

    run = {
        "run_id": run_id, "created": _now(), "status": "running",
        "bundles": bundles, "rules": snapshot, "ruleset_sha256": ruleset_sha,
        "counts": {"events": 0, "findings": 0, "matched_docs": 0, "by_rule": {}},
    }
    osclient.index_doc(config.RUNS_INDEX, run, doc_id=run_id)

    try:
        all_findings: list[dict] = []
        by_rule: dict[str, int] = {}
        for r in selected:
            if r["kind"] == "correlation":
                fs = _correlation_findings(run_id, r, bundles)
            else:
                fs = _sigma_findings(run_id, r, bundles)
            by_rule[r["name"]] = len(fs)
            all_findings.extend(fs)

        if all_findings:
            osclient.bulk_index(config.FINDINGS_INDEX, all_findings)
            osclient.refresh(config.FINDINGS_INDEX)

        events = osclient.count(config.ROUTING_INDEX, _bundle_filter(bundles)) if bundles else 0
        run["status"] = "complete"
        run["counts"] = {
            "events": events,
            "findings": len(all_findings),
            "matched_docs": sum(f.get("matched_docs", 0) for f in all_findings),
            "by_rule": by_rule,
        }
    except Exception as exc:  # noqa: BLE001 - record the failure on the run
        run["status"] = "error"
        run["error"] = str(exc)
    osclient.index_doc(config.RUNS_INDEX, run, doc_id=run_id)
    return run


def list_runs(limit: int = 50) -> list[dict]:
    if not osclient.index_exists(config.RUNS_INDEX):
        return []
    res = osclient.search(config.RUNS_INDEX, {
        "size": limit, "sort": [{"created": "desc"}], "query": {"match_all": {}},
    })
    return [h["_source"] for h in res["hits"]["hits"]]


def get_run(run_id: str) -> dict | None:
    if not osclient.index_exists(config.RUNS_INDEX):
        return None
    res = osclient.search(config.RUNS_INDEX, {
        "size": 1, "query": {"term": {"run_id": run_id}},
    })
    hits = res["hits"]["hits"]
    return hits[0]["_source"] if hits else None


def run_findings(run_id: str, limit: int = 2000) -> list[dict]:
    if not osclient.index_exists(config.FINDINGS_INDEX):
        return []
    res = osclient.search(config.FINDINGS_INDEX, {
        "size": limit, "query": {"term": {"run_id": run_id}},
    })
    return [h["_source"] for h in res["hits"]["hits"]]