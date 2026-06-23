"""Detection runs: compile the selected Sigma rules with pySigma, run them over the
loaded datasets, and persist a Run plus its findings.

A Run is the spine object. The Experiments ledger shows run history and diffs.

A finding collapses all matches for a rule in a bundle into one record with a
representative event and a matched_docs count.
"""
from __future__ import annotations

import datetime
import glob
import hashlib
import os
import uuid

from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend

from . import config, osclient

_FINDING_BUCKETS = 1000


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def available_rules() -> list[dict]:
    """Every selectable detection: the Sigma rules under rules/sigma."""
    out = []
    for path in sorted(glob.glob(os.path.join(config.SIGMA_DIR, "*.yml"))):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            title = SigmaCollection.load_ruleset([path]).rules[0].title
        except Exception:  # noqa: BLE001
            title = name
        out.append({"name": name, "kind": "sigma", "title": title, "path": path})
    return out


def validate_rule(text: str) -> dict:
    """Compile a Sigma rule body with pySigma. Returns {ok, queries|error}."""
    try:
        rules = SigmaCollection.from_yaml(text)
        queries = OpensearchLuceneBackend().convert(rules)
        return {"ok": True, "queries": queries}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def _bundle_filter(bundles: list[str]) -> dict:
    return {"terms": {"bundle": bundles}}


def _sigma_findings(run_id: str, rule: dict, bundles: list[str]) -> list[dict]:
    """Run one Sigma rule scoped to the selected bundles and collapse matches into
    per-bundle findings."""
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
            "aggs": {"by_bundle": {
                "terms": {"field": "bundle", "size": _FINDING_BUCKETS},
                "aggs": {"rep": {"top_hits": {"size": 1}}},
            }},
        }
        res = osclient.search(config.LOGS_INDEX, body)
        for bucket in res["aggregations"]["by_bundle"]["buckets"]:
            src = bucket["rep"]["hits"]["hits"][0]["_source"]
            findings.append({
                "run_id": run_id, "kind": "sigma",
                "rule": rule["name"], "rule_title": title,
                "bundle": bucket["key"],
                "ts": src.get("ts") or src.get("@timestamp"),
                "matched_docs": bucket["doc_count"],
                "event": src,
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
            fs = _sigma_findings(run_id, r, bundles)
            by_rule[r["name"]] = len(fs)
            all_findings.extend(fs)

        if all_findings:
            osclient.bulk_index(config.FINDINGS_INDEX, all_findings)
            osclient.refresh(config.FINDINGS_INDEX)

        events = osclient.count(config.LOGS_INDEX, _bundle_filter(bundles)) if bundles else 0
        run["status"] = "complete"
        run["counts"] = {
            "events": events,
            "findings": len(all_findings),
            "matched_docs": sum(f.get("matched_docs", 0) for f in all_findings),
            "by_rule": by_rule,
        }
    except Exception as exc:  # noqa: BLE001
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