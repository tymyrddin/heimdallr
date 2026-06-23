#!/usr/bin/env python3
"""heimdallr UI: the Flask surface.

Four verbs, the detection-engineer's workflow: Data (what do I have), Detections
(what am I testing), Findings (what happened), Experiments (did it improve). This
slice builds the spine (the Run object + heimdallr-runs/heimdallr-findings) and the
Data page (bundle list, idempotent load, and the bundle explorer); the other three
pages are wired to the spine but filled in next.
"""
from __future__ import annotations

from flask import (Flask, abort, jsonify, redirect, render_template,
                   request, url_for)

from heimdallr_ui import bundles, config, detector, indices, jobs, loader, osclient

app = Flask(__name__)

@app.before_request
def _ensure_content():
    # The container can start before OpenSearch is ready, so apply detection content
    # lazily (idempotent, once) rather than only at boot. Never let it crash a page.
    try:
        indices.ensure_all()
    except Exception:  # noqa: BLE001
        pass


@app.context_processor
def _nav():
    return {"stack_up": osclient.ping(), "active_jobs": jobs.active()}


@app.route("/")
def index():
    return redirect(url_for("data"))


# --- Data -------------------------------------------------------------------

@app.route("/data")
def data():
    return render_template("data.html", bundles=bundles.list_bundles(),
                           recent_jobs=jobs.recent(8))


@app.route("/bundles/load", methods=["POST"])
def bundles_load():
    names = request.form.getlist("bundles")
    if names:
        label = "load " + (", ".join(names) if len(names) <= 3 else f"{len(names)} bundles")
        jobs.submit("load", label, lambda ns=names: loader.load_bundles(ns))
    return redirect(url_for("data"))


@app.route("/bundles/unload", methods=["POST"])
def bundles_unload():
    name = request.form.get("bundle")
    if name:
        jobs.submit("unload", f"unload {name}", lambda n=name: {"deleted": loader.unload_bundle(n)})
    return redirect(url_for("data"))


@app.route("/bundles/<name>")
def bundle_detail(name):
    meta = bundles.bundle_metadata(name)
    if meta is None:
        abort(404)
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        offset = 0
    page = bundles.browse_events(name, offset=offset, size=50)
    return render_template("bundle.html", meta=meta, page=page)


# --- Jobs (polled by the page) ---------------------------------------------

@app.route("/jobs")
def jobs_list():
    return jsonify(jobs.recent(20))


@app.route("/jobs/<job_id>")
def job_detail(job_id):
    j = jobs.get(job_id)
    return (jsonify(j), 200) if j else (jsonify({"error": "not found"}), 404)


# --- Spine views, filled in next slice -------------------------------------

@app.route("/detections")
def detections():
    return render_template("placeholder.html", page="Detections",
                           note="Sigma editor, rule selection and Run land in the next slice.",
                           rules=detector.available_rules(),
                           loaded=osclient.loaded_bundles(config.LOGS_INDEX))


@app.route("/findings")
def findings():
    return render_template("placeholder.html", page="Findings",
                           note="Findings detail (by rule / by bundle / why-fired) lands next.")


@app.route("/experiments")
def experiments():
    return render_template("experiments.html", runs=detector.list_runs())


# Spine API: lets a run be created before the Detections page exists, so the
# Experiments ledger and the Run object can be exercised end to end now.
@app.route("/api/runs", methods=["POST"])
def api_create_run():
    payload = request.get_json(force=True, silent=True) or {}
    bundle_names = payload.get("bundles") or list(osclient.loaded_bundles(config.LOGS_INDEX))
    rule_names = payload.get("rules") or [r["name"] for r in detector.available_rules()]
    job_id = jobs.submit("run", "detection run",
                         lambda b=bundle_names, r=rule_names: detector.run_detection(b, r))
    return jsonify({"job": job_id, "bundles": bundle_names, "rules": rule_names})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)