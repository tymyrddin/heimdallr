"""Paths and index names for the heimdallr UI.

Data lives on mounts (rules/ read-write so the editor can save, ingest/ read-only);
logic lives in the image. Everything is env-overridable so the app also runs
outside a container during development.
"""
import os

RULES_DIR = os.environ.get("HEIMDALLR_RULES", "/rules")
INGEST_DIR = os.environ.get("HEIMDALLR_INGEST", "/ingest")

LOGS_INDEX = os.environ.get("LOGS_INDEX", "logs")
RUNS_INDEX = os.environ.get("RUNS_INDEX", "heimdallr-runs")
FINDINGS_INDEX = os.environ.get("FINDINGS_INDEX", "heimdallr-findings")

SIGMA_DIR = os.path.join(RULES_DIR, "sigma")