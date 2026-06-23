#!/usr/bin/env bash
# ctl — heimdallr range control (OpenSearch + Sigma).
#
# heimdallr is a detection engineering lab. Load datasets via the UI, author
# Sigma rules under rules/sigma/, and run detections. ctl brings the stack up
# and tears it down.
#
# Commands:
#   up           start OpenSearch + Dashboards + UI
#   down         stop the stack (data volume kept)
#   status       show services + cluster health
#   detect       compile the Sigma rules and run detections
#   dashboard    print the dashboard URL
#   ui           print the heimdallr UI URL
#   clean        stop and remove the data volume (full reset)
#
# Security (auth/TLS) is disabled on the local node; this is a local range, not an
# exposed service. Do not publish these ports off the host.

set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"

export BUILDX_NO_DEFAULT_ATTESTATIONS=1
COMPOSE="docker compose -f compose/docker-compose.yml"
OS_URL="http://localhost:9200"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_wait_for_opensearch() {
    echo "[ctl] Waiting for OpenSearch ..."
    for _ in $(seq 1 60); do
        if curl -fsS "$OS_URL/_cluster/health" >/dev/null 2>&1; then
            echo "[ctl] OpenSearch is up."
            return 0
        fi
        sleep 3
    done
    echo "[ctl] OpenSearch did not come up in time."; exit 1
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

CMD="${1:-help}"; shift || true

case "$CMD" in

  up)
    echo "[ctl] Starting OpenSearch + Dashboards + UI ..."
    $COMPOSE up -d --build opensearch dashboards ui
    _wait_for_opensearch
    echo ""
    echo "  Range is up."
    echo "  heimdallr UI: http://localhost:5000"
    echo "  Dashboards:   http://localhost:5601"
    echo "  OpenSearch:   $OS_URL"
    echo "  Load data:    open the UI and drop datasets under ingest/"
    echo "  Detect:       ./ctl detect"
    echo "  Stop:         ./ctl down"
    ;;

  detect)
    _wait_for_opensearch
    echo "[ctl] Compiling the Sigma rules and running detections ..."
    $COMPOSE --profile sensors run --rm --build detector
    ;;

  down)
    $COMPOSE down
    ;;

  clean)
    echo "[ctl] Stopping and removing the data volume (full reset) ..."
    $COMPOSE down -v
    ;;

  status)
    $COMPOSE ps
    curl -fsS "$OS_URL/_cluster/health?pretty" 2>/dev/null || echo "[ctl] OpenSearch not answering."
    ;;

  dashboard)
    echo "http://localhost:5601"
    ;;

  ui)
    echo "http://localhost:5000"
    ;;

  help|*)
    cat <<'EOF'
Usage: ./ctl <command>

  up           start OpenSearch + Dashboards + UI
  down         stop the stack (data volume kept)
  status       show services + cluster health
  detect       compile the Sigma rules and run detections
  dashboard    print the dashboard URL
  ui           print the heimdallr UI URL
  clean        stop and remove the data volume (full reset)
EOF
    ;;

esac