#!/usr/bin/env bash
# ctl — heimdallr range control (OpenSearch + Sigma).
#
# heimdallr is a live detection range, not a wire tap. Inputs arrive as files in
# ingest/, the routing feeder relays them as observations into OpenSearch, an
# ingest pipeline enriches them (RFC 6811 ROV + covering aggregate, against
# heimdallr's baseline), and detections surface on the dashboard. ctl brings the
# stack up, applies the detection content (index template + ingest pipeline),
# ingests, and tears down.
#
# Commands:
#   up           start OpenSearch + Dashboards, apply the detection content
#   down         stop the stack (data volume kept)
#   status       show services + cluster health
#   ingest       relay ingest/ into OpenSearch (refreshes the pipeline first)
#   detect       compile the Sigma rules and run detections + correlation
#   dashboard    print the dashboard URL
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

# Apply heimdallr's routing detection content: the index template (mappings +
# default pipeline) and the ingest pipeline (normalise + ROV/covering enrichment,
# built from rules/baseline/aggregates.json and the observed VRPs in ingest/).
_apply_detection() {
    echo "[ctl] Applying the routing index template ..."
    curl -fsS -XPUT "$OS_URL/_index_template/routing" \
        -H 'Content-Type: application/json' \
        --data-binary @rules/pipeline/index-routing.json >/dev/null
    echo "[ctl] Building and applying the routing ingest pipeline ..."
    OPENSEARCH_URL="$OS_URL" python3 rules/pipeline/build_pipeline.py ingest
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
    _apply_detection
    echo ""
    echo "  Range is up."
    echo "  heimdallr UI: http://localhost:5000"
    echo "  Dashboards:   http://localhost:5601"
    echo "  OpenSearch:   $OS_URL"
    echo "  Load + run:   open the UI, or  ./ctl ingest  then  ./ctl detect"
    echo "  Stop:         ./ctl down"
    ;;

  ingest)
    _wait_for_opensearch
    # Refresh the pipeline so its VRP params match whatever is staged in ingest/.
    _apply_detection
    echo "[ctl] Relaying ingest/ into OpenSearch via the routing feeder ..."
    $COMPOSE --profile sensors run --rm --build routing
    curl -fsS -XPOST "$OS_URL/routing/_refresh" >/dev/null 2>&1 || true
    echo "[ctl] Done. Watch the dashboard, or run a detection query."
    ;;

  detect)
    _wait_for_opensearch
    echo "[ctl] Compiling the Sigma rules and running detections + correlation ..."
    $COMPOSE --profile sensors run --rm --build routing-detector
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

  up           start OpenSearch + Dashboards, apply the detection content
  down         stop the stack (data volume kept)
  status       show services + cluster health
  ingest       relay ingest/ into OpenSearch (refreshes the pipeline first)
  detect       compile the Sigma rules and run detections + correlation
  dashboard    print the dashboard URL
  ui           print the heimdallr UI URL
  clean        stop and remove the data volume (full reset)
EOF
    ;;

esac
