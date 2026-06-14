#!/usr/bin/env bash
# ctl — heimdallr range control.
#
# heimdallr is a live detection range, not a wire tap. Inputs arrive as files in
# ingest/, the sensors read them in file mode, and Wazuh raises alerts on the
# dashboard. ctl brings the stack up, seeds the rule workspace from a scenario
# baseline (or every baseline in SOC mode), runs the sensors over the ingested
# captures, and reloads the workspace after edits.
#
# Commands:
#   up [--scenario N | --mode soc]  build, seed the workspace, start the stack
#   down                            stop the stack (data volumes kept)
#   status                          show running services
#   ingest                          run the sensors over ingest/ now
#   scenario NAME                   seed a scenario, reload, then ingest
#   reload                          reload the Wazuh manager after rule edits
#   dashboard                       print the dashboard URL
#   set-password [PASS]             rotate the indexer admin password
#   clean                           stop and remove data volumes (full reset)
#
# .env is the single source of truth for credentials and is never generated
# here. The indexer admin hash is derived from it (see _render_internal_users).

set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"

# BuildKit's default provenance attestations hang in offline environments.
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

COMPOSE="docker compose -f compose/docker-compose.yml --env-file .env"
WORKSPACE="rules/workspace"
BASELINE="rules/baseline"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# .env is the single source of truth. It is the operator's file, never generated
# here, so it cannot silently drift. ctl reads the password from it and derives
# everything else (the indexer hash) from it. If it is missing, say how to make
# one rather than inventing values.
_require_env() {
    [ -f .env ] && return 0
    echo "[ctl] No .env found. Create it from the example, then edit if you like:"
    echo "        cp env.sample .env"
    exit 1
}

_env_value() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }

# Derive a bcrypt hash for a password using the indexer image's own hash tool,
# so we never hand-maintain a hash that has to match a plaintext elsewhere.
_hash_password() {
    docker run --rm wazuh/wazuh-indexer:4.14.5 sh -c \
      'export OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk; exec bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$1"' \
      _ "$1" 2>/dev/null | grep -E '^\$2' | head -1
}

# Render the indexer's internal_users.yml from its committed template, with the
# admin hash derived from INDEXER_PASSWORD in .env. This is what makes .env the
# one source of truth: the hash the indexer enforces is always computed from the
# plaintext the manager and dashboard send, so the two cannot disagree. The
# rendered file is gitignored; the template is committed.
_render_internal_users() {
    local tmpl="compose/config/wazuh_indexer/internal_users.template.yml"
    local out="compose/config/wazuh_indexer/internal_users.yml"
    local pass hash
    pass="$(_env_value INDEXER_PASSWORD)"
    [ -n "$pass" ] || { echo "[ctl] INDEXER_PASSWORD is not set in .env"; exit 1; }
    echo "[ctl] Deriving the indexer admin hash from .env ..."
    hash="$(_hash_password "$pass")"
    case "$hash" in
      \$2*) : ;;
      *) echo "[ctl] Could not derive a password hash from the indexer image"; exit 1;;
    esac
    sed "s|__ADMIN_HASH__|${hash}|" "$tmpl" > "$out"
}

# Check the .env admin password against the running indexer. On a fresh boot the
# derived hash always matches; this only fails if the password was changed in
# .env without rotating the live cluster, and it says how to fix that.
_check_indexer_auth() {
    local pass code
    pass="$(_env_value INDEXER_PASSWORD)"
    code="$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:${pass}" https://localhost:9200/ 2>/dev/null || true)"
    case "$code" in
      200) echo "[ctl] Indexer credentials OK." ;;
      401) echo "[ctl] WARNING: indexer rejected the .env admin password. The live"
           echo "       cluster predates it. Apply it with:  ./ctl set-password $pass" ;;
      *)   echo "[ctl] Indexer not answering yet (HTTP ${code:-none}); credential check skipped." ;;
    esac
}

# Generate the TLS certificates on first use. The wazuh-certs-generator writes
# them into compose/config/wazuh_indexer_ssl_certs, which the stack bind-mounts.
_ensure_certs() {
    # Pre-create the dir as the current user so the certs generator (which runs
    # as root in its container) does not leave a root-owned directory behind.
    mkdir -p compose/config/wazuh_indexer_ssl_certs
    [ -f compose/config/wazuh_indexer_ssl_certs/root-ca.pem ] && return 0
    echo "[ctl] No certificates yet, running the Wazuh certs generator ..."
    docker compose -f compose/generate-indexer-certs.yml run --rm generator
}

# Pre-create the per-source stream files the collector tails, empty, so
# logcollector follows them from offset zero. The sensors append their per-run
# output; a batch file the agent only discovers afterwards would be tailed from
# the end and skipped. Volume name is <project>_sensor-logs (project: heimdallr).
_ensure_stream() {
    docker run --rm -v heimdallr_sensor-logs:/l alpine:3 sh -c \
      'mkdir -p /l/stream && touch /l/stream/suricata.json /l/stream/zeek.json /l/stream/routing.json /l/stream/host.json' \
      >/dev/null 2>&1
}

# Seed the live rule workspace that the manager bind-mounts. With a scenario,
# copy that scenario's baseline. In SOC mode, concatenate every baseline. With
# neither, leave an existing workspace alone, or lay down empty valid files.
_seed_workspace() {
    local sel="${1:-}"
    mkdir -p "$WORKSPACE"
    local rules="$WORKSPACE/local_rules.xml"
    local decoder="$WORKSPACE/local_decoder.xml"
    if [ "$sel" = "soc" ]; then
        { echo '<!-- heimdallr SOC mode: every baseline ruleset. -->'
          cat "$BASELINE"/*/local_rules.xml 2>/dev/null; } > "$rules"
        { echo '<!-- heimdallr SOC mode: every baseline decoder set. -->'
          cat "$BASELINE"/*/local_decoder.xml 2>/dev/null; } > "$decoder"
        echo "[ctl] Workspace seeded from all baselines (SOC mode)."
    elif [ -n "$sel" ]; then
        [ -d "$BASELINE/$sel" ] || { echo "[ctl] No baseline for '$sel' under $BASELINE/"; exit 1; }
        cp "$BASELINE/$sel/local_rules.xml" "$rules"
        cp "$BASELINE/$sel/local_decoder.xml" "$decoder"
        echo "[ctl] Workspace seeded from baseline/$sel."
    else
        # Empty workspace still needs a valid, inert rule: Wazuh's analysisd
        # refuses to start on a <group> with no rules, which takes the whole
        # manager down with it.
        if [ ! -f "$rules" ]; then
            cat > "$rules" <<'XML'
<!-- heimdallr empty workspace. One inert placeholder so analysisd starts. Load
     a scenario baseline, or replace this with your own rules. -->
<group name="local,heimdallr,">
  <rule id="100100" level="0">
    <match>heimdallr-placeholder-never-matches</match>
    <description>heimdallr workspace placeholder, inert until you add rules</description>
  </rule>
</group>
XML
        fi
        [ -f "$decoder" ] || printf '<!-- heimdallr decoders -->\n' > "$decoder"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

CMD="${1:-help}"; shift || true

case "$CMD" in

  up)
    SCENARIO=""; MODE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --scenario) SCENARIO="${2:?--scenario needs a name}"; shift 2;;
        --mode)     MODE="${2:?--mode needs a value}"; shift 2;;
        *) echo "[ctl] unknown argument: $1"; exit 1;;
      esac
    done
    _require_env
    _render_internal_users
    _ensure_certs
    _ensure_stream
    if [ "$MODE" = "soc" ]; then _seed_workspace soc
    elif [ -n "$SCENARIO" ]; then _seed_workspace "$SCENARIO"
    else _seed_workspace; fi
    echo "[ctl] Building and starting the core stack ..."
    $COMPOSE up -d --build wazuh.indexer wazuh.manager wazuh.dashboard collector
    echo ""
    echo "  Range is up. The indexer takes a minute or two to bootstrap on first boot."
    echo "  Dashboard:  https://localhost   (admin / INDEXER_PASSWORD from .env)"
    echo "  Ingest:     drop captures in ingest/ then  ./ctl ingest"
    echo "  Rules:      edit rules/workspace/ then  ./ctl reload"
    echo "  Stop:       ./ctl down"
    ;;

  down)
    $COMPOSE down
    ;;

  status)
    $COMPOSE ps
    [ -f .env ] && _check_indexer_auth
    ;;

  ingest)
    echo "[ctl] Running the offline sensors over ingest/ ..."
    $COMPOSE --profile sensors run --rm --build zeek
    $COMPOSE --profile sensors run --rm --build suricata
    echo "[ctl] Routing artefacts go through feeders/routing.py (M2, not wired yet)."
    echo "[ctl] Sensors done. Watch the dashboard for alerts."
    ;;

  scenario)
    NAME="${1:?usage: ./ctl scenario NAME}"
    [ -d "scenarios/$NAME" ] || { echo "[ctl] No scenario '$NAME' under scenarios/"; exit 1; }
    _seed_workspace "$NAME"
    # A scenario manifest can stage its inputs into ingest/; that wiring is M2.
    "$REPO/ctl" reload || true
    "$REPO/ctl" ingest
    ;;

  reload)
    echo "[ctl] Reloading the Wazuh manager (picks up rules/workspace edits) ..."
    $COMPOSE exec wazuh.manager /var/ossec/bin/wazuh-control restart
    ;;

  dashboard)
    echo "https://localhost   (admin / INDEXER_PASSWORD from .env)"
    ;;

  set-password)
    # Rotate the indexer admin password: .env stays the one source of truth, the
    # hash is re-derived from it, and the change is applied to the live cluster.
    _require_env
    NEW="${1:-}"
    if [ -z "$NEW" ]; then read -r -s -p "New indexer admin password: " NEW; echo; fi
    [ -n "$NEW" ] || { echo "[ctl] empty password, aborting"; exit 1; }
    if grep -qE '^INDEXER_PASSWORD=' .env; then
      sed -i "s|^INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${NEW}|" .env
    else
      printf 'INDEXER_PASSWORD=%s\n' "$NEW" >> .env
    fi
    _render_internal_users
    if docker ps --format '{{.Names}}' | grep -q '^heimdallr-wazuh.indexer-1$'; then
      echo "[ctl] Applying the new password to the running indexer ..."
      certs=/usr/share/wazuh-indexer/config/certs
      docker exec heimdallr-wazuh.indexer-1 sh -c \
        "export OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk; exec bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
         -f /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml \
         -t internalusers -icl -nhnv \
         -cacert $certs/root-ca.pem -cert $certs/admin.pem -key $certs/admin-key.pem -h localhost"
      echo "[ctl] Recreating manager (fresh filebeat credential) and dashboard ..."
      $COMPOSE rm -sf wazuh.manager >/dev/null 2>&1 || true
      docker volume rm heimdallr_filebeat_etc heimdallr_filebeat_var >/dev/null 2>&1 || true
      $COMPOSE up -d wazuh.manager wazuh.dashboard
      echo "[ctl] Done. New dashboard login: admin / ${NEW}"
    else
      echo "[ctl] Indexer not running; the new password takes effect on the next ./ctl up."
    fi
    ;;

  clean)
    echo "[ctl] Stopping and removing data volumes (full reset) ..."
    $COMPOSE down -v
    ;;

  help|*)
    cat <<'EOF'
Usage: ./ctl <command>

  up [--scenario N | --mode soc]  build, seed the workspace, start the stack
  down                            stop the stack (data volumes kept)
  status                          show running services
  ingest                          run the offline sensors over ingest/ now
  scenario NAME                   seed a scenario, reload, then ingest
  reload                          reload the Wazuh manager after rule edits
  dashboard                       print the dashboard URL
  set-password [PASS]             rotate the indexer admin password (.env stays source of truth)
  clean                           stop and remove data volumes (full reset)

Scenarios: routing-hijack  ot-modbus
Credentials: .env is the one source of truth; the indexer hash is derived from it.
EOF
    ;;

esac
