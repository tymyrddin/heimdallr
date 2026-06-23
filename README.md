# Heimdallr

A detection engineering tool built on OpenSearch and Sigma. Load any JSONL dataset,
write or import Sigma rules, run them, and see exactly what fired and what did not —
scoped per dataset so you can tell whether a rule is specific or noisy.

Four views drive the workflow: **Data** (what you have loaded), **Detections** (which
rules to run), **Findings** (what fired, per dataset), **Experiments** (how results
change as you iterate on a rule).

## Dependencies

Linux with Docker. The OpenSearch node wants memory.

| Dependency | Notes                                                  |
|------------|--------------------------------------------------------|
| Linux      | kernel 5.x+ (`vm.max_map_count=262144` for OpenSearch) |
| Docker     | Engine 24+ with the compose plugin                     |
| RAM        | ~4 GB free; the single OpenSearch node is not shy      |

Security (auth/TLS) is disabled: this is a local tool, not an exposed service.
Do not expose these ports off the host.

## Quickstart

```bash
./ctl up        # start OpenSearch + Dashboards + the UI
./ctl ui        # print the UI URL
./ctl detect    # compile Sigma rules and run detections (CLI shortcut)
./ctl dashboard # print the OpenSearch Dashboards URL
```

Open `http://localhost:5000`:

1. **Data** — drop a dataset directory under `ingest/`, then click **Load**.
2. **Detections** — pick rules from `rules/sigma/` or author a new one.
3. **Findings** — see what fired, per dataset, with a representative event.
4. **Experiments** — compare runs as you iterate on a rule.

OpenSearch Dashboards at `http://localhost:5601` is the deep hunt-and-tune surface.

## Datasets

A dataset is a directory under `ingest/<name>/` holding one or more `.jsonl` files
(newline-delimited JSON, one event per line). The directory name becomes the dataset
label in the UI and in findings.

See `ingest/README.md` for layout conventions and an EVTX conversion one-liner.

Good public sources:

| Dataset | What it covers | Where |
|---|---|---|
| **OTRF Security Datasets** | Windows/Linux attack simulations, labelled by ATT&CK technique, JSONL-ready | github.com/OTRF/Security-Datasets |
| **EVTX-ATTACK-SAMPLES** | Windows event log `.evtx` files per ATT&CK technique | github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| **Atomic Red Team** | Test results from individual ATT&CK technique executions | github.com/redcanaryco/atomic-red-team |
| **Boss of the SOC (BOTS) v3** | Full SOC scenario dataset | github.com/splunk/botsv3 |

OTRF Security Datasets is the easiest starting point — many datasets ship as `.jsonl`
already, each tagged with the ATT&CK technique it exercises.

## Rules

Sigma rules live under `rules/sigma/`. Any `.yml` file there is picked up automatically
by the detector and the UI's rule selector.

The [Sigma specification](https://github.com/SigmaHQ/sigma-specification) covers the
rule format. The [SigmaHQ community repo](https://github.com/SigmaHQ/sigma) has 3000+
rules across Windows, Linux, cloud, and network — a ready source to adapt or run
as-is against matching datasets.

## Layout

```
compose/      docker-compose stack: opensearch, dashboards, ui, detector
feeders/      load.py — generic JSONL bulk loader (used by the UI; also callable directly)
rules/        sigma/ (rules), correlation/ (aggregations), pipeline/ (field mappings)
ingest/       dataset dirs: one subdir per dataset, each holding .jsonl files
sensors/      zeek and suricata stubs (parked, future pcap profile)
ctl           up / detect / down / status / clean / dashboard / ui
docs/         authoring guides
```