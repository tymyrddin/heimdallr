# Heimdallr

The watchman. A live detection range where a defender practises spotting the
attack labs' handiwork in a real stack, against real telemetry, by hand.

heimdallr is the blue counterpart to the attack-only labs (`inter-domain-simlab`
for routing, `ics-access-simlab` for OT) and pairs with the `huginn-and-muninn`
observation toolkit, the eyes. It runs OpenSearch with a dashboard, takes
telemetry in as files through `ingest/`, derives the anomalies itself in the
detection layer, and surfaces them so the practitioner can hunt and tune. It does
not run the attacks, and it does not sniff a live wire: the boundary with the
attack labs is a directory, not a wire.

Where the attack labs make a thing happen, heimdallr is where you learn to see it:
observations go in, the practitioner builds the detection, and nothing is
hand-authored to make a rule fire.

## Dependencies

Linux with Docker. The OpenSearch node wants memory, so give it room.

| Dependency | Notes                                                          |
|------------|----------------------------------------------------------------|
| Linux      | kernel 5.x+ (`vm.max_map_count=262144` for OpenSearch)         |
| Docker     | Engine 24+ with the compose plugin                             |
| RAM        | ~4 GB free; the single OpenSearch node is not shy              |

Security (auth/TLS) is disabled: this is a local range, not an exposed service, so
keep the ports on the host.

## Quickstart

```bash
./ctl up        # start OpenSearch + Dashboards + the UI, apply the index template + pipeline
./ctl ingest    # relay ingest/ into OpenSearch (the routing feeder + the enrichment)
./ctl detect    # compile the Sigma rules and run detections + the arm->hijack correlation
./ctl ui        # the UI URL; ./ctl dashboard for OpenSearch Dashboards
```

You come up at the UI on `http://localhost:5000`: the Data page lists the bundles
staged under `ingest/`, where you pick which to load (or load all, for the
SOC-chaos case) and browse a bundle's raw events before loading a thing. The
detections run from `ctl detect` today, with the per-bundle run-and-findings view
landing in the UI next. Dashboards on `http://localhost:5601` is the deep
hunt-and-tune surface.

With the bundles already committed under `ingest/`, `up` then `ingest` then
`detect` shows the routing hijacks firing end to end before you write a thing.

## Bundles

A bundle is a directory under `ingest/`: the raw telemetry an attack lab exported
(for routing, `events.jsonl` + `roa-history.txt` + `vrps.json`), self-describing by
its name. The detection content is not per-bundle: heimdallr's baseline, the ingest
pipeline and the Sigma rules apply across whatever is staged, so a rule either
detects its pattern wherever it occurs or it does not.

| Bundle                        | What it exercises                                     | Detected today |
|-------------------------------|-------------------------------------------------------|----------------|
| `false-origin-prefix-hijack`  | a more-specific from an unauthorised origin           | yes            |
| `incomplete-rpki-hijack`      | a monitored prefix with no covering ROA (MOAS)        | yes            |
| `roa-poisoning-hijack`        | a ROA removal, then the prefix surfaces (arm->hijack) | yes            |
| `route-leak-hijack`           | a valley-free violation in the AS_PATH                | awaiting rules |
| `route-legitimacy-subversion` | a forged IRR route-object behind a more-specific      | partial        |
| `policy-trust-abuse-hijack`   | a peer-trust / route-policy abuse                     | partial        |
| `legitimate-peering-hijack`   | injection over a real peering session                 | awaiting rules |

The first three fire end to end against the baseline rules. The newer four are
staged real telemetry awaiting their detection content; building it is the practice.

## Status

M2 (the routing profile) is built and validated end to end on the real stack. The
feeder relays the raw routing telemetry as observations only, an OpenSearch ingest
pipeline normalises and enriches each (RFC 6811 origin validation and the covering
aggregate, the one derivation no signature rule can do), and Sigma rules plus the
arm->hijack correlation derive the anomalies against heimdallr's own baseline. The
three routing-hijack bundles fire and generalise, and the benign flood fires
nothing.

The UI is coming up: the Data page (browse and load bundles) and the run spine (a
run, its rules pinned by content hash, and its findings) are built and validated;
the Detections, Findings and Experiments pages are landing on top.

## Roadmap

- Detection content for the newer bundles: AS_PATH analysis for route leaks, an IRR
  feed with an IRR-versus-RPKI rule for the legitimacy subversion, and the peer-trust
  and route-policy signals.
- Portability: export a detection written here to other backends (Splunk, Elastic,
  and so on), the payoff of authoring in vendor-neutral Sigma.
- SOC mode and real-internet noise: always-on monitors, and `huginn-and-muninn`
  captures as a benign corpus for tuning the false-positive rate.
- The OT profile (Zeek and Suricata over pcaps), parked until `ics-access-simlab`
  exports artefacts.

## Layout

```
compose/      docker-compose stack: opensearch, dashboards, the UI, the feeder + detector
sensors/      zeek and suricata, parked for a future OT/pcap substrate
feeders/      the routing sensor: raw telemetry -> JSON observations -> OpenSearch
rules/        baseline/ (authored baseline), pipeline/ (enrichment), sigma/ (rules), correlation/
ingest/       bundle dirs: raw telemetry, committed so a fresh clone runs out of the box
ctl           up / ingest / detect / down / status / clean / dashboard / ui
docs/         rule-authoring guides
```

## Docs

- [docs/authoring](docs/authoring) for writing detections on this stack: the
  ingest-pipeline field mapping and the Sigma rules that match it.
- [PLAN.md](PLAN.md) for the design record: what heimdallr is, the decisions taken,
  and the milestones.
