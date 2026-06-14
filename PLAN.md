# heimdallr: build plan and design record

This file is the handoff document for heimdallr, the blue-side detection lab. It captures what
heimdallr is, the decisions taken, the architecture, and the questions still open. A future
session working in this repo can read it without the original conversation. Written 2026-06-14.

## 1. What this is and why it exists

heimdallr is a detection lab: a live, containerised range where a defender practises detection
and correlation against the artefacts the attack labs produce. It runs a real SIEM with a
dashboard and network sensors, takes captures and logs in through an ingest directory, and gives
the practitioner a rule workspace to write, reload and tune detections until the attack shows up
on the dashboard. It is the blue counterpart to the attack-only labs (inter-domain-simlab for
routing, ics-access-simlab for OT), and the watchman that pairs with the huginn-and-muninn
observation toolkit (the eyes).

It is not a CI rule-tester and not a synthetic event generator. The previous detection layer
(red-lantern-detection, exercised only against the fake red-lantern-sim generator) was never
validated against real telemetry, and the surrounding doctrine was coupled to a simulator whose
events carried fabricated fields. heimdallr works the other way round: real captures and logs go
in, a real stack processes them, and the practitioner builds the detection by hand.

heimdallr resolves inter-domain-simlab PLAN open question 12 (rebuild detection fresh, in its own
repo, against real lab output).

## 2. Place in the wider ecosystem

The attack labs split by substrate; heimdallr is the defender's range that reads what they emit.

- inter-domain-simlab (live containerlab, attack-only): BGP/inter-domain. Exports routing
  artefacts (MRT dumps, a JSON event timeline, and, as its governance zone and scorer land, BMP,
  RPKI-validator and router-syslog records). See its PLAN section 8.
- ics-access-simlab (live containerlab, attack-only): the OT estate. Exports pcaps and, after a
  small adaptation, structured host-event logs from the Modbus/OT servers.
- huginn-and-muninn (observation toolkit, the eyes): the real public internet (RIPE RIS,
  RouteViews, RIPEstat). Exports genuine routing captures for benign noise and false-positive
  tuning.
- heimdallr (THIS repo): takes those captures and logs in as files, runs them through sensors and
  a SIEM, and surfaces alerts on a dashboard for the practitioner to build and tune.

heimdallr never connects to the attack labs. Inputs arrive as files, exported and dropped into the
ingest directory. Decoupling is deliberate: each lab and heimdallr stay independently runnable, and
a saved capture doubles as repeatable practice material.

The doctrine lives in the blue docs, not here. blue `source/docs/counter/network/correlation.md`
holds the correlation reasoning (source authority, the three patterns, design heuristics, failure
modes). heimdallr is where that doctrine gets practised, with rewritten rule-authoring guides that
point back at it.

## 3. Decisions already made

- A live detection range, not a rule-test harness. heimdallr stands up a running stack with a
  dashboard and a rule workspace. Practice happens in it, by hand.
- Wazuh as the core SIEM. Manager, indexer and dashboard, open source, matching the ecosystem
  (ics-access docs, the Establishment's stated Wazuh use). It is the alerting surface and the rule
  workspace.
- Zeek and Suricata as sensors, run offline. They read committed pcaps in file mode (`zeek -r`,
  `suricata -r`), producing logs and eve.json alerts. Nothing sniffs a live wire by default, which
  is what lets heimdallr run on captures alone. An optional live-replay mode (tcpreplay onto a
  dummy veth) exists for practising live capture, off by default.
- Inputs are files. Captures and logs land in an ingest directory, exported from the attack labs
  and huginn-and-muninn. No live link to any lab.
- docker-compose plus a `ctl` wrapper. The stack is services, so compose is the natural fit; `ctl`
  gives up/down and scenario/mode selection, for parity with the other labs.
- Two run modes, chosen at bring-up. Focused (`ctl up --scenario <name>`) loads one profile, its
  inputs and a baseline ruleset to extend, for learning one move. SOC (`ctl up --mode soc`) ingests
  everything into one always-on stack for the busier view. Same stack underneath.
- Real inputs only. Every capture or log is from a real lab run or the real internet. No fabricated
  events. This is the line red-lantern-sim crossed.
- Doctrine in blue, practice in heimdallr. The correlation reasoning stays at
  counter/network/correlation.md; heimdallr holds the running stack, the baseline rulesets, the
  scenario profiles, and the rule-authoring how-to.

## 4. Architecture: the running range

One persistent stack. Inputs flow through it and out to the dashboard:

```
ingest/ (pcap, logs,        sensors                  SIEM                    dashboard
 MRT/BMP/RPKI)         ->   Zeek + Suricata (-r)  -> Wazuh manager       ->  Wazuh dashboard
                            routing feeder            (decoders, rules,        (alerts, hunt)
                            host logs (as-is)         correlation)
                                                          ^
                                                   rule workspace
                                                   (mounted, editable, reloadable)
```

Components:

- `ingest/`: the input directory. Captures and logs dropped here are what a scenario or the SOC
  mode reads. This is the boundary with the attack labs, a directory, not a wire.
- Sensors (Zeek, Suricata): containers that run over the pcaps in file mode and emit logs and
  eve.json. Zeek's Modbus analyser gives OT captures structure (function codes, register
  addresses); Suricata gives signature alerts. A routing feeder turns MRT / BMP / JSON-timeline /
  RPKI artefacts into JSON log lines, since BGP is not pcap-shaped. Host logs from ics-access pass
  through unchanged.
- Wazuh (manager, indexer, dashboard): ingests the sensor logs, the routing-feeder logs and the
  host logs; decodes, runs rules and correlations, and raises alerts. The dashboard is where the
  practitioner watches them land and hunts.
- Rule workspace: mounted directories for Wazuh decoders and rules (and Suricata signatures, Zeek
  scripts) so edits take effect on reload, without rebuilding the image. This is the practice
  surface.
- `ctl`: brings the stack up and down, loads a scenario or SOC mode, replays or re-ingests inputs,
  and reloads rules.

## 5. Ingest paths

Three paths into the one stack, by input shape:

- pcap to sensors to SIEM. A capture (OT Modbus traffic, or any network pcap) is read by Zeek and
  Suricata in file mode; their logs and alerts are ingested by Wazuh. This covers the OT estate and
  any packet-level material.
- logs straight to SIEM. Host-event logs (from the ics-access servers) are ingested as-is by Wazuh
  decoders and rules.
- routing artefacts to feeder to SIEM. MRT dumps, BMP streams, the JSON event timeline and
  RPKI-validator state are converted by a small feeder into JSON log lines that Wazuh decodes. This
  is where the routing single-signal detections and the correlation patterns get practised.

## 6. Scenario profiles and modes

A scenario profile bundles, per attack type: the input artefacts to ingest, a baseline ruleset to
extend (sometimes empty, sometimes partial), and a short brief on what to detect and where the
doctrine for it lives in blue. Examples: routing-hijack (the false-origin artefact), ot-modbus (a
Modbus pcap plus host logs).

Two ways to bring the stack up:

- Focused: `ctl up --scenario routing-hijack` mounts one profile's inputs and baseline, for
  learning one move without the noise of the others.
- SOC: `ctl up --mode soc` ingests every available input into one always-on stack, a busier and
  more realistic view, weaker as a teaching slice.

Both run the same containers; the mode decides what is loaded and which baseline ruleset is
mounted.

## 7. Milestones

- M1, the range boots. DONE (2026-06-14). docker-compose Wazuh (manager, indexer, dashboard, with
  the official single-node certificates and security config), Zeek and Suricata as offline sensor
  containers, a Wazuh-agent collector, the ingest directory, the rule workspace, and
  `ctl up/down/ingest`. A trivial benign pcap flows end to end, pcap to sensors to collector to
  manager to indexer, and shows up on the dashboard. Wazuh's own self-monitoring (FIM, SCA,
  rootcheck, vulnerability detection) is off, so the board shows lab detections rather than the
  stack keeping a diary about itself. This is "the lab runs and shows data".
- M2, routing profile. The routing feeder (MRT / BMP / JSON-timeline to Wazuh logs), a baseline
  routing ruleset (the single-signal detections that mirror the blue hunts: MOAS, more-specific,
  RPKI-invalid, short-lived window), and the first scenario from inter-domain-simlab's false-origin
  hijack. Practise until the dashboard flags the MOAS and the more-specific. The correlation
  patterns (arming, RPKI-cover, multi-stage) wait on BMP/RPKI inputs from that lab's governance zone
  and scorer.
- M3, OT profile. The ics-access export adaptation (a pcap-capture wrapper in its `ctl`, plus
  structured logging in the Modbus/OT servers), the Zeek Modbus path and Suricata, host-log rules,
  and the Modbus scenarios.
- M4, SOC mode and real-internet noise. The all-inputs mode, plus huginn-and-muninn captures as a
  benign corpus for measuring and tuning the false-positive rate the doctrine warns about.
- Optional, later: a regression layer. A committed scenario plus its expected alerts, replayed
  headless, to catch rule rot over time. Useful, but secondary to the hands-on range, and explicitly
  not the core.

## 8. Source material and the harvest

From the retired blue establishment/red-lantern section, rewritten fresh here against the Wazuh
stack and the real inputs, never lifted verbatim (the originals were fake-sim-coupled):

- `detection/generic.md` to platform-agnostic detection patterns (the canonical baseline logic).
- `detection/decoders.md`, `rules.md` to the Wazuh decoder and rule-authoring guide for this stack.
- `detection/other-siems.md` to cross-platform notes, if and when a second SIEM is added.
- `response/playbooks.md` to response playbooks, cross-checked against blue
  counter/impact/response.md.
- `threat-intel/modelling.md` to threat-modelling notes (light).

Dropped, too fake-sim-coupled to rewrite: `threat-intel/iocs.md`, `advanced/feeds.md`,
`advanced/scenarios.md` (the financial-institution example), `advanced/integration.md`.

Kept as doctrine in blue, referenced not duplicated: the correlation reasoning now at
counter/network/correlation.md.

To read before building: inter-domain-simlab PLAN.md (sections 8, 13, 14, 15) for the routing
artefact shape; ics-access-simlab (its `ctl`, `zones/*/components/`, `challenges/*-pcap.md`) for the
OT export; huginn-and-muninn (NOTES.md, the glass/recall outputs) for the real-internet captures.

## 9. Realism charter

- Real inputs. Every capture or log is from a real lab run or the real internet. Nothing is
  hand-authored to make a rule fire.
- A real stack. Detection is built in a genuine SIEM with real sensors, not asserted by a script.
  What the practitioner sees is what the tools actually produced.
- Honest sensing. Sensors read what the capture held; the optional live-replay mode replays the
  capture's own timing, it does not invent traffic.
- Bounded scope, the normal shape of a range. heimdallr replays captures and logs; generating them
  is the attack labs' job. A move is practiceable here once a real capture or log for it exists. The
  human-correlation and intent-analysis doctrine that does not reduce to a rule stays doctrine in
  blue.

## 10. Repo tree (target)

```
compose/
  docker-compose.yml       wazuh manager + indexer + dashboard, zeek, suricata, collector
sensors/
  zeek/                    scripts and config (incl. Modbus)
  suricata/                signatures and config
feeders/
  routing.py               MRT / BMP / JSON-timeline / RPKI -> Wazuh JSON log lines
rules/
  baseline/                starter decoders/rules per scenario (the workspace seed)
  workspace/               mounted, editable, reloadable
scenarios/
  routing-hijack/          inputs manifest + baseline ref + brief
  ot-modbus/
ingest/                    drop captures and logs here (gitignored; samples committed small)
ctl                        up / down / scenario / mode / reload
docs/
  authoring/               rule-authoring guides (rewritten from red-lantern)
PLAN.md
README.md
```

## 11. Design questions, resolved

1. RESOLVED. Routing into Wazuh goes through the feeder (MRT/BMP/RPKI to JSON log lines Wazuh
   decodes), keeping one practice surface. No separate BGP monitor; revisit only if routing
   detection outgrows rules.
2. RESOLVED. Wazuh dashboard only. No Grafana.
3. RESOLVED. Log shipping is a Wazuh agent in a collector container, tailing the sensor and feeder
   logs. Not filebeat-direct.
4. RESOLVED. Live-replay (tcpreplay onto a veth) is deferred. File mode only for now; sensors read
   committed pcaps with `-r`.
5. RESOLVED. huginn-and-muninn is depended on as committed snapshots only. No live pull.
6. RESOLVED. heimdallr carries its own CLAUDE.md with the British-English / no-em-dash / no-bold /
   no-"should" prose rules (as inter-domain-simlab does), scoped to Markdown and prose; code and
   config follow code conventions.
7. RESOLVED. Norse naming kept. heimdallr (the watchman) and huginn-and-muninn (the ravens) are
   Norse; the Discworld docs fiction stays separate.
8. RESOLVED. Same licence as the sibling labs: the dual-licence trio (Polyform Noncommercial 1.0.0
   LICENSE + COMMERCIAL-LICENSE.md + SECURITY-RESEARCH-EXCEPTION.md), plus DISCLAIMER and
   CODE-OF-CONDUCT.md, copied from inter-domain-simlab.

## 12. Current status

M1 is done (2026-06-14): the range boots and shows data. The docker-compose Wazuh stack (manager,
indexer, dashboard, on the official single-node certificates and security config), Zeek and
Suricata as offline sensors, the Wazuh-agent collector, the ingest directory and rule workspace,
and `ctl up/down/ingest` all stand up from a clean `ctl up`, and a benign smoke pcap flows end to
end to a dashboard alert. Credentials are single-sourced in `.env`, with the indexer admin hash
derived from it at bring-up (`ctl set-password` rotates), so the plaintext and the hash cannot
drift. Wazuh's self-monitoring is disabled, so a fresh board shows two lab alerts rather than ~190
housekeeping ones. The licence trio, DISCLAIMER, CODE-OF-CONDUCT and CLAUDE.md are in place
(resolutions 6 and 8).

Next is M2: the routing feeder (MRT / BMP / JSON-timeline to Wazuh logs) and the routing-hijack
scenario from inter-domain-simlab's false-origin artefact, once that lab exports its MRT seed and a
scorer timeline. The baseline routing ruleset and the ot-modbus scenario are already stubbed under
`rules/baseline/` and `scenarios/`, ready to flesh out.
