# Heimdallr

The watchman. A live detection range where a defender practises spotting the
attack labs' handiwork in a real SIEM, against real captures, by hand.

heimdallr is the blue counterpart to the attack-only labs (inter-domain-simlab
for routing, ics-access-simlab for OT) and pairs with the huginn-and-muninn
observation toolkit, the eyes. It runs Wazuh with a dashboard, Zeek and Suricata
as offline sensors, and a rule workspace you edit and reload until the attack
shows up on screen. It does not run the attacks and it does not sniff a live
wire: inputs arrive as files in `ingest/`.

The full design record lives in [PLAN.md](PLAN.md).

## Quick start

The range wants Docker with the compose plugin, and a fair amount of RAM (the
Wazuh indexer is not shy).

```sh
./ctl up                      # build, generate .env, start manager/indexer/dashboard/collector
# drop a pcap into ingest/, then:
./ctl ingest                  # run Zeek and Suricata over it
./ctl dashboard               # the URL to watch alerts land
```

A committed smoke signature fires on any packet, so a trivial benign pcap proves
the path end to end before any real scenario is loaded. Turn it off once you
believe the range (`sensors/suricata/rules/local.rules`).

## Run modes

Two ways to bring the same stack up:

- Focused: `./ctl up --scenario routing-hijack` loads one profile's baseline
  ruleset, for learning one move without the noise of the others.
- SOC: `./ctl up --mode soc` seeds every baseline into one always-on stack, a
  busier and more realistic view that makes a weaker teaching slice, but can be 
  fun for the chaotic experience of a SIEM.

Edit detections in `rules/workspace/`, then `./ctl reload`.

## Layout

```
compose/     docker-compose stack: wazuh manager, indexer, dashboard, collector
sensors/     zeek and suricata, run offline over ingest/
feeders/     routing artefacts (MRT / BMP / RPKI / timeline) to Wazuh logs (M2)
rules/       baseline/ seeds per scenario, workspace/ the live editable surface
scenarios/   per-attack profiles: inputs manifest, baseline ref, a short brief
ingest/      drop captures and logs here (gitignored; small samples committed)
ctl          up / down / ingest / scenario / reload
docs/        rule-authoring guides
```

## Where the doctrine lives

The correlation reasoning can be found in the blue docs at
`counter/network/correlation.md`. Heimdallr is where it gets practised. The
rule-authoring guides under `docs/authoring/` point back at it rather than
repeating it.

## Status

M1 in progress: standing the range up so it boots and shows data. See PLAN.md
section 12 for exactly where the work is.

## Licence

Dual-licensed, matching the sibling labs: Polyform Noncommercial for
non-commercial use, with a commercial option and a security-research exception.
See LICENCE, COMMERCIAL-LICENCE.md and SECURITY-RESEARCH-EXCEPTION.md.
