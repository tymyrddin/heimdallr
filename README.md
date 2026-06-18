# Heimdallr

The watchman. A live detection range where a defender practises spotting the
attack labs' handiwork in a real stack, against real telemetry, by hand.

heimdallr is the blue counterpart to the attack-only labs (inter-domain-simlab
for routing, ics-access-simlab for OT) and pairs with the huginn-and-muninn
observation toolkit, the eyes. It runs OpenSearch with a dashboard, takes
telemetry in as files through `ingest/`, derives the anomalies in the detection
layer, and surfaces them so the practitioner can hunt and tune. It does not run
the attacks and it does not sniff a live wire.

The full design record lives in [PLAN.md](PLAN.md).

## Quick start

The range wants Docker with the compose plugin and a fair amount of RAM (the
OpenSearch node is not shy). Security (auth/TLS) is disabled: this is a local
range, not an exposed service, so keep the ports on the host.

```sh
./ctl up        # start OpenSearch + Dashboards, apply the index template + ingest pipeline
./ctl ingest    # relay ingest/ into OpenSearch (the routing feeder + the enrichment)
./ctl detect    # compile the Sigma rules and run detections + the arm->hijack correlation
./ctl dashboard # the URL to hunt and watch findings
```

With the three routing-hijack bundles staged under `ingest/`, `up`, `ingest`,
`detect` shows all three attacks firing end to end before you write a thing.

## How detection works

The contract is observations in, verdicts derived. The feeder relays raw telemetry
(BGP announce/withdraw, ROA changes, the validated-ROA set) as observations, with
no verdicts. OpenSearch's ingest pipeline normalises them and derives the anomalies
against heimdallr's own baseline (`rules/baseline/aggregates.json`) and the observed
RPKI state: the covering aggregate, whether an announcement is more-specific, whether
its origin is authorised, and RFC 6811 validity. The Sigma rules in `rules/sigma/`
then match those derived fields, and a correlation ties a ROA removal to the prefix
surfacing not-found (the ROA-poisoning arm to hijack), across the full event stream.

For the routing substrate the heavy lifting is in the enrichment, not Sigma; the
Sigma-authoring canvas comes into its own on the OT/pcap substrate (a later
milestone). See `docs/authoring/`.

## Layout

```
compose/      docker-compose stack: opensearch, dashboards, the feeder + detector
sensors/      zeek and suricata, parked for a future OT/pcap substrate
feeders/      the routing sensor: raw telemetry -> JSON observations -> OpenSearch
rules/        baseline/ (authored baseline), pipeline/ (enrichment), sigma/ (rules), correlation/
ingest/       bundle dirs: raw telemetry, an optional brief alongside (committed, ships with the lab)
ctl           up / down / ingest / detect / status / clean
docs/         rule-authoring guides
```

## Where the doctrine lives

The correlation reasoning is in the blue docs at `counter/network/correlation.md`.
heimdallr is where it gets practised. The rule-authoring guides under
`docs/authoring/` point back at it rather than repeating it.

## Status

M2 done: the routing profile runs end to end on OpenSearch + Sigma, all three
hijack bundles firing (false-origin, incomplete-rpki, roa-poisoning). The core
moved from Wazuh during M2, because the routing detections need IP-in-CIDR and RFC
6811 logic that Wazuh's rule engine could not express; see PLAN.md sections 3 and 7
for the pivot. M3 next: Sigma translation and portability (`sigma convert` to other
back ends). OT is de-scheduled (sensors kept parked). See PLAN.md section 12 for
exactly where the work is.

## Licence

Dual-licensed, matching the sibling labs: Polyform Noncommercial for non-commercial
use, with a commercial option and a security-research exception. See LICENCE,
COMMERCIAL-LICENCE.md and SECURITY-RESEARCH-EXCEPTION.md.
