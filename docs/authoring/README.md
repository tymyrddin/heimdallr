# Writing detections

You author detections in Sigma, the open YAML rule standard, and the lab compiles
and runs them. This page covers how, with the routing rules as worked examples.

## Where the logic lives (read this first)

Detection in heimdallr splits in two, and being honest about the split saves
confusion:

- The ingest pipeline (`rules/pipeline/build_pipeline.py`) does the work a signature
  rule cannot: longest-prefix matching against the baseline (covering aggregate,
  more-specific), and RFC 6811 origin validation against the VRPs (validity). For
  the routing substrate this is where the real detection logic is, and it is
  reviewable, version-controlled detection content.
- The Sigma rules (`rules/sigma/`) then match the fields the pipeline derived. For
  routing they are deliberately thin.

So authoring a routing detection is mostly: understand what the enrichment derived
(see [the data model](../data-model.md)), then write a short Sigma rule over those
fields. The richer Sigma-authoring style (matching many raw fields, encoding your
own logic in the rule) is where the future OT/pcap substrate goes, where the input
is already structured and no IP arithmetic is needed.

## A Sigma rule, anatomy

The shipped more-specific rule, `rules/sigma/routing-more-specific.yml`:

```yaml
title: BGP more-specific announcement within a monitored aggregate
status: experimental
description: >
  An announcement more specific than its covering monitored aggregate ...
logsource:
  product: routing
detection:
  selection:
    type: announce
    more_specific: true
  condition: selection
fields:
  - prefix
  - origin_as
  - covering_aggregate
  - rpki_validity
level: high
```

- `logsource.product: routing` scopes it to the routing data.
- `detection` is named selections plus a `condition`. Here: announcements the
  pipeline flagged `more_specific`.
- `fields` are what to show on a hit.
- `level` sets severity.

The other three shipped rules follow the same shape:

- `routing-unauthorised-origin.yml`: `covering_aggregate` present and
  `origin_authorised: false` (a MOAS / origin hijack of monitored space).
- `routing-rpki-invalid.yml`: `rpki_validity: invalid`.
- `routing-rpki-notfound.yml`: `rpki_validity: notfound` and `covering_aggregate`
  present (scoped to monitored space, since not-found is common on the open
  internet).

## Compile and run

`ctl detect` compiles every rule in `rules/sigma/` with pySigma and runs it:

```sh
./ctl detect
```

```
[BGP more-specific announcement within a monitored aggregate]  (8 hits)
    query: type:announce AND more_specific:true
    roa-poisoning-hijack: 6  [203.0.113.0/25x6]
    false-origin-prefix-hijack: 2  [203.0.113.0/25x2]
```

The printed `query:` line is the compiled OpenSearch query, so you can see exactly
what your YAML became.

## Write your own

Say you want to flag any announcement whose AS_PATH ends in a particular suspect
origin, regardless of prefix. Create `rules/sigma/routing-suspect-origin.yml`:

```yaml
title: Announcement from a suspect origin AS
status: experimental
logsource:
  product: routing
detection:
  selection:
    type: announce
    origin_as: 65020
  condition: selection
fields:
  - prefix
  - origin_as
  - covering_aggregate
level: medium
```

Then `./ctl detect` and your rule appears in the output alongside the others. (This
particular rule is keyed to a literal origin, which is fine for a quick hunt but
does not generalise; the shipped rules deliberately key on derived properties, not
literals, so they catch the next hijack too.)

## The cidr modifier (the showcase, and its caveat)

Sigma can match an `ip`-typed field against a CIDR with the `cidr` modifier. This
is the capability that justified OpenSearch over the previous stack, and it is the
model you reuse on the OT/pcap substrate:

```yaml
detection:
  selection:
    type: announce
    network_address|cidr: '203.0.113.0/24'
    network_prefix_length|gt: 24
  condition: selection
```

This finds an announcement inside `203.0.113.0/24` that is longer than /24. It
works, but note the limitation: the `|gt: 24` hardcodes a /24 aggregate, and it
re-lists the prefix. That is exactly why the shipped routing rules instead key on
the size-generic `more_specific` field the pipeline derives, single-sourced from
the baseline. Keep the `cidr` form for ad-hoc hunts and for the OT substrate; for
the monitored routing space, prefer the derived field.

## Tuning

A detection is finished when it fires on the attack and stays quiet on the noise.
The flood (`roa-poisoning-hijack`, ~80k events) is your false-positive corpus: after
writing a rule, check its hit count is the attack and nothing else (the
[hunting](../hunting.md) guide shows the benign-stays-quiet check). If a rule is too
loud, tighten its selection or scope it to `covering_aggregate` (monitored space).

Next: [correlation](../correlation.md) for multi-step patterns, and
[portability](../portability.md) to take your rule to another SIEM.
