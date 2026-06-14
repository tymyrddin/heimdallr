# Scenario brief: routing-hijack

## The move

A false-origin hijack: an attacker AS announces a victim's prefix (or a
more-specific of it) that it has no authority for. The classic loud signals are
a second origin for a prefix already seen (MOAS), a more-specific that pulls
traffic, and an RPKI-invalid announcement.

## What to detect

Start from the baseline ruleset (MOAS, more-specific, RPKI-invalid), watch the
dashboard flag the announcement, then tune so the genuine event fires and the
backbone noise stays quiet. The correlation patterns (trust-signal arming,
RPKI-cover hijack, multi-stage) wait on BMP and RPKI inputs from
inter-domain-simlab's governance zone.

## Where the doctrine lives

Source authority, the three correlation patterns and the failure modes are in
blue at counter/network/correlation.md. This brief points at it rather than
repeating it.

## Inputs

Pending inter-domain-simlab exporting its MRT seed and a scorer timeline. Until
then this scenario has rules but nothing to ingest.
