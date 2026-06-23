# ingest

Drop datasets here. The UI loads them into OpenSearch; Sigma rules run against them.

## Dataset layout

Each dataset is a directory, `ingest/<name>/`, containing one or more `.jsonl` files
(newline-delimited JSON, one event per line):

```
ingest/
  credential-dumping-lsass/
    sysmon.jsonl
  lateral-movement-wmiexec/
    sysmon.jsonl
    security.jsonl
```

The directory name becomes the dataset's identifier in the UI and in findings. Each
event should be a flat JSON object. If your data has a `bundle` field already, it
is overwritten on load with the directory name.

## Loading

Open the UI at `http://localhost:5000`, go to **Data**, and click **Load** next to
each dataset. To reload a dataset (after editing rules or data), load it again —
it replaces, never duplicates.

## Finding public data

| Dataset | What it covers | Where |
|---|---|---|
| **OTRF Security Datasets** (formerly MORDOR) | Windows/Linux attack simulations, labelled by ATT&CK technique, JSONL-ready | github.com/OTRF/Security-Datasets |
| **EVTX-ATTACK-SAMPLES** | Windows event log `.evtx` files per technique (needs evtx→JSONL conversion) | github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| **Atomic Red Team** | Test results from individual ATT&CK technique tests | github.com/redcanaryco/atomic-red-team |
| **Boss of the SOC (BOTS) v3** | Full SOC scenario dataset, Splunk export (needs conversion) | github.com/splunk/botsv3 |

OTRF Security Datasets is the easiest starting point — many datasets ship as
`.json` or `.jsonl` already, and each is tagged with the ATT&CK technique it
exercises, so you can pick a technique, load it, and write a rule to detect it.

## Converting EVTX to JSONL

```sh
pip install evtx
evtx_dump --format jsonl <file.evtx> > events.jsonl
```

Place the resulting `events.jsonl` in its own directory under `ingest/`.

## Field conventions

Sigma rules reference field names from the log source. Common ones for Windows
Sysmon data (EID 1, process creation):

- `EventID`, `Channel`, `Computer`
- `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`
- `User`, `IntegrityLevel`
- `Hashes`, `MD5`, `SHA256`

For network logs: `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol`.

If your data uses different field names, either normalise them to ECS/Sigma
conventions before loading, or write your rules to match the raw field names in
your dataset.