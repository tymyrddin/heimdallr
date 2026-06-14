# Style rules, non-negotiable

These apply to Markdown and prose (`.md` files, READMEs, briefings, docs).
Check before saving, not after.

- British English throughout
- No em dashes. Not `—`, not ` -- `. Use a comma, colon, or separate sentence instead
- No bold (`**text**`)
- No horizontal rules (`---` dividers in Markdown)
- No `should` or `must` directed at the reader. Use: can, could, might, may, is worth, works best when, needs to
- Do not over-explain
- A dash of sharp but acceptable humour

## What these rules do not touch

Code and config are out of scope: FRR `.conf` files, shell scripts, Dockerfiles,
clab `.yml` topologies and the like follow their own conventions (code comments,
box-drawing in tables, technical accuracy over prose style). The list above is
about written English, not about how a route-map reads.

## Scope rules

- Only make changes that were explicitly requested
- Do not add links, pages, or cross-references that were not validated first

## Self-check before saving Markdown

After writing any new prose, grep for:
- `—` or ` -- ` (em dashes)
- `\bshould\b` and `\bmust\b` (reader-directed use)
- `\*\*` (bold)