# API Set map text sources

One JSON file per (module, architecture) - the reviewed offline source the
`apiset-map.bin` binary is generated from (`tools/gen_apiset_map.py`).
The binary travels inside the
user's system-module directory next to its raw ntdll; the engine reads only
the binary, through a bounded reader that rejects a map whose architecture
or anchor differs from the world.

## Schema (version 1)

```json
{
  "schema": 1,
  "arch": "x64",
  "anchor": {"xxhash64": "0x...", "note": "the raw ntdll these entries were reviewed against"},
  "entries": [
    {"contract": "api-ms-win-core-console-l1-1-0", "host": "kernelbase.dll"},
    {"contract": "api-ms-win-core-console-l1-1-0", "importer": "fakeuser32.dll", "host": "other.dll"}
  ]
}
```

Field rules:

- `contract`: folded, extension-less api set name (the map never stores
  `.dll`); `importer`: optional folded name - an importer-specific entry
  beats the unconditional entry for the same contract; `host`: folded name
  with extension, resolved inside the same directory under the strict
  source rules.
- One (contract, importer) pair maps to one host: conflicting rows are a
  generation error, and the runtime reader rejects duplicates outright.
- The anchor is the whole-file xxhash64 of the directory's raw ntdll - the
  unique applicability anchor. A directory whose ntdll hash differs from
  the map's anchor is a named construction rejection, never a guess across
  module hashes.
- Directory mode disables the two synthetic-mode prefix fallbacks
  (`api-ms-win-crt-* -> ucrtbase`, `api-ms-win-* -> kernelbase`); an
  api-set name the map does not cover is a named unmapped rejection.

## Sources in this directory

| file | build | anchor (whole-file xxhash64 of its ntdll) |
|---|---|---|
| `ntdll.x64.json` | fixture corpus | see the file |
| `ntdll.x64.win1809.json` | Windows 10 1809/LTSC 2019 (build 17763) x64 | `0xabfab64c572b14f7` |
| `ntdll.x64.win26300.json` | Windows 11 26300 x64 | `0x10d75b5a36dbefaf` |

Each `<stem>.json` ships with two companions that make the review chain
reproducible:

- `<stem>.evidence.json` - the tool's evidence report: scanned inputs with
  their hashes, per (contract, importer) observed functions, per-host
  coverage (body / forward slot / jmp-thunk / absent), forward reachability,
  candidates, and the resolution status with its recorded basis.
- `<stem>.resolve.json` - the explicit review adjudications (contract ->
  host + basis) for every contract the same-source schema does not cover.

`apiset-schema.win1809.json` / `apiset-schema.win26300.json` are the
same-source API Set schemas (parsed from each build's `apisetschema.dll`
`.apiset` section), the host authority the derivation prefers.

## Regenerating a source

1. Collect the build's system directory: `ntdll.dll`, `kernel32.dll`,
   `kernelbase.dll`, `ucrtbase.dll` (the scanned hosts and importers), the
   build's `apisetschema.dll`, and every corpus image whose api-set closure
   the map must serve (`--extra-pe`; the crt family only shows up through
   sample/CRT imports, never through the system DLLs' own).
2. Parse the same-source schema:
   `python tools/apisetmap/dump_apiset_schema.py <System32 ntdll.dll>
   <apisetschema.dll> tools/apisetmap/apiset-schema.<build>.json`
3. Derive with evidence:
   `python tools/gen_apiset_evidence_map.py <system-dir> <ntdll-anchor>
   --evidence <stem>.evidence.json --map <stem>.json --schema <schema.json>
   --resolve <stem>.resolve.json --extra-pe ...`
   The tool writes the reviewed map only once every contract is confirmed -
   by the schema's host field (importer-specific branches preserved), or by
   a recorded review whose basis states the evidence. A unique EAT candidate
   alone does not confirm a host; ambiguity and zero-coverage fail named in
   the report.
   Both confirmation routes require reachable observed exports, including
   complete named forwarder chains without cycles. Schema-backed sources
   retain the schema's default and all importer-specific branches, including
   unobserved importers; observing only an exception never makes it the default.
4. Compile the binary the directory carries:
   `python tools/gen_apiset_map.py <stem>.json apiset-map.bin` (anchor and
   conflict validated there; the bin itself is user-directory content,
   never committed).
