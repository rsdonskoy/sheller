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
