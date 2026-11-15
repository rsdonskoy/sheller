# Boundary description manifest sources

One JSON file per (module, architecture) - the versioned classification
authority the directory-mode boundary derivation consumes.
`tools/gen_boundary_seed.py` compiles these
files into the committed `src/engine/boundary_seed.inc`; builds never read
the JSON. Editing a JSON without regenerating the seed fails
`boundary_seed` (the test regenerates and byte-compares).

## Schema (version 1)

```json
{
  "schema": 1,
  "module": "ntdll.dll",          // folded name, with extension
  "arch": "x64",                  // the format carries x64 only ("x86" reserved)
  "images": [                     // applicability: whole-file xxhash64
    {"xxhash64": "0x21efce8c9258a643",
     "note": "where these bytes come from (build, image, tool)"}
  ],
  "exports": [                    // every export of every listed image
    {"name": "NtCreateFile", "ordinal": 0, "kind": "syscallstub"},
    {"ordinal": 5, "kind": "syscallstub"},              // unnamed export
    {"name": "Fn", "kind": "intercept"},
    {"name": "Fn", "kind": "trap"},
    {"name": "Fn", "kind": "compat", "ret": "0xC0000001",
     "out": ""},                                        // reserved recipes
    {"name": "Data", "kind": "data",
     "layout": {"size": 8, "align": 8, "bytes": "1020304050607080"}},
    {"name": "Fn", "kind": "syscallstub",
     "abi": {"x86_cleanup": 0}}                         // reserved (x86)
  ]
}
```

Field rules:

- `kind`: `syscallstub | intercept | trap | compat | data`. The derive
  validates a `syscallstub` against the source body's `4C 8B D1 B8` prefix
  (the shape is the verdict; names never decide). Aliases (names sharing
  one EAT index) must carry the same kind - they share one derived body.
- `ret` (compat): the failure return value, decimal or `0x` hex. Required
  for `compat`, forbidden otherwise.
- `out` (compat): `;`-separated OUT-parameter recipes. Reserved for now
  (empty string = none); the runtime handler contract lands with the
  compat-stub execution work.
- `layout` (data): `size` bytes, `align` a power of two, `bytes` exactly
  `2*size` hex characters. Required for `data`, forbidden otherwise.
- Forwarded exports carry no entry: classification follows the chain to
  its target at bind time.
- `abi.x86_cleanup`: schema-reserved stdcall cleanup byte count; unused
  while the x86 directory mode does not exist.

Applicability: a directory file is derived only when its whole-file
xxhash64 (seed 0) appears in `images` for its folded module name and
architecture; anything else is a named construction rejection - the
manifest never guesses across a version drift.

## Sources in this directory

| file | build | anchor (whole-file xxhash64) |
|---|---|---|
| `ntdll.x64.json` | fixture corpus (`tests/boundary_fixture.h` image) | `0x6c806f42b18c5f46` |
| `ntdll.x64.real.json` | local Windows build x64 System32 ntdll (2026-11-11 patch level) | `0x10d75b5a36dbefaf` |
| `ntdll.x64.win1809.json` | Windows 10 1809/LTSC 2019 (build 17763) x64 System32 ntdll | `0xabfab64c572b14f7` |

File names describe the build, never the collection machine; the seed
compiler disambiguates multiple manifests per (module, arch) by the file
name's remainder after `<module>.<arch>`. Regenerate the seed after any
manifest change:
`python tools/gen_boundary_seed.py tools/boundary_manifest src/engine/boundary_seed.inc`
