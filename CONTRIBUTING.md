# Contributing to Sheller

Sheller is a Unicorn-based Windows user-mode emulation engine focused on PE
unpacking, shellcode extraction, and pre-payload behavior fingerprinting (GPLv2).
This file is the contributor quick reference.

## Build (one command)

Prerequisites: CMake >= 3.24, Ninja, MSVC 2022 / GCC 13+ / Clang 16+, and
`VCPKG_ROOT` pointing to a vcpkg checkout.

```bash
cmake --preset windows-release      # or linux-release
cmake --build --preset windows-release
ctest  --preset windows-release
```

Presets: `linux-debug/release`, `windows-debug/release`, `linux-sanitizer` (ASan+UBSan).

## Repository layout

```
include/sheller/   public headers (no third-party includes)
src/engine/        engine: unicorn rebuild, hooks, SEH / C++ EH dispatch,
                   syscall dispatch, cooperative threads, virtual time and
                   burn-loop fast-forward, loop-native gate, region map,
                   write ledger, dump writer, log facade state
src/loader/        deterministic PE loader route: layout, relocs, TLS,
                   imports (host modules or synthetic ones)
src/runtime/       runtime-environment layer: capture/ (Windows only); craft/
                   serializes the loader-constructed guest into a v1 container
                   (the environment bytes are loader::build_environment /
                   fill_kuser_shared_data output, not a second construction)
src/syscalls/      guest syscall policy table
src/behavior/      event ledger, report event accounting, behavior rules
src/unpack/        IAT repair
src/api/           analysis facade: analyze / unpack_sample, wiring and
                   structured artifacts (static sheller_api; links engine +
                   unpack + capture, kept outside sheller_engine to stay
                   acyclic)
src/cli/           sheller command line (capture, run, unpack) + the
                   sheller_cli_render static library: deterministic JSON
                   formatting over the facade's public artifacts (links no
                   library - every name it uses is inline in a public header)
src/shared/        the shared interface library (sheller.dll / libsheller.so):
                   api.cpp defines the six exported entries and forwards each
                   to the static core's internal name
tests/             test suites, synthetic samples, golden baselines
tools/             generators and setup helpers the tree calls on by hand, the
                   local Linux verification gates and their fault injection
                   (see tests/README.md for what each one gates)
cmake/             shellerConfig.cmake.in - the package template that turns
                   find_package(sheller CONFIG) into the sheller::sheller target
docs/              cli.md (the command line) and embedding.md (linking the library)
```

## Dependency policy

- unicorn: vcpkg manifest, whole catalog pinned via `builtin-baseline` (`vcpkg.json`)
- GoogleTest: FetchContent, `tests/` only
- xxhash: vcpkg manifest, `tests/` only (event-stream baseline digests, non-crypto use)
- spdlog: header-only mode (`SPDLOG_USE_STD_FORMAT` + `SPDLOG_NO_EXCEPTIONS`), linked by `cli/` only
- engine modules (`engine/`, `syscalls/`, `behavior/`, `unpack/`, `runtime/`) depend on
  the standard library plus unicorn/peconv only

## Code style (enforced in CI)

- C++23; types PascalCase, functions/variables snake_case, private members end with `_`,
  getters are the member name without `_`, no setters (state is set at construction)
- constants/enum values prefixed `k`; macros are discouraged (SHELLER_ prefix if unavoidable)
- brace-init everything; const wherever possible; by-value parameters take const in the
  definition, not the declaration (view types take none)
- braces: function bodies on a new line (Allman), control flow on the same line (K&R),
  brace single-statement bodies
- the engine core is exception-free: errors propagate as return values
  (`bool` / `std::optional` / `std::expected`); MSVC keeps EH on, first-party code
  never throws or catches
- hook hot paths ban heap allocation, locks, I/O, and logging - guest facts go to the
  event ledger, host diagnostics to `sheller/log.h` (silent by default; never mix the two)
- **a guest address is not a host pointer**: guest memory is only accessed through the
  engine API / GuestProbe
- public headers (`include/sheller/`) must not include third-party headers; Win32 is
  only allowed in `runtime/capture/` and `cli/`
- identifiers, comments, report fields, and commits are in English; comments explain
  constraints and reasons, not what the code does

## Commits and pull requests

- Conventional Commits: English imperative + module scope (`engine:`, `cli:`, ...)
- one PR = one coherent slice; the description must address that slice's acceptance items
- PRs touching the event stream or the dump path must include a baseline comparison
- real malware samples never enter the repository: corpora are synthetic only, private
  collections are mounted from a local directory
