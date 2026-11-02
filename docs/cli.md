# The sheller command line

`sheller` has three subcommands: `capture` produces a v1 snapshot from a running
sample, `run` replays a snapshot or passes a sample straight through, and
`unpack` is the one-shot pipeline that ends in a repaired image. Every run of the
same input produces a byte-identical event stream; the report shape and the
determinism mechanism are described at the end of this file.

The library-side contract - what an embedder links, how to consume an installed
prefix, and the decisions a host owns - is in [embedding.md](embedding.md).

## Synopsis

```bash
sheller capture <sample.exe> -o snapshot.snap [--shellcode] [--no-aslr] [--args <tail>]
            [--log-level <debug|info|warn|error>]
sheller run <sample> [--from-snapshot] [--reject <number>=<status>]... [--dump <dir>]
            [-b|--budget <n>M] [--stop <goal>] [--timeout-ms <ms>]
            [--report <file.json>] [--event-level <semantic|counts|full>]
            [--save-snapshot <path>] [--guest-stdout]
            [--system-modules <dir>] [--system-modules-fallback]
            [--log-level <debug|info|warn|error>]
sheller unpack <sample.exe> [-o <out.exe>] [--shellcode] [--keep]
            [-b|--budget <n>M] [--stop <goal>] [--timeout-ms <ms>]
            [--report <file.json>] [--event-level <semantic|counts|full>]
            [--save-snapshot <path>]
            [--system-modules <dir>] [--system-modules-fallback]
            [--log-level <debug|info|warn|error>]
```

## Routes

`run` states its route rather than inferring it: with `--from-snapshot` the
positional is a v1 snapshot and replays; without it the positional is an x64 PE
sample that passes straight through - captured in-process on Windows, constructed
into a v1 container on other hosts (sample bytes + the synthetic system module
directory, `synth_modules`, located next to the executable) and then replayed
through the same snapshot pipeline. No intermediate snapshot file is written
unless `--save-snapshot` asks for one. A snapshot file passed without the flag is
a capture-class refusal named on standard error, never a silently rerouted replay,
and the report the failure path still writes carries the four-key `events` object
with empty counts/detail, an empty stub table and the `null` loss pair.

On a non-Windows host the sample route needs the synthetic system module
directory: it exits 2 with one line on standard error when the directory cannot
be located. `--from-snapshot` does not require it for a captured container; a
constructed container that carries the synthetic module pages fails with its own
message when the directory is absent. A PE32 sample is refused on non-Windows
hosts before execution (capture-class failure naming the 32-bit limitation), and
the same condition is distinguishable from the missing-directory failure. An x64 DLL
is a valid sample on Windows (and for replaying an already-captured v2
container on any host): `capture` spawns a generated load-stub runner -
the sample never enters a real process; its bytes travel with the
snapshot as a pending module that the emulator loads synthetically at
the stub's `LoadLibraryW` call. The runner imports the base pair plus
every verified system dependency, so those initialize normally under
the real loader before the entry spin. Dependencies are admitted by
system-source verification (a same-named file outside the system
directory does not pass); private, path-shaped, or missing dependencies
are rejected by name before any process exists. The non-Windows
construction route for DLL input is not delivered yet - DLL samples
there fail with a named construction error until that slice lands.

`--system-modules <dir>` builds the resident system world strictly from the
named directory (real DLL bytes; the boundary pair `ntdll.dll`/`win32u.dll`
derives under the hash-bound manifest) - the host's system directories are
never read, and a closure member the directory lacks is a named rejection.
`--system-modules-fallback` opts into pulling such members from the synthetic
directory, marked in the module source table. The directory ships its own
`apiset-map.bin` (required; API Set resolution stops prefix guessing), and a
constructed container carries the versioned metadata record plus the e_res2
marker, so replay restores the run tables without the directory. Unsupported
boundary functions stop the run with a `boundary-trap` diagnosis in the
report. `capture` does not offer these options.

`--reject` maps a syscall number to a rejection NTSTATUS, both hexadecimal, and is
repeatable:

```bash
sheller run snap.snap --from-snapshot --reject 0x1000=0xC0000123
```

`--guest-stdout` forwards the guest's `NtWriteFile` bytes to standard output.
Without it they are discarded, at every log level: an empty write sink is disabled
rather than defaulted, and the library never writes a host standard stream.

`--budget` (`-b`) is an integer count of millions - `5M` is 5,000,000 and `0M`
keeps the unlimited value; bare integers are rejected. Exhausting it is the
normal end of a bounded run at this surface: the report and the statistics line
are written and `run` exits 0. The library result still carries the typed
`kBudgetExhausted` for embedders; capture, snapshot-IO, timeout and other run
failures keep their nonzero exit. Without `-b`, `run` bounds the run at 3M
instructions and a 10s wall clock; `unpack`'s defaults are its own (below).

## Stop targets (`--stop`)

`run` and `unpack` carry a stop-target option next to the limit flags (budget,
wall clock): a target is a place the run wants to reach and stops at
successfully, a limit is a bound it fails at - first to arrive wins. The goal
grammar:

* `xfer=<n>` - stop before the landing block of the Nth execution transfer
  (1-based; `0` = off; not an event-stream seq). The transfer event itself is
  still emitted, and the landing block is counted and produces `block-exec`,
  but its code does not execute. A hit is a successful stop: the report/dump
  are written and the exit code is 0. Transfers are checked at block
  granularity while the instruction budget and wall clock are checked at leg
  boundaries, so the first to arrive wins; a wall clock crossed inside the leg
  the transfer ends does not become a timeout.
* `esp` - stop at the confirmed entry-stack restore (below).
* `esp+xfer` - arm on the confirmed restore and stop at the next execution
  transfer, with the xfer stop face (the landing block never executes, the
  endpoint renders `module!section`).

A miss prints one line - `xfer target <n> not reached (xfers=<k>)` or
`esp target not reached` - and keeps the run's normal verdict and exit code,
including the no-attribution-map route, which never counts transfers. When a
limit closed the run before the goal, the miss line names it
(`; instruction budget arrived first` / `; wall clock arrived first`); a miss
on the run's own close-out (normal completion, guest termination) stays bare.
The transfer count is only accumulated while the xfer gate is active (an event
sink or a non-zero target), so `xfers=0` does not mean the run executed no
transfers. The count also skips transfers a burn-loop probe speculates
through, and those still show up as `kXfer` records in the report, so a
report's `kXfer` ordinal is not always the same number to pass to `--stop
xfer=`.

The failure faces are usage errors before any run starts: a typo'd goal or a
non-integer after `xfer=` exits non-zero naming the goal grammar; giving
`--stop` twice is a mutex error. `--xfer` is not part of this option: the
retired sugar spelling is an unknown argument. `capture` has no stop option.
Targets never change the budget or wall-clock defaults (`run` 3M/10s;
`unpack`'s 30s/600s wall clock) - pass an explicit budget when the goal lies
beyond their reach.

The `esp` targets face the shells that save registers on the stack at their
entry (the classic push-then-pop stub, UPX-class): the engine statically scans
the entry's contiguous push sequence for the save extent (capped at 64 bytes;
an entry that opens with anything else - `sub rsp` straight into a call - has
no such area and the monitor is not established), watches the save area below
the entry stack pointer, and confirms a restore when a decoded register pop
reads with the callback stack pointer at the slot address and puts it back at
the entry face. The confirmation emits the passive `stack-restore` event in
every instrumented run - the stop is only ever the goal's. `esp` stops inside
that confirming read (stop line `esp target reached (stack restore confirmed)`,
exit 0, dump); `esp+xfer` arms there. A miss - no save area, a relocated stack
(the VM shape), or an anti-debug probe reading its own save area with
something other than a pop - prints `esp target not reached` and closes the
run on its own terms.

For DLL inputs the monitor re-arms at the synthesized module's DllMain, and
UPX-class DLL stubs open that scene with argument-shadow stores and a reason
branch before their register saves - the scan finds no contiguous push
sequence at the entry, so `esp` / `esp+xfer` are a documented silent miss on
those shells (the run continues and closes normally). The usable stop face
there is `--stop xfer=1`: the stub's post-restore jump to the unpacked entry
is the first counted transfer, which is exactly the OEP dump stop.

## The report artifact

`--report` writes the deterministic JSON object `{"events":{...}}` - one event
stream, no second conclusion section. `events` always carries four keys:

* `counts` gives exact whole-run counts per type, key order by event-type id,
  zero-count types omitted. Judgment events are types like any other, so
  `smc-execute` or `oep-candidate` count alongside `block-exec` and `syscall`.
* `detail` is the one seq-ordered list of entries. The default level lists the
  default column: the eight semantic types (`xfer`, `syscall`, `apicall`,
  `exception`, `thread-create`, `cpuid`, `rdtsc`, `stack-restore`), the
  `mem-read`/`mem-write`
  instances where sample code accesses a system DLL, and the 12 low-frequency
  judgments (`peb-walk`,
  `export-walk`, `direct-syscall`, `indirect-syscall`, `getpc`, `rwx-alloc`,
  `anti-debug`, `oep-candidate`, `exception-disposition`,
  `exception-handler-install`, `loop-skip`, `kusd-access`). Other page accesses
  stay in `counts` (and join the full-level window). Every entry carries
  `type`, `seq` (the whole-run event ordinal) and its payload fields; the full
  level adds `tid`/`pc` to the head.
* `stub_calls` is the `module!name -> count` side table, `{}` when nothing called.
* `loss` is `{"dropped":null,"truncated":null}` when no ledger was built, and
  the ledger's counters (zero included) at full level.

`detail` renders one entry per line: the opening bracket ends the header line,
each entry occupies exactly one line, and the closing bracket opens the tail
line with `stub_calls` and `loss`. An empty list stays `[]`, so a report with
no events remains a single line.

At semantic level, entries sharing the primary key collapse into one entry. The
primary key is every rendered field apart from `seq` and the type's secondary
fields; `kusd-access` treats `aux` as secondary, keeping the first value and
adding `aux_last` when it varied. A merged entry keeps the first occurrence's
`seq`, adds `count` (the total) and `seqs` (the first 8 occurrence seqs). The
counts header stays exact. Full level does not merge: every underlying event
stays an entry.

There is no top-level `signals` key: the judgment events are ordinary entries
in the same stream, with the same numbering. The same replay produces a
byte-identical file.

```json
{"events":{"counts":{"block-exec":1204,"xfer":1,"syscall":5,"rdtsc":1},
           "detail":[{"type":"xfer","seq":2,"from":"packed.exe!UPX1",
                      "to":"packed.exe!UPX0"},
                     {"type":"syscall","seq":3,"num":"0x1000",
                      "api":"NtWriteFile","status":"0x0","caller":"0x140001000"}],
           "stub_calls":{},
           "loss":{"dropped":null,"truncated":null}}}
```

The report carries no sample-origin classification (`sample` /
`sample-transitive` / `system`). A host that needs it derives the classification
from the full stream's `caller` values against the name tables the library
artifacts carry (`TimelineNameTable::module_ranges` and `sample_image_range`); the
report itself carries no such tables.

## Event levels

`--event-level` decides whether the window side joins the one detail list; there
is no second event file to join afterwards.

`counts` emits no detail entries: the report is the counts header, the stub table
and the null loss pair (`detail` is `[]`). It builds no ledger and is the compact
form for runs whose detail would be dominated by high-frequency clock events.

`semantic` (the default) is the default column above. It builds no event ledger,
so a semantic-level run costs what it always cost, and `loss` renders the null
pair.

`full` builds the ledger window and inserts its entries - `block-exec`,
`sample-code`, `smc-execute` - into the same list by whole-run `seq`. The default
column's entries keep their `seq`, fields and relative order; only the window
entries and the loss shape differ. The window is bounded, so `loss.dropped` is
normally nonzero on a real sample (`sample-code` alone forwards millions of
instructions): a gap in `seq` is expected, not an error. `loss.truncated` counts
payloads the slot cap cut. Both fields render at full level, zero included; at
semantic level `loss` is `{"dropped":null,"truncated":null}` - null means "not
observable", which `0` would misstate.

Every entry at either level carries the whole-run `seq`: there is one numbering
space. Full-level entries also spell `tid` and `pc` in the head.

```json
{"events":{"counts":{"block-exec":1204,"xfer":1,"syscall":5,"rdtsc":1},
           "detail":[{"type":"block-exec","seq":1,"tid":4096,
                      "pc":"0x140001000","addr":"0x140001000"},
                     {"type":"xfer","seq":2,"tid":4096,"pc":"0x140001010",
                      "from":"packed.exe!UPX1","to":"packed.exe!UPX0"},
                     {"type":"syscall","seq":3,"tid":4096,"pc":"0x140001040",
                      "num":"0x1000","api":"NtWriteFile","status":"0x0",
                      "caller":"0x140001000"}],
           "stub_calls":{},
           "loss":{"dropped":57000,"truncated":0}}}
```

`unpack` gives `--event-level` the same meaning. Its report path is
`<output>.report.json` by default, and `--report <path>` overrides it; nothing
else lands beside the image.

## Attribution conventions

xfer endpoints - the semantic entries and the full-level stream alike - render
`module!section` when the landing refines to a module image. Region-level landings
(no module/section refinement) carry their region class in the payload's sentinel
segment and render the class name: `private-exec`, `private-data`, `mapped`.
Snapshot-captured and runtime-registered regions of the same class share one name
(the wire format distinguishes the tiers, 0xFF0x against 0xFF1x, and the signal
layer treats the runtime tier as sample territory). Unclassifiable regions -
MEM_IMAGE alignment gaps, unknown types - fall back to `runtime`.

Hand-mapped images the Ldr list never enumerates (reflective loads) are recovered at
image-group granularity: contiguous same-MEM_IMAGE snapshot regions chain into a
group, a group overlapping any Ldr module span is abandoned whole, and the lowest
64KB-aligned member's PE32+ headers define the synthesized `unknown-image-<base>`
module (size = min(SizeOfImage, chain union), appended after the Ldr set). Its pages
render `unknown-image-<base>!<section>` like any other image; unnameable fragments
(isolated unaligned pages, abandoned groups) stay region-level. The synthesized
records carry a flag the engine-side module iterations (ISA gate normalization, SEH
dispatch attribution) skip, so dispatch behavior is identical with and without them.

## xfer edge rules

A transition emits an xfer event only when it crosses between sample-territory
sides: sample image section to sample image section, sample image to
sample-allocated memory, sample-allocated memory to sample image.
Allocation-to-allocation hops, crossings into or out of system modules (API calls),
and entries into system-issued (infrastructure) memory stay silent: xfer is the
unpacking and OEP-jump signal, not an API-call trace.

An allocation counts as sample-allocated when its issuing call chain carries a
sample-side frame (a bounded stack scan at the alloc seam decides it); system-issued
allocations - CRT or CLR JIT machinery - map and answer but stay event-silent.
Captured regions tied to a module span (image alignment gaps, companion thunk pages
such as ntdll's forwarder-thunk page) are that module's territory, and a packed
sample's stub page is sample image (a section-covering tail page inside the sample
image span). Orphan captured regions outside every module span are sample side.

## `sheller capture` (Windows)

`sheller capture <sample.exe>` photographs a real process into the v1 snapshot
the other subcommands replay. The sample is spawned suspended
(`CREATE_SUSPENDED`) under the real Windows loader with its entry point patched
into an in-place spin (`EB FE`) and its TLS callback array zeroed, then resumed
only until the loader has finished and the main thread spins at the entry: the
sample executes zero instructions of its own in the real process. The
photographer reads registers, TEB and every committed region, and the process
is terminated once the snapshot is complete. `--shellcode` blobs are embedded
verbatim into a generated minimal wrapper PE (one RX section, entry at its
start) and ride the same route.

The replay side never runs guest code natively: `run`, `unpack` and `analyze`
execute the snapshot inside the user-mode emulator, guest syscalls are answered
by the engine's policy table (default deny), and the guest has no access to the
host's network, registry or filesystem - its `NtWriteFile` bytes reach the host
only through `--guest-stdout`. What lands on disk is sheller's own output
(snapshot, report, dump regions, repaired image).

That is analysis-tool isolation, not a hardened sandbox: the capture process
maps the sample's image and runs the loader over it (security software may react
to the sample file), and the engine is user-mode. If the sample is hostile
enough to worry about, run sheller inside a virtual machine.

## Dumping dirty regions

`--dump <dir>` exports the write ledger at the exit trigger: for every region the
guest wrote (or allocated at run time), one raw `.bin` file named by its hexadecimal
base, plus a `manifest.txt` (base / size / type / protection / first dirty page,
fixed-width hex, base order). The five deterministic stops dump - normal exit,
crash fallback, budget exhaustion, xfer target, esp target - while a pure
wall-clock timeout does not. A wall clock crossed inside the leg the target ends
still dumps: a target stop vetoes the finish-time wall-clock recomputation. The
same replay produces byte-identical files.

## Repair inside `unpack`

Repairing happens inside `unpack`; the library's `repair_dump` stays public for
direct use. Each manifest region aggregated by allocation base is probed for a PE
header, its bound import thunks are resolved against the snapshot modules' exports,
and the result is rewritten as name imports and dumped as `repaired_<base>.exe`.
The three-state conclusion (complete / partial with a per-thunk listing / failed
with a reason) is returned structurally in `UnpackOutcome::repair`; the library also
delivers it through the diagnostics log - one `info` per region, one `debug` per
uncovered thunk, a `warning` with the reason for failures - so a host with a sink
sees it and a host without one reads the field. No `repair_report.txt` is written.
Regions without a valid PE header - bare shellcode buffers - are kept as they are.

## `sheller unpack`

`sheller unpack <sample>` is the one-shot pipeline on every host: Windows
captures, other hosts construct the v1 container from the sample and the
synthetic system modules and replay it - then run with dump, engine-native
repair, and target-region selection. It produces exactly two artifacts:
`<sample>.unp` (or `--output`) and one report (`<output>.report.json` by default;
`--report <path>` overrides it). `--budget` (`-b`) bounds the underlying run in
integer millions (`0M` = unlimited, the default); `--timeout-ms` bounds its wall clock
(30000 when no budget is given, 600000 with one), and `--stop xfer=<n>` stops before the Nth
execution transfer as a successful stop. The stop targets join here too:
`--stop esp` / `--stop esp+xfer` stop
at (or arm on) the confirmed entry stack restore - see "Stop targets" above. A
budget stop still writes the dump and
repairs; an xfer stop writes the dump and repairs with `failure` empty; a timeout writes
no dump and surfaces as a run failure. Without `-b` the CLI
prints a one-line hint on standard error naming the effective wall clock and pointing at
`-b`. The standard output also carries a one-line repair verdict summary
(`repair regions=N complete=... partial=... failed=... not-image=... uncovered=N`)
derived from `UnpackOutcome::repair`, independent of the log threshold. There is no
`<output>.reports/` directory and no `repair_report.txt`.

Repair fidelity follows the executed container, and both hosts execute a world
with the sample's Ldr entry and module exports: the packed corpus lands
`verdict=complete` on both routes, with no uncovered thunk. The non-Windows
container also feeds the attribution probe, so the judgment stream is populated
(judgment entries, semantic events and `module!section` endpoint names) instead
of the retired zero-signal boundary; at full level the report additionally
carries the merged event window. `--keep` passes an explicit work directory and
prints its path, so the intermediates survive the call. `--save-snapshot` writes
the snapshot the run executed: the captured bytes on Windows, the constructed
container elsewhere (replayable with `run --from-snapshot`). Its size follows the
inputs - the packed corpus constructs about 2.5 MB (sample image + module pages +
environment); a large sample's own image dominates, and zero-filled mappings are
recorded content-absent.

## The loader construction and container replay

On non-Windows hosts the engine constructs the guest world from PE bytes -
deterministic layout, relocations, TLS callbacks, imports resolved against the
synthetic system modules - serializes it as a v1 container, and executes that
container through the snapshot replay path. The construction is the only
producer, the replay the only executor: `prepare_pe_file` is an internal step,
`run_pe_file` keeps its public signature but constructs and replays internally,
and the container is also the repair input. On Windows hosts `run_pe_file` keeps
the live loader entry (the production sample path is capture; the loader entry
serves the loader corpus tests).

The replay rebuilds the loader-side tables (module and export index, LDR entry
handles, API interception entries, TLS callbacks) from the container's own module
pages and the synthetic directory. It does so only when the container's module
bases equal the finite synthetic base set exactly - captured containers keep
their replay behavior unchanged. PE32 sample input is refused on non-Windows
hosts: the 32-bit route does not start there yet, and the refusal names it
instead of silently entering a broken path.

## Determinism, baselines and diagnostic traces

Every run of the same snapshot produces a byte-identical event stream: one cursor
numbers the engine events, the forwarded page/code facts and the judgment events,
with no wall clock anywhere, and guest time advances by executed instructions
(KUSER_SHARED_DATA ticks and the RDTSC answers alike). Clock-based delay loops
therefore complete in bounded emulation time, and burn-loop detection collapses
pure-counter spins behind a `loop-skip` judgment. Committed per-config baselines in
`tests/goldens/` pin the event-stream digests of the deterministic-termination
corpus, and a micro-benchmark gate holds the full syscall chain under a 10 us/call
red line.

Diagnostic traces (`SHELLER_SEH_TRACE`, `SHELLER_LOOP_GATE_TRACE`,
`SHELLER_FILE_TRACE`) are `kDebug` log records, rendered only when their site switch
is set *and* the host's sink threshold takes them; they reach the sink the host
installed. The shipped CLI is one such host: its sink writes through spdlog, with the
level decoration on standard output, and its threshold is `warn` unless you say
otherwise - so setting a variable alone changes nothing.

```bash
SHELLER_LOOP_GATE_TRACE=1 sheller run sample.snap --from-snapshot --log-level debug
```

`--log-level {debug,info,warn,error}` on `run`, `unpack` or `capture` is the lever:
that run puts the loop-gate summary in the CLI's output, and the same run at the
default level does not. A library that installed no sink hears nothing either way. The
observable event stream is untouched by any of this: the committed baselines
reproduce byte for byte with all three switches set and the records rendered. The one
ungated exception is the unhandled-crash line, a `kWarning` record, because an
operator needs it without asking for diagnostics.

[../tests/README.md](../tests/README.md) maps the suites that hold these claims down,
platform by platform.
