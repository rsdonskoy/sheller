# tests/

GoogleTest suites plus the synthetic samples, thunks, blobs and golden
baselines they drive: 79 ctest tests register on a Windows host, 61 on a Linux
host (both measured with the runner-admission merge; the new portable target
registers on both). Portable units run on every platform
and CI job; Windows-only ones need a real capture host (real loader, real
system DLLs, ml64/nasm toolchain). The Linux side has a local pre-push gate of
its own, driven by two tracked scripts under `tools/` - see "Local Linux
verification gates" below.

Two of them are the shared-library faces: `shared_api` (direct calls
through the shared interface library) and `export_surface` (its symbol face
reconciled against a checked-in list). Two numbers are worth keeping apart when a count is quoted. Locally the whole
registered set runs (`ctest --preset windows-release` -> 79, Linux -> 61); CI
excludes the corpus-heavy live-capture entries, so its suite is smaller - with
`-E "event_baseline|exception_e2e|behavior_e2e|loader_byhash_x86_e2e|capture_x86_e2e"`
Windows runs 74 (measured on the 79-test set) and Linux runs 60 (only
`event_baseline` of those five registers there, so the exclusion removes one).
Registration is configuration-independent: Windows Debug registers the same 79,
and the new portable target was not re-run in the Debug configuration. The
Debug `event_baseline` digest golden is stale at HEAD (a clean
`b5e3828` worktree reproduces the same drifted digests while the Debug product
reports stay byte-identical to the Release baseline); it is recorded, not
re-pinned by this batch. What the discipline-and-diagnostics
work added on top of the older set is the four engine discipline gates,
`shared_guard`, `engine_diag`, the three `engine_trace` runs of one binary,
`concurrency`, and the POSIX-only `export_guard_injection`. What the delivery-surface
batch added on top of that is `version_consistency` and `guest_sink_guard` (both
platforms), the three `SyscallRunGuestSink` cases inside `syscall_e2e` (Windows), and
the installed-prefix consumer under `tests/install-consumer/`, which is deliberately
**not** a ctest entry - see "Installed-surface checks" below. The esp-law batch
added the portable `esp_target` suite and the `--stop` faces inside the two CLI
suites. The runner-admission merge added the portable `admission_diff` suite
(both platforms): the two admission routes' plans are compared directly, and the
plan text is frozen in `tests/data/admission-plans/`.

## The two link routes, and which suites sit on which

A test target links **either** the shared interface library (`sheller_shared`)
**or** the static core - never both, because a binary holding both keeps two
copies of the process state (the log sink is the visible one). The consequence
for reading these files: the six product names (`analyze` x2, `unpack_sample`,
`capture::run`, `log::set_sink`, `unicorn_version_string`) are *defined* only in
`src/shared/api.cpp`, so:

- `shared_api_test` is the only suite that links `sheller_shared`, and the only
  one that calls those names.
- Every other suite links the static core and calls the internal names the
  forwarders point at: `api::detail::analyze_path_impl` /
  `analyze_bytes_impl` / `unpack_sample_impl` (declared in `src/api/wiring.h`),
  `capture::detail::run_impl` (`src/runtime/capture/capture_detail.h`),
  `log::detail::set_sink_impl` (`src/engine/log_detail.h`),
  `engine::detail::unicorn_version_impl` (`src/engine/engine_detail.h`).
  Fifteen files call them: `capture_test`,
  `behavior_e2e_test`, `event_baseline_test`, `exception_e2e_test`,
  `syscall_e2e_test`, `rebuild_test`, `iat_repair_test`,
  `capture_x86_e2e_test`, `wrapper_pe_e2e_test`, `log_test`,
  `analysis_facade_test`, `concurrency_test`, `engine_diag_test`,
  `engine_trace_test` and the opt-in `analysis_facade_local_corpus`.
  Calling a product name from a static-core suite does not link - that is the
  gate, not a convention.

## Test executables - portable units

| target | ctest name | what it covers |
|---|---|---|
| `cli_version_test` | `cli_version` | `sheller --version` |
| `log_test` | `log` | log facade: merged `set_sink(sink, level)`, level threshold, empty-sink silence, replacement, and the `would_log` pre-check agreeing with what `write` delivers - driven through `log::detail::set_sink_impl`, the name the static core defines (`sheller_engine` only, no shared library) |
| `guest_sink_guard_test` | `guest_sink_guard` | the engine's other host-callback delivery point, called directly: `engine::sink_trampoline` with a `std::function` that throws loses only that delivery (a sink that records before throwing keeps `one`/`three` and reports `entered=3, thrown=1`), the handler is a catch-all not a typed one (`throw 42` and `throw "..."` are both contained), and wiring it the way `syscall_dispatch.cpp:33` does - through the `syscalls::WriteSink` POD's inline `write_bytes` - shows one handler on that path rather than one per layer. Portable on purpose: the containment is a property of this frame, not of the Windows-only capture route needed to reach it from a real guest, and the end-to-end half is covered twice over - across a crafted snapshot in `analysis_facade_test`'s `EngineGuestOutput` group (portable, needs no corpus file) and across a captured sample in `syscall_e2e` (Windows, where the capture route exists to produce one). Note honestly recorded in the file: "the empty-sink test sits outside the handler" is **not** falsifiable from here (calling an empty `std::function` raises `std::bad_function_call`, which this handler would swallow), so that clause is held by the single-construction-site grep and the gate allowlist, not by a case |
| `self_contained_syscallrun` | `self_contained_syscallrun` | public-header self-containment gate: `<sheller/syscallrun.h>` as a TU's sole include |
| `self_contained_analysis` | `self_contained_analysis` | same gate for `<sheller/analysis.h>` |
| `iat_repair_test` | `iat_repair` | IAT mapper/audit units, repair pipeline over crafted snapshots - portable by design; the packed.exe acceptance is the only WIN32-gated section. Registered in the default build on both platforms (the Linux repair e2e). Verdicts are asserted structurally and through the captured diagnostics (one `info` per region, one `debug` per uncovered thunk, `warning` with the reason for a failed region); no `repair_report.txt` exists. `iat_repair_portability` greps the file for windows.h/unicorn regressions |
| `unpack_cli_test` | `unpack_cli` | `sheller unpack` one-shot flow over packed.exe through `unpack_sample` on both hosts - Windows capture route, other hosts a constructed container over the generated synthetic modules: `.unp` + one report (`<output>.report.json`, `--report` override asserted to be the only report) + a one-line verdict summary whose numbers agree (`complete` on both routes; the old loader-route `partial` boundary retired with the container route); no `.reports/` directory and no `repair_report.txt`; `--stop xfer=1` on the packed corpus reaches the OEP transfer and still lands the image/report, while `--stop xfer=5` misses with the hint line (bare - no limit is involved) and still unpacks; `--stop esp+xfer` stops at the delivery boundary and stamps the payload entry (`rva 0x213dc`, the plain-unpack reference value), while bare `--stop esp` confirms the restore and still writes the repaired image with no OEP stamped (the entry point stays the stub's); the `--stop` parse faces hold on this subcommand too (typo, non-integer, the retired `--xfer` spelling refused as an unknown argument, double-`--stop` mutex, the subcommand help naming the three goals); on non-Windows hosts it also drives `run`: save-snapshot -> `--from-snapshot` report equality, default zero intermediate snapshot, missing-directory exit 2 with the one-line hint, and a PE32 sample refused with a distinct capture-class message |
| `shared_api_test` | `shared_api` | the DLL/so route: links `sheller_shared` only, includes public headers only. All six exports addressed and called; the portable negative faces (golden sentinel -> snapshot-IO, non-snapshot bytes -> capture, missing path -> snapshot-IO) prove the failure mapping survives the boundary; Windows chains `capture::run` into `analyze` over the hello sample and unpacks packed.exe for real (seconds-scale, live capture - the same cost `unpack_cli` carries); other hosts construct the v1 container (`unpack_sample` lands the .unp with a `complete` verdict; `analyze` on the same corpus reports its post-OEP payload crash as a run failure carrying the statistics and instrumented artifacts - the facade's mapping, since analyze has no dump stage to absorb a stop) and check that `capture::run` refuses with a reason. The sink round trip is the state-consistency proof for that one-route rule: a recording sink installed through the exported `log::set_sink` must receive the engine's own `engine run start` record (raised inside the library, statically linked there) - raising the test's threshold to kWarning drops it and the case goes red, so the assertion is not vacuous. It cannot craft a snapshot - `snapshot::Writer` is not exported - which is why the data-building suites stay on the static side |
| `export_surface_gate.cmake` | `export_surface` | `cmake -P` gate (not an executable): reads the built library's dynamic face - `nm -D --defined-only` through `c++filt`, ` T ` lines only; `dumpbin /exports` through `undname`, tools taken from the configured toolchain directory, not PATH - and set-diffs it against `expected_symbols.linux.txt` / `expected_symbols.windows.txt`. Any extra or missing symbol fails by name; the list must carry exactly six entries. Registered by default on both platforms, skipped on `linux-sanitizer` (a sanitizer `.so` carries detector-runtime symbols no list should pin) |
| `report_events_test` | `report_events` | report events section over the facade artifacts: exact per-type counts header (judgments included), one seq-ordered `events.detail` list at semantic and full levels with the whole-run `seq` (four keys always: `counts`, `detail`, `stub_calls`, `loss`), semantic entries sharing the primary key merging into one line with `count`, the first 8 `seqs`, and secondary first/last values (`kusd-access` aux; full stays per-event), the counts level's compact report (`detail` empty, null loss), default-column judgment/fact entries and their subtype/annotation fields, xfer sentinel classes, stub snapshot, the one-entry-per-line detail layout (empty list stays `[]`), byte-exact determinism, and the full-level merged stream: an ordinal both tiers carry renders once with the semantic entry winning, window entries interleave by the whole-run ordinal, `loss` is the `null` pair at semantic level and both counters (zero included) at full level, and a malformed window tail stops the walk without fabricating an entry |
| `event_ledger_test` | `event_ledger` | ledger ring, TLV/JSON dumps (write_json = the minimal nameless render), exception `code` render, region-sentinel attribution render; the CLI render library's full-level events section and the report's `stub_calls` key are exercised through the TLV+name-table entry points |
| `api_call_codec_test` | `api_call_codec` | kApiCall function-form and kSyscall payload wire codec |
| `api_descriptions_test` | `api_descriptions` | API description table invariants and the parameter-name join over the CLI render library's full-level stream (the sample-origin call-flow view retired with the companion-file family) |
| `analysis_facade_test` | `analysis_facade` | analysis facade over `sheller_api` (its `api::detail::*_impl` names, since the product names live in the shared library): magic routing, three failure kinds, the default stream + window tier (real ring eviction, one seq join), the event-stream tee (forwarded facts and judgments share one cursor), host subscription (mask filter, throw guard, facade-owned sink slots), guest-output discard - asserted twice over, through the facade and one level down at the engine entry `run_snapshot_syscalls`, because that is where the discard default lives: a two-write snapshot reaches a sink as `{"ab", "ok\n"}` in emission order, the same run with no sink leaves both host standard streams at zero bytes, and dropping the bytes changes neither the run statistics nor the event stream. The same portable fixture also carries the guest-output callback's throw contract end to end on both platforms (the unit level under it is `guest_sink_guard`): a sink that throws on its first delivery loses exactly that write - the second still arrives at the same sink in guest order - the run converges to the same verdict with the same five statistics and the same event rows, both host streams stay at zero bytes, and a ruler case has the host write from inside the callback so that "zero bytes" cannot be satisfied by a capture that never redirected anything; a nested counter loop is skipped under the burn-loop fast-forward (the `loop-skip` event reaches the report and the outer loop's cached re-entries exit); unpack timeline/save-snapshot; Windows-gated: full packed unpack pipeline, two-thread work-dir uniqueness (four threads on both platforms is `concurrency_test`), repair-failure artifacts, budget bounds; Linux-gated: constructed-container unpack via synthetic modules (complete verdict, instrumented artifacts), the crafted save-snapshot size bound, and the PE32/missing-directory refusal distinction. Its crafted-snapshot serializer moved to `snapshot_fixture.h`, shared with `engine_trace_test` and `concurrency_test` rather than copied a third time. The portable `EngineXferStop` group drives a two-section crafted image: the first-transfer success (landing block counted and `block-exec`-visible but not executed, dump present), counting with no sink, a missed target falling back to normal termination, instruction- and block-budget precedence, the stop holding with both the instruction budget and the wall clock unbounded (the only case where the leg loop's explicit break is load-bearing), the mid-leg wall-clock veto (a 1ms clock crossed before the leg the transfer ends, every leg leaving ahead of the boundary check), pure-timeout no-dump, byte-identical replay dumps, and the `AnalysisOptions::run.xfer_number` pass-through; the Windows-gated unpack cases pin the OEP stop through `unpack_sample` and the mid-leg wall-clock veto through the full unpack pipeline (a delay-then-transfer corpus sample with a 1ms clock still lands the `.unp`) |
| `snapshot_format_test` | `snapshot_format` | v1 snapshot codec round-trip against the golden file |
| `pe_headers_test` | `pe_headers` | portable PE header walk (entry, TLS, preferred base) |
| `contract_test` | `contract` | guest-contract seams + TLV codec, golden bytes; the event-type table pins the id space (25 = `stack-restore`, the name spelling, and `stack-restore` sitting outside the judgment range - engine-produced, not rule-layer) |
| `esp_target_test` | `esp_target` | the esp stop target over crafted save/restore corpora through the public `run_snapshot_syscalls` (portable, fixture-pinned addresses): the `esp` form stops inside the completed restore read with the terminate tail unexecuted (one logical block, zero syscalls - the block count carries the deterministic write-prot leg split), `esp+xfer` arms there and the xfer machinery stops before the landing block (`esp_stop=true` alongside `xfer_stop=true` with `xfers` carrying the ordinal - the public contract; a transfer stop the arm never preceded is the xfer target's alone and leaves `esp_stop` clear, the explicit-xfer-ordinal coexistence case (the public API spelling of the CLI's `--stop xfer=1`)), the hit form on the arm fixture stops before the jump, a non-pop window read (the anti-debug shape) is rejected by the decode gate alone and the run terminates, `pop rsp` at the completion slot (the stack-pivot shape) is excluded from the closed set - no stop, no event, silent miss, a restore block at the image page's last bytes still confirms (the decode reads whatever is mapped; a complete short pop is decodable), the silent cells (entry without pushes = no monitor; relocated stack = armed window never read) close on the miss path, the burn-loop probe's speculation keeps the window silent while the fast-forward still lands the post-loop restore, and a no-goal run on the hit corpus is untouched |
| `api_call_codec_test` | `api_call_codec` | kApiCall function-form and kSyscall payload wire codec |
| `registry_intercept_e2e_test` | `registry_intercept_e2e` | engine registry interception over the loader route (advapi32 semantics) |
| `mem_region_map_test` | `mem_region_map` | PE32+ section-table parse (+ SizeOfImage legality) + three-tier attribution queries (hierarchical adjudication: section refinement beats protection-split region fragments); runtime evolution (`register_region`, page-granular `apply_protection` carve with origin/flag inheritance), region classification pure function, stable interval identity keys under split/re-sort; module ownership truth table (overlap / adjacency / orphan) + xfer territory and edge truth tables; unknown-image group synthesis (instoll-shape 8-region chain, chain ordering/no-overlap/capacity self-clamp/determinism) |
| `native_gate_test` | `native_gate` | loop-native gate: Zydis closed-CFG classification over fixture bytes (accept/reject classes, self-write, exit targets, malformed-stream soundness) + verdict-slot ABI |
| `syscall_number_map_test` | `syscall_number_map` | ntdll export enumeration + stub-immediate decode; semantic policy dispatch (the synthetic ntdll image builder lives in `fake_ntdll.hpp`, shared with `run_facts`) |
| `write_ledger_test` | `write_ledger` | page-dirty write ledger (`on_write`, runtime `add_region`) + original-bytes dump export and manifest |
| `run_facts_test` | `run_facts` | the read-only run-facts layer the run-state assembly consumes: the PEB-derived current directory on the happy path (Windows-only, because the captured separator is a backslash; it also exercises the appended-separator branch) plus its degradation cells (no PEB, null ProcessParameters, odd UNICODE_STRING length, unreadable path buffer, non-absolute path, not a directory - each keeps the guest's own base), the sample module's region-map record on a hit (known/index/SizeOfImage) and its no-match cell, the syscall number <-> name tables over the shared fake ntdll (both directions built together, a non-Nt export in neither), and the assembly-stage failure's raw `uc_err` on a crafted v1 container whose entry address is unmapped - pinned to `UC_ERR_WRITE_UNMAPPED` with every statistic still zero (the entry-byte restore is the first write, so it fails before any state or hook exists; the assertion was proven red against the old zero placeholder) |
| `run_plan_test` | `run_plan` | the run plan's pure decision core over hand-built guests with a null unicorn: alias rows sharing one VA collapse to one stub slot with the first whitelist name, an intercept supersedes a boundary trap on the same VA, directory mode counts only the explicit whitelist while the synthetic mode counts every non-intercepted export, heap/Ldr family names match through `fold_name`, an already-registered VA is never appended twice, the intercept VA's module index resolves inside the module span and falls back to the `0xFFFF` sentinel outside, and the per-mode trampoline/allocator cursors sit on the layout constants with no overlap against the heap, stack and environment ranges (T1-T6 and T8 of the split assessment; each assertion was mutation-proven red) |
| `behavior_rules_test` | `behavior_rules` | judgment-event emission over synthetic fact sequences: every rule pattern, one event per hit (no dedupe, no capacity cap), the rule fields carried on the wire |
| `wrapper_test` | `wrapper` | minimal-PE blob construction for bare shellcode |
| `admission_diff_test` | `admission_diff` | the two runner-admission routes are one algorithm: T1 drives the Windows capture admission (`capture::admit_dll_sample`) and the synthetic construction admission (`engine::admit_synth_dll_sample`) over the same five-sample real-export corpus and asserts the plans are equal (`RunnerPlan::operator==`; Windows-gated - the capture route needs real system DLLs); T2 serializes each plan to the module / symbol / ordinal text frozen in `tests/data/admission-plans/*.plan` under the sample's arrival name, and checks it through the synthetic route on **every** platform (Linux CI's admission coverage) plus the capture route on Windows; T3 asserts both routes refuse the same rejection corpus (path-shaped dependency name, missing export, arrival-name collision, unverifiable module) without comparing their deliberately different wording. The fixtures are hand-built x64 PEs with an arbitrary import table, generated in-test. The assessment's over-capacity cell is not reachable from sample bytes - `parse_imports` bounds a sample at 64 module descriptors, so a plan carries at most 66 imports against the 96-entry runner capacity - so the capacity guard has no corpus and the test does not pretend otherwise. The module-name fold (`fold_module_name` / `fold_module_name_equals`) is pinned here too: ASCII-only case folding, non-ASCII bytes pass through, and equal-length comparison |
| `syscall_bench` | `syscall_bench` | micro-benchmark + red-line gate: syscall chain <= 10 us/call, bare hook cost |
| `det_helper` | - (no ctest entry; driven by `dll_capture_e2e`) | resident determinism helper: one replay per invocation over a given container - raw event stream (`[type][seq][pc][payload]` records) to disk through the facade's host observer, exit dump, repair into a `.unp`; no budget and no wall clock, terminated in its stats line only |
| `event_baseline_test` | `event_baseline` | relocation-normalized event-stream baselines vs goldens: the production event stream (rules + forwarding + one cursor) over the Windows sample set; address-bearing forwarded/judgment payload fields are normalized, the type/order/pc pins remain |
| `rebuild_test` | `rebuild` | snapshot rebuild into Unicorn, entrypoint proof (real-capture paths Windows) |
| `loader_test` | `loader` | loader-route pure functions: PE parse, deterministic layout, relocs, TLS |
| `loader_env_x86_test` | `loader_env_x86` | loader-route environment pure functions + the x86 loader-run e2e |
| `uc_context_contract_test` | `uc_context_contract` | pins the unicorn context save/restore behaviors the thread scheduler builds on |
| `seh_dispatcher_test` | `seh_dispatcher` | engine-side SEH dispatcher: UNWIND_CODE prolog accounting table, plus the malformed-unwind-data cases behind the index checks (opcode count past the prolog, an X64 frame register indexed past the 16-slot table, a chained info token asking for more codes than the allocation holds) - each built as real snapshot bytes and run through the engine entry, asserted as a stop rather than a crash |
| `loader_pe_e2e_test` | `loader_pe_e2e` | loader-run e2e: TLS order, direct syscall, terminate, budget exhaustion, cross-run determinism (non-Windows hosts construct the container and need the generated synthetic modules) |
| `capture_cli_test` | `capture_cli` | `sheller capture` CLI behavior (positive path Windows) |
| `synth_modules_test` | `synth_modules` | synthetic system modules generated from frozen manifests; engine synthetic-mode run over the packed corpus through the constructed container |
| `boundary_derive_test` | `boundary_derive` | directory-mode boundary derivation: syscall numbers validated in the source body (never by name prefix), names/ordinals/aliases/forwarders preserved, EAT rebuilt, weld-slot + e_res2 marker layout, double-derive determinism, named rejections; derived images walked by the loader-side index/forwarder resolver |
| `boundary_seed_test` | `boundary_seed` | boundary-manifest codegen: deterministic, committed seed freshness enforced, the pinned fixture binding compiles |
| `boundary_manifest_test` | `boundary_manifest` | manifest applicability verdicts are named rejections; seed rows drive the derive end-to-end; forwarded exports classify along the chain |
| `boundary_metadata_test` | `boundary_metadata` | metadata codec: deterministic encode, named over-limit rejection, damage-by-name decode rejections, the e_res2 marker round trip |
| `apiset_map_test` | `apiset_map` | API Set map generator determinism; bounded reader named rejections (magic/version/arch/anchor/range/conflict); the explicit context resolves directory maps with no prefix fallback, synthetic route unchanged |
| `loader_directory_test` | `loader_directory` | the directory-mode route end to end: strict source tiers, required anchored API Set map, named closure rejections (host system directories never read), marked synthetic fallback, resident real-module IAT binding before any map bytes exist, trap stop with the named diagnosis, whitelist-driven stub counting (compat counted once per alias pair, real bodies never), metadata region + e_res2 marker, bilateral replay-side checks (one-sided or damaged containers rejected by name), packed-DLL directory construction determinism + replay, and the env-gated real-DLL corpus test (`SHELLER_REALDLL_DIR` carrying real ntdll/kernel32/kernelbase + the anchored apiset-map; skip when unset, never in CI) |
| `snapshot_craft_test` | `snapshot_craft` | the `snapshot-craft` capability: a v1 container constructed from a prepared guest and replayed through the snapshot route - self-sufficient execution up to the OEP transfer with API answers, base-ordered/writable record fidelity (each condition separately breakable back to the 2-block failure), attribution to `module!section`, byte-identical double construction plus replay, the exact-base synthetic-world predicate (congruent-but-unequal bases do not trigger), reattach table equality against the construction (intercepts as the documented superset), LdrLoadDll handle == the container's LDR entry VA and `STATUS_DLL_NOT_FOUND` on a resident miss, and the machine-derived container size bound with an in-test reverse injection |
| `linux_packed_e2e_test` | - (`EXCLUDE_FROM_ALL`) | opt-in: a Windows-captured packed snapshot replayed and repaired on the Linux engine (needs `tests/packed_lin.snap` transferred) |
| `analysis_facade_local_corpus` | - (`EXCLUDE_FROM_ALL`) | opt-in local-corpus equivalence for the facade: instoll pins the default stream (6 records: 5 syscall with 3 rejects + 1 rdtsc; rdtsc at wire_seq 87324; all 16 `mem-write` instances are counts-only because none is a sample-code write into a system module) and the window-side counts (57077 block-exec, 180211 sample-code, full window with eviction), packed.exe (Windows capture) pins the judgment face (exactly one `oep-candidate` event and the single `packed.exe UPX1 -> UPX0` xfer). Instoll snapshot is local corpus; default path is the analyzed run30 capture, `SHELLER_INSTOLL_SNAP` overrides. Build + run explicitly: `cmake --build --preset windows-release --target analysis_facade_local_corpus`. Both tests also arm an unreachable `xfer_number=2` and pin `xfers` against the emitted `kXfer` event count (instoll 0/0, packed.exe 1/1) - the counter skips burn-loop probe speculation while the emitter does not, so that agreement is the evidence that no probe crossed an attribution-identity boundary on these corpora |

| `shared_guard_test` | `shared_guard` | the export layer's containment helpers (`src/shared/guard.h`): `guard`/`contained`/`internal_error_message` mapped through the six entries' result types, the `"internal error:"` prefix, and a tripwire that the prefix alone fits small-string optimization (so the fallback path needs no allocation - the one thing a failed allocation inside the guard must not need) |
| `export_guard_injection_test` | `export_guard_injection` | Linux only: the allocation-failure half of the contract, reached by defining global `operator new` in the test executable (the `.so` leaves it as an undefined dynamic symbol, so the executable's definition wins - proven by a ruler case that counts interceptions). Every entry is swept through the armed window; asserts the failure surfaces as an `internal error:` result, that a run's resources are released before the answer, and that a `set_sink` that throws leaves the previously installed sink intact |
| `engine_diag_test` | `engine_diag` | the diagnostic helper (`src/engine/diag_trace.h`) with a ruler that measures rendering rather than delivery: a `std::formatter` specialization that counts its own invocations. Pins that a disabled site switch and a too-high host threshold each stop `std::format` from running at all, with a positive control per case (records alone cannot tell a skipped render from a dead sink), and that the site switches read the environment (unset in this binary by design - the switch-on half is `engine_trace`) |
| `engine_trace_test` | `engine_trace`, `engine_trace_quiet`, `engine_trace_nosink` | one binary, three ctest entries: the site switches cache their `getenv` in function-local statics, so "switch on" and "switch off" cannot share a process and the mode comes from `argv`. Every case asserts both halves - the marker arrives at `kDebug` in the switch-on run, and no such record arrives in the quiet one, which also runs a census naming the only records allowed to reach a sink unasked (the engine's `run start` line, and the `kWarning` unhandled-crash line). The third entry is the third cell: switches set **and no host sink**, where the library has to reach neither descriptor 1 nor descriptor 2 - it captures both, runs the gated corpus and (on Windows) the unhandled-crash one, then runs them again *with* a sink and requires the records to show up, so "nothing was written" is never a statement about a site that never fired. Each entry names the cases it selects, and the `--no-sink` run fails itself if its filter matched nothing |
| `concurrency_test` | `concurrency` | the concurrency contract through the static core: four threads run the same deterministic snapshot through `analyze_bytes_impl` and each thread's artifacts are compared against a single-thread baseline as one canonical byte string - timeline TLV wire bytes, run statistics, exact per-type counts, loss counters, **and the values of every record** (semantic events field by field with their parameters and judgment fields, OEP candidate addresses, stub-call rows, the timeline name tables). Comparing only sizes would let four threads agree on how many OEP candidates they found while each found different ones, so a second case in the same binary digests pairs that have equal sizes and different contents and requires the digest to move; four assertions of it, plus the baseline asserted non-empty, keep the comparison from being vacuous. `LogDeliveryThread` holds the other half of the callback contract: every record the facade delivers arrives on the thread whose call produced it (one run on the caller's own thread, then four concurrent runs), which is what makes a reentrant callback a deadlock rather than a race. Four `unpack_sample_impl` calls with `work_dir` left empty must be handed four distinct generated directories; the `.unp` byte-equality case runs off Windows, where the loader route is deterministic (on Windows the same input rides live capture, which drifts by design) |

### Engine discipline gates

Four `cmake -P` scripts (not executables) scan the engine's source set and fail as
ctest entries. The scanned set is the union of `sheller_engine`, `sheller_capture`
and `sheller_unpack` sources across both platforms - 71 files / 39 translation units -
generated at configure time into `build/<preset>/tests/engine_gate_sources.txt`, so
a file joins the discipline by being added to a target rather than by editing a
list. `sheller_unpack` is in it because its objects reach the shared library through
the same engine link: code that lands in the product is scanned whether or not it was
ever compiled with the flag the discipline replaced.

Each rule is proven by a mutant, not by a reading: a one-statement injection into a
real engine TU, the gate run over it, and the requirement that it go red *and* name
that file, on both cmake toolchains, because they disagree (see the `while(TRUE)`
note below). The harness that does this is a scratch tool rather than a checked-in
one, and it currently holds 47 cases. The worth of a case is that it names a
violation the rule claims to catch and that an earlier version of the gate let
through - a `throw` inside a short lambda, `copy_file(a, b)` (a comma is not an
`error_code`), `std::wcout`, a second `.at(` on a line that already has one - so the
proof is of the rule, not of the spelling someone happened to think of. A mutation
that only the gate's author could be proud of proves nothing. The negative half
matters too: a `snprintf` into a buffer, the same spelling inside a comment, and an
identifier that merely contains the banned word must stay green, and a mutation that
leaves an allowlist entry matching nothing has to be reported as stale rather than
ignored. A gate that has never been red has not been shown to watch anything.

| ctest name | rule | how the exception is recorded |
|---|---|---|
| `engine_nothrow` | no `try`, `throw` or `catch` **statement** in an engine TU. The core is compiled with exceptions enabled so a host exception can unwind through engine frames, but first-party engine code must not throw. Comments are stripped first and each keyword is anchored to token boundaries rather than to the start of the line: the anchors were only there to keep prose like "never throw" out, and they hid a `throw` that followed an `if`, a semicolon, or a `[...]` on the same line | `engine_nothrow_allowlist.txt`, `<path>:<pattern-id>`; today **two** files and four entries - `src/engine/log_state.cpp:try`/`:catch` (the log facade's delivery point) and `src/engine/rebuild_state.cpp:try`/`:catch` (`sink_trampoline`, the guest-output delivery point) - the two frames where the engine hands control to a host callback. `throw` is deliberately not exempt in either. A third file is not a third exemption but a new host-callback entry point and has to be argued for as one. Current readings: 4 statement hits, 21 naive token hits (comments, not violations), 4 allowlist entries |
| `engine_stdapi` | throwing standard-library API is banned outright in engine TUs: the `std::sto*` family, and `std::filesystem` operations whose `error_code` overload exists but was not used. The family is matched by shape (`filesystem::` + name + `(`) and a short list of names is released as non-operations, so a call nobody enumerated is demanded an `error_code` instead of going unwatched. The test is that the **last** argument is a name this file declared as a `std::error_code`; a comma in the argument list is not the test, and an argument list the walk cannot read - wrapped onto the next line, or nested - is a violation rather than a skip | no allowlist, no exemption: every `std::filesystem` operation in the library takes its `ec`, `temp_directory_path` included (the claim that it has no `ec` overload was checked against both toolchains and is false - `src/api/unpack.cpp` already uses the `ec` form). The gate prints its own counts so nothing multiplies quietly |
| `engine_at_sites` | bounds-checked subscripting (`x.at(`) is capped per file, not banned: the call text repeats and line numbers move, so an identity list would need re-maintenance on unrelated edits. Occurrences are counted, not lines: two `.at(` on one line are two subscripts | `engine_at_sites.txt` (`<path> <count>`; 5 files at their ceilings, 38 sites). A file with `.at()` and no row fails; a registered count above reality is reported so the table gets tightened |
| `engine_stdstream` | no engine TU writes a host standard stream: `fprintf`/`printf`/`wprintf` (and the `v` forms) to `stderr`/`stdout`, `fputs`/`fputws`/`fputc`/`fputwc`/`putc`/`putchar`/`fwrite`, `std::cerr`/`cout`/`clog` and their wide `wcerr`/`wcout`/`wlog` siblings, `freopen`, and a call whose stream argument is on the next line (counted, fail-closed). The bare identifiers `stdout` and `stderr` are themselves named nowhere in an engine TU, so the rule bans mentioning them - which is what closes the route of binding a stream to a local name and writing through it. `snprintf` is not a hit - it fills a buffer | `engine_stdstream_allowlist.txt`, `<path><TAB>needle<TAB>count` with the needle cut from the site's own line, **now empty**: an unregistered hit fails, an entry that stops matching fails (a rerouted site cannot leave a dead exemption), and a registered spelling that gains a second statement fails. A hit is claimed by the longest registered needle in its file, so the short opener of a two-line call cannot take a site a narrow needle names |

Both gates read files through one walker (`engine_gate_lines.cmake`) because there
is no correct "file into a list of lines" in CMake: `file(STRINGS)` merges a C++
line ending in a comma (918 elements for a 929-line file), and the naive split
either loses lines or inflates them depending on the escaping - so the walker takes
one line off the front of a blob per step, exactly 929 iterations for that file, and
the caller keeps the line number. Comments are stripped before matching, since these
files discuss their own diagnostics constantly. The same header records the
toolchain trap that made a gate green on one host and blind on the other:
`while(TRUE)` does not loop under cmake 3.25 in script mode (no
`cmake_minimum_required`, so CMP0012 is unset and `TRUE` is read as a variable name),
which is why the loop conditions are variables.

### Sanitizer and instrumentation presets

`linux-sanitizer` (ASan+UBSan) is the leak half of the exception-discipline
evidence - a throw escaping an engine frame no longer terminates the process, so the
cleanup is what has to be watched, and it runs as its own CI job.
`linux-tsan` is the ThreadSanitizer preset (configure/build/test): it is run by
hand, not in CI. Two facts about it are worth knowing before trusting a clean
output. First, the binaries have to start under `setarch "$(uname -m)" -R`: on this
WSL kernel TSan otherwise dies before the first test with
`FATAL: ThreadSanitizer: unexpected memory mapping`, and the other standard remedy
(raising `vm.mmap_min_addr`) is a host kernel parameter. Re-measured on the full
tree: the same `concurrency_test` binary without `setarch -R` prints that FATAL and
never runs a case; with it, 5 cases in 7.1 s. Second, it has shown it can find
something - the first version of `concurrency_test` kept its per-thread success
flags in a `std::vector<bool>`, which is a real data race when four threads write
neighbouring bits of one word, and TSan reported it along with a failing case. With
that fixed the concurrency suites come back clean. unicorn and Zydis come from vcpkg
uninstrumented, so the claim covers first-party code and the cross-boundary path, not
their internals.

Measured end to end (this is what the preset had never been given: the earlier run
covered only a handful of targets, so 34 of 43 cases were `Not Run` and the suite
cost was unknown). Full build `-fsanitize=thread`, g++-13, WSL2, 93 translation
units, 0 warnings, `ctest -N` 46 with nothing `Not Run`; then, under `setarch -R` and
with the CI filter `-E "event_baseline|exception_e2e|behavior_e2e|loader_byhash_x86_e2e"`
(45 cases, the same filter and the same round as the `linux-sanitizer` run beside it):

| | wall clock | ThreadSanitizer reports | flakes |
| --- | --- | --- | --- |
| `linux-tsan` (45 cases) | 31.83 s (30.07 - 31.51 s over 5 repeats) | 0 | 0 of 5 |
| `linux-sanitizer`, same filter | 23.91 s | n/a | 0 of 1 |

The decision rule for putting this in CI was written before the numbers existed: add
the job if 0 reports *and* the wall clock does not exceed `linux-sanitizer`. Zero
reports and zero flakes, but 31.83 s against 23.91 s - 1.33x, +7.9 s - so the rule
says no and `linux-tsan` stays a manual preset. The +8 s is cheap enough that the
rule was put to a human rather than applied silently; the answer was to keep the rule
as written. Either way the ceiling on the claim is the one stated above: first-party
code, this case set, no reports - not "the dependencies are race-free".

### Public-header self-containment gates


`self_contained_syscallrun` / `self_contained_analysis` compile an empty TU
whose sole include is one public header: a header relying on a transitive
standard-library pull is a latent embedder break the CI third-party-include
grep cannot see. Red-green usage: remove the suspect include from the header
under test and the target must turn red, restore it and it turns green. Note
that today's pinned toolchains transitively satisfy several headers (both
MSVC's STL and libstdc++ 13 pull `<vector>` in via `<map>`); the gate locks
them anyway so a stdlib internal reshuffle cannot silently unbreak. `<functional>`
is a red that reproduces on gcc-13 (std::function is not a transitive
freebie) - verified when the gate was introduced.

### Export-surface gate

`export_surface` is the symbol-level half of the same idea: the product face is
six names, and a build that exports a seventh (or silently stops exporting one)
should say which symbol rather than which count. The two checked-in lists are
platform spellings of the *same* six entries (`c++filt` and `undname` never
agree on text, so they stay two files; "exactly six entries" per file is what
keeps the pair honest). Regenerate - never hand-edit - from a release-shaped
build:

```bash
# Linux
nm -D --defined-only build/linux-release/src/shared/libsheller.so.0.1.0 \
  | c++filt | grep ' T ' | sed 's/^[0-9a-fA-F]* T //' | sort
# Windows (dumpbin/undname next to the configured compiler/linker)
dumpbin /exports /nologo build/windows-release/src/shared/Release/sheller.dll
#   -> name column, each through undname, keep the 'is :- "..."' text, sort
```

Red-green usage, both directions proven when the gate landed: add a seventh
`SHELLER_API` definition in `src/shared/api.cpp` and the gate fails naming the
extra symbol; delete `SHELLER_API` from one entry's declaration *and* its
definition in `api.cpp` and the gate fails naming the missing one. The second
red is only reachable because `sheller_shared` compiles with
`-fvisibility=hidden` on POSIX: without that flag the function keeps default
visibility and stays in `.dynsym` after the macro disappears, so the face would
still read as six on Linux while Windows went red. Build only `sheller_shared`
when running the mutation by hand - the in-tree consumers (CLI, `shared_api`)
link the product names and stop linking the moment one is un-exported, which is
the same fact the gate reports.

### Version reconciliation gate

`version_consistency` (`tests/version_gate.cmake`, `cmake -P`, registered by default on
both platforms) is the mechanism behind "the version is written once". `project()` in
the root `CMakeLists.txt` is that one place; the library file name and the SONAME
derive from it, so they cannot disagree by construction. The public header
(`include/sheller/version.h`) stays a checked-in file with three macros and a
`version_string()` literal, because the include-boundary and self-containment gates
grep `include/sheller/` directly and a header that only exists after a configure would
make those scans find nothing - so this gate compares the header's three macros and its
literal against the file's own `project(sheller VERSION x.y.z)` line, and against the
configured value as a third check that the build tree is not stale. On a mismatch it
prints both places with line numbers.

`vcpkg.json`'s `version` is deliberately out of scope: it names this package inside
vcpkg's manifest mode, and the project does not distribute itself through vcpkg, so it
is not a version claim made to a consumer of the library.

Red-green, all three measured: change the header literal `0.1.0` to `0.1.1` and it
fails naming `version.h:18` and `CMakeLists.txt:3`; change `SHELLER_VERSION_MINOR` to
`2` and it fails the same way on the minor digit; change `project()` to `0.2.0` without
reconfiguring and it fails on the configured-versus-file difference and says to
reconfigure. Each injection was restored byte-for-byte (sha256 before/after), not by
eye.

### Installed-surface checks (`tests/install-consumer/`)

The delivery surface - what a host that cannot see this source tree gets - is judged by
a real consumer of a real install prefix, not by reading the CMake files:

| piece | what it is |
|---|---|
| `tests/install-consumer/CMakeLists.txt` + `main.cpp` | the minimal consumer: one `find_package(sheller CONFIG REQUIRED)`, one `target_link_libraries(... sheller::sheller)`, no source-tree path, no vcpkg, no hand-written include directory. It calls `unicorn_version_string()` and **both** `analyze` entries - the path form and the bytes form - because `std::vector<std::uint8_t>` only crosses the boundary through the second one |
| `tests/install-consumer/run.cmake` | the driver: installs a configured build tree to a throwaway prefix, then runs the five checks below. A `cmake -P` script rather than a shell one, because it has to do the same job on a Visual Studio multi-config generator and on a single-config one |

**It is deliberately not registered in the default ctest set** - it needs an installed
prefix and a normal build does not have one. Run it after a build:

```bash
cmake -DSHELLER_ROOT=<src> -DBUILD_DIR=<build/windows-release> -DCONFIG=Release \
      -DSNAPSHOT=<a replayable snapshot> -P tests/install-consumer/run.cmake
```

The five things it proves, in order:

1. `cmake --install` succeeds and the prefix holds the delivery and **nothing else** -
   the driver fails if `include/` or `lib/cmake/` contains anything but `sheller`. That
   check caught a real defect on its first run: googletest ships install rules, so a
   prefix built with tests on filled up with 63 gtest/gmock headers, four libraries and
   a competing `GTestConfig.cmake`. Fixed with `set(INSTALL_GTEST OFF)` in
   `tests/CMakeLists.txt`.
2. the installed header set equals the source tree's, name for name (16), and the CI
   third-party-include grep re-run against the installed copy finds nothing;
3. the package's ABI literal matches the configuration installed
   (`shellerAbiConfig.cmake`), and the exported target interface carries no
   `SHELLER_LIB_ABI_DEBUG` at all - the value comes from the literal, which is the whole
   point of the arrangement;
4. the consumer configures, builds and **runs** from the prefix, and the shipped CLI
   runs out of `<prefix>/bin` with no environment variable set (guarded: the driver
   refuses to run that check if `LD_LIBRARY_PATH` is set in the calling environment,
   because then it would prove nothing about the install rpath). On Windows the
   consumer's own executable is the only file copied into `bin/`, so a successful run is
   the installed `unicorn.dll`/`Zydis.dll` carrying it - the contract
   `include/sheller/export.h` states and the install has to honour;
5. the static core stays out of the consumer: the **link line** is read out of the
   generated build system (`link.txt` on Ninja, `<AdditionalDependencies>` in the
   `.vcxproj`) and none of `sheller_api`/`sheller_engine`/`sheller_capture`/
   `sheller_unpack`/`sheller_cli_render` may appear; and the built executable is
   symbol-censused for internal names. On Linux that census is load-bearing, and it
   counts **defined** symbols only (`nm -C` classes `T D B R t d b r`): a weak `W`
   line naming `sheller::engine::` inside the consumer's own binary is a
   public-header instantiation, not a second copy of the core - `AnalysisOptions`
   holds an `engine::SyscallRunOptions` member (`include/sheller/analysis.h`), so
   inline thunks from the public headers land in the consumer's translation unit;
   the fact type is internal (`src/engine/behavior_fact.h`) and cannot contribute.
   Measured in this tree: the consumer's Debug executable has 1137 symbol lines,
   2 weak `sheller::engine::` lines and **0** defined internal names, while a
   binary that really links and calls the core carries those names as defined
   symbols (`iat_repair_test`: 2044 defined hits, `log_state` 4, `set_sink_impl` 1;
   `engine_diag_test`: 7 `t`).
   That control is no longer a one-off measurement: the driver now runs the identical
   regex against an in-tree core-linked test binary from the same build tree and
   **fails the leg** when it reads zero defined internal names there, because a census
   that has gone blind prints the same clean line as a census with nothing to find. Its
   live reading on the current build is 2040 defined hits in `iat_repair_test`; the
   number tracks the build (it was 2035 when the narrowing was being decided), so what
   the control asserts is *non-zero*, not a fixed count. With no such binary in the tree
   (tests switched off) the step says `NOT RUN` and the consumer result is recorded as
   unverified, not as evidence. Both branches were made to happen rather than reasoned
   about: breaking the defined-class list in the copy the driver runs makes the consumer
   read clean *and* the control fail the leg naming the blindness, and pointing the
   candidate list at binaries that do not exist prints `NOT RUN` while the leg still
   exits zero. The Release run that first
   established this check (107 lines, no hits) agrees: `-O3` does not emit those trivial
   thunks out of line. On Windows it is **not**: `dumpbin /symbols` on a Release
   executable without debug info returns 16 lines, so the script prints
   that caveat itself and leans on the link line plus `dumpbin /imports` (the product
   names the consumer imports out of `sheller.dll`), which is what "no second copy of
   the core" looks like on a toolchain that put the archive on the link line and
   extracted nothing from it. It is the same invariant the in-tree link-route rule
   protects, checked where a host actually meets it - and "it built" is not the
   evidence for it.

The mismatching-configuration case is checked too: against a Release prefix, the same
consumer project built in Debug **must** fail to compile, and the driver requires the
diagnostic to contain the mismatch wording from `export.h` rather than just a non-zero
exit. Off Windows the driver prints NOT APPLICABLE and records it as a coverage gap -
the debug/release comparison is ringed in `#if defined(_WIN32)` because
`_ITERATOR_DEBUG_LEVEL` is an MSVC thing.

## Test executables - Windows-only e2e

| target | ctest name | what it covers |
|---|---|---|
| `cli_run_test` | `cli_run` | `sheller run` over the facade: `--from-snapshot` replays a snapshot with the library's default statistics, and the same file on the bare default route is a capture-class refusal naming the snapshot magic - non-zero exit, the refusal on standard error with nothing of it echoed on standard output (the two streams are captured separately for that case), no run statistics line, and the report the failure path still writes carrying the four-key empty `events` object - sample pass-through, per-number `--reject` overrides, `--guest-stdout` switch, default zero intermediate files, and `--log-level` on both sides of its contract - with a trace switch set in the environment the record is absent at the default threshold and present at `debug` (the two runs differ only by the flag, and both assert the run's own summary so "no trace" cannot mean "no run"), while an unknown level name is a usage error rather than a silently ignored option, and `--event-level` on both sides of its contract: `full` lights the ledger and merges it into the same report (instruction-level entries present, the default entries' `(type,seq)` list identical to semantic, the `loss` key rendered as counters) while writing no `.timeline.json`/`.calls.json`/`.stubcalls.json` sibling, the default is byte-identical to an explicit `semantic` run, carries the `null` loss pair and no instruction-level entry, `counts` writes the compact report (`detail:[]`, the `counts-only` summary), a deterministic budget stop exits 0 with the statistics and the `instruction budget exhausted` note while an unhandled crash still exits non-zero with its report, a level name outside the set is a usage error, and the retired `--timeline` spelling is an unknown argument; `--stop xfer=<n>` on the captured xfer snapshot stops with `terminated=0`/`syscalls=0` and a dump, a miss prints the hint while keeping the normal exit, `xfer=0` leaves the run alone, an explicit 1M budget wins over a packed OEP transfer (miss hint naming the budget) while the untouched defaults - 3M instructions over a 10s wall clock - reach that transfer with the stop line, the 200ms wall clock wins over a spin sample with the wall clock named in the hint, and a portable crafted snapshot proves the mid-leg wall-clock veto through the CLI; the `--stop` family: typo'd goal and non-integer `xfer=` are usage errors naming the grammar, two `--stop`s mutex-error, the help text names all three goals and carries no `--xfer` anywhere, the retired `--xfer` spelling is an unknown argument, `xfer=0` is explicit off with the same close-out a no-goal run has, the esp scenarios run on the portable crafted fixtures (hit with dump/report and exactly one `stack-restore`, `esp+xfer` arming to the xfer stop line with the endpoint in the report, the anti-debug read and the `pop rsp` stack pivot stopping nothing and emitting no `stack-restore`, the no-push and relocated-stack silent misses printing the bare hint, the passive event firing with no goal at all, the missed goal adding no stream bytes, and the esp mid-leg wall-clock veto) |
| `capture_test` | `capture` | full capture pipeline over a real sample (TLS callback) |
| `syscall_e2e_test` | `syscall_e2e` | hello/deny/spin samples through the syscall run path, plus the `SyscallRunGuestSink` cases over a fourth sample (`capture_syscall_multiwrite`, `entry_multi`: three `NtWriteFile` calls of different lengths before terminating - one write cannot show that only the throwing one was lost): a host sink that throws during a run loses exactly that write and the run still converges (`terminated=1`, `exit=0x1234`, `syscalls=4`), the writes after it still reach the same sink in guest order (`kept` is `onethree` against the reference run's `onetwothree`), the event ledger's TLV and JSON dumps of the throwing run are byte-identical to the non-throwing run and the statistics match, the host's stdout and stderr stay at zero bytes - with a companion case that makes that last assertion mean something by having the sink *print* and proving the capture fixture sees it |
| `exception_e2e_test` | `exception_e2e` | SEH frame walk, VEH, `__finally`-on-unwind, C++ EH (`__CxxFrameHandler4`, optimized and debug corpus shapes), hardware AV into C++ handlers, fastfail crash fallback, cross-section xfer, the alloc-jump corpus (runtime-region xfer sentinels, reader-fact guard, MBI carve answers), the unknown-image corpus (synthesized `unknown-image-<base>` module: real-index xfer landings, absolute `module!.text` renders, MBI region semantics + MII module extent, in-image fault resolving identically with and without a synthesis-able chain in both dispatch modes); the dump pipeline (normal-exit / budget-exhaustion / timeout exports, replay determinism); and the captured xfer-stop cases (first ordinal stops before text2 with a dump and matching block/bookkeeping counts, second ordinal stops before the terminate thunk) |
| `behavior_e2e_test` | `behavior_e2e` | the production `EventStream` (one cursor, fact forwarding, judgment drain) over the read-mode sample (PEB walk, BeingDebugged probe, `call $+5`/`pop` GetPC, unregistered syscall), the VEH sample, and the burn-loop delay corpus (nested counter loop terminates only when `loop-skip` fires and the outer re-entries hit the cached exit); asserts the emitted judgment sequence, the counts/ledger binding and byte-identical reports |
| `wrapper_pe_e2e_test` | `wrapper_pe_e2e` | bare blob rides the standard capture route and executes in the emulator; also holds `WrapperConcurrency.DistinctWrapperNamesUnderContention`, eight threads wrapping the same blob at once - every capture must succeed and a poller must catch at least two distinct `sheller_wrap_*` names in flight, which is what keeps "all succeeded" from being the only evidence (the same case is red twice in five runs when the name generator is process-wide static state) |
| `loader_imports_test` | `loader_imports` | IAT resolution units against the host's real system DLLs (forwarder chains) |
| `loader_imports_e2e_test` | `loader_imports_e2e` | full loader import chain over a real PE |
| `loader_byhash_e2e_test` | `loader_byhash` | by-hash shellcode: Ldr triple-chain walk, MZ checks, module count |
| `loader_byhash_x86_e2e_test` | `loader_byhash_x86_e2e` | x86 PEB32/Ldr chain walk, exit via raw int 2e |
| `loader_imports_x86_e2e_test` | `loader_imports_x86_e2e` | x86 stdcall IAT calls through the interception layer (SysWOW64 modules) |
| `seh_x86_smoke_test` | `seh_x86_smoke` | x86 raw FS:[0] SEH registration, AV, handler continues execution |
| `capture_x86_e2e_test` | `capture_x86` | x86 snapshot route: capture a real WOW64 process, rebuild and run in 32-bit mode |
| `thread_e2e_test` | `thread_e2e` | cooperative scheduler: thread create, cross-thread handoff, blocking wait, exit |
| `thread_x86_smoke_test` | `thread_x86_smoke` | same scheduler semantics via int 2e in 32-bit |
| `shim_pf_test` | `shim_pf` | AVX shim memory-failure semantics: VEX.256 load/store on unmapped memory synthesizes AV, never #UD |
| `iat_repair_test` | `iat_repair` | IAT mapper/audit units, repair pipeline over crafted snapshots, packed.exe repair acceptance |

## Local Linux verification gates (`tools/`)

CI is the published gate; these two scripts are the local pre-push one. They are
tracked in `tools/` because `build/` is ignored as a whole directory and git
cannot re-include one file beneath it, so a gate kept there is a single-machine
file whose repair cannot be committed or reviewed. That is how the previous one
died without anyone noticing (see the mirror bullet).

| script | preset | shape |
|---|---|---|
| `tools/run_linux_suite.sh` | `linux-debug` | lock, mount, mirror, chown, configure, build, the whole registered set (49 tests), then the installed-consumer leg |
| `tools/run_linux_sanitizer.sh` | `linux-sanitizer` | the same stages, no install leg, and the CI's four-name `-E` exclusion (47 of 49) |

Both drive WSL as root, because they mount the dev drive and chown the mirror
target. Copy-paste invocation:

```bash
wsl -u root -e bash -c "mount | grep -q devdrive || mount -t drvfs 'C:\devdrv' /mnt/devdrive; bash /mnt/devdrive/src/sheller/tools/run_linux_suite.sh"
wsl -u root -e bash -c "mount | grep -q devdrive || mount -t drvfs 'C:\devdrv' /mnt/devdrive; bash /mnt/devdrive/src/sheller/tools/run_linux_sanitizer.sh"
```

Four properties the two scripts exist to keep:

- **Each stage decides its own outcome.** `run_step <stage> <log> <command...>`;
  on failure it prints the log tail, names the stage (`gate: configure FAILED`)
  and exits 1, so no trailing `tail` can be the last word any more. An empty test
  set fails twice over: the gate counts `ctest -N` before running it (the
  `test-set-count` line), and `ctest` is given `--no-tests=error`. Both guards
  have been seen to fire, separately, under injected faults - see "Proving a gate
  can still fail" below.
- **One run at a time.** The first stage takes `flock -n /tmp/sheller-gate.lock` and
  holds it through the fd until the script exits, because everything downstream is
  single-slot: the mirror target, its build tree, the install-consumer prefix the driver
  wipes at its own start (`tests/install-consumer/run.cmake:60`), and the fixed `/tmp`
  stage logs. Without it, an injection round interleaved with a leg produces the worst
  possible artifact - the injected mirror has no `cmake/`, so the leg dies naming
  `configure` and looks exactly like the 19324d3 defect this batch was written to end.
  Measured rather than assumed (probe: `build/linux-gate-durability/probe_flock2.sh`): a
  second script is refused at its own lock stage with exit 1, and the lock is free again
  once the holder exits, so there is no stale-lock state to clean - which is what made
  this worth adding instead of documenting. The lock file is never unlinked: flock locks
  an open file description, so deleting it lets a new run open a different inode and
  proceed alongside a holder that still locks the old one. One gap is left on purpose:
  `build/wsl_linux.sh` is the developer loop and is not tracked, so it runs outside the
  lock and cannot be made to share it by a committable change.
- **The mirror is exclusion-based, anchored at the archive root.**
  `tar -C <src> --exclude=./build ... -cf - .` instead of an enumerated member list, so
  a top-level directory added to the repository reaches the gate without anybody editing
  the gate. 19324d3 added `cmake/` - the package template that
  `configure_package_config_file` reads - and the enumerated list did not carry it:
  configure died in both scripts while each still reported 0. The patterns are anchored
  because the archive is made from `.` and its member names therefore start with `./`:
  measured on the pinned GNU tar, `--exclude=build` drops `./src/build` along with
  `./build`, while `--exclude=./build` leaves the nested directory alone - that is the
  starvation this closes, and today the tree holds exactly one nested hit of an excluded
  name (`tools/__pycache__`), which stays excluded on purpose because `.git` and
  `__pycache__` are deliberately left unanchored. The mirror also clears every previous
  top-level entry before extracting and keeps only `build/` - generated, and the home of
  the installed vcpkg tree at `build/<preset>/vcpkg_installed` - so an incremental
  configure still costs 14 s while a stray mirror-root installed tree, possibly built for
  another platform, cannot survive into the next run. `pipefail` covers the making side
  of the `tar | tar`, so a truncated mirror cannot be inherited by configure.
- **The suite leg installs and consumes.** After ctest, the gate drives
  `tests/install-consumer/run.cmake`, which installs `build/linux-debug` to a
  throwaway prefix and runs the consumer against that prefix alone
  (`-DCONFIG=Debug`; replay input `build/seh.snap` from the mounted drive - a
  real capture, local-only by policy, and the leg names the path and fails if it
  cannot read one). This is the installed delivery face measured in a Debug
  configuration for the first time: 25 files installed, the package ABI literal
  `SHELLER_LIB_ABI_DEBUG_LITERAL=1`, the consumer configured, built and ran
  (`instrumented=1`, 9 semantic events, 0 OEP candidates, 55 events through both
  `analyze` entries), and the `_GLIBCXX_DEBUG` mismatch case failed to compile
  naming `_GLIBCXX_DEBUG` as the check promises. The prefix and the work tree are
  removed by the script's exit trap, so the next run starts from nothing.

### Proving a gate can still fail

`tools/gate_fault_inject.py` injects the historical fault shapes into *copies* of
the two scripts - never into the tracked files, and never into the working tree
the gate mirrors - then asserts each run exits non-zero, names the failing stage,
and never prints `PASSED`:

```bash
python tools/gate_fault_inject.py                  # nine cases; c and c2 are the slow ones
python tools/gate_fault_inject.py --check-anchors  # the same five, injected in memory
```

`--check-anchors` exists because the cases are anchored to the gate scripts' own text: a
rewrite that moved a stage would otherwise let a case run an *un-injected* script and
report a green gate nobody tested. The check builds every variant in memory, requires
each anchor to be found, requires the result to differ from the tracked text, and
requires the injected marker to be present - so a stale anchor fails there rather than
reading as a pass later. Measured both ways: it reports five ok against the shipped
scripts, and it goes red for a moved anchor ("anchor not found") as well as for an edit
that replaces nothing ("the injection changed nothing"). It runs no WSL and writes
nothing outside its own stdout, so it is safe while a leg is in flight.

| case | injected fault | expected stage |
|---|---|---|
| `a_missing_cmake` | the mirror excludes `cmake/` (the 19324d3 shape) | `configure` |
| `b_broken_cmake` | a doctored `CMakeLists.txt` inside the mirror copy | `configure` |
| `c_empty_ctest` | both `--test-dir` arguments point at an empty directory | `test` |
| `c2_empty_ctest_only` | only the `ctest` run is redirected, so `--no-tests=error` is the guard that has to fire | `test` |
| `d_mount_fail` | the share the mount stage is told to mount does not exist | `mount` |
| `e_chown_fail` | the chown stage hands the mirror to a user that does not exist | `chown` |
| `f_maker_tar_fail` | the making side of the mirror pipe gets a missing member | `mirror` |
| `g_lock_held` | nothing injected: another process holds the lock, the gate must refuse | `lock` |
| `s_missing_cmake` | case (a) against the sanitizer script | `configure` |

`d`, `e` and `f` are the three stages that run before anything is built. They used to be
carried by structure alone - "the mount stage fails loud because `run_step` judges it" -
which is exactly the kind of claim this section refuses to leave unmeasured, so each now
has a fault that has to be seen firing: `gate: mount FAILED`, `gate: chown FAILED`,
`gate: mirror FAILED`, each exit 1. `f` is the one that answers root cause three
directly: without `pipefail` the making side's `Cannot stat` is swallowed and the
extractor happily publishes a truncated mirror for configure to choke on.

The generated copies go to `C:/devdrv/tmp/linux-gate-fault-inject` (WSL:
`/mnt/devdrive/tmp/linux-gate-fault-inject`) and are removed when the round ends, along
with the empty directory `c` and `c2` create in WSL. What is deliberately *not* repaired
is the mirror target: it keeps the shape of the last injected run until the next gate
run, whose own mirror stage clears and re-mirrors it - measured, a suite leg coming back
green after a whole injection round is what proves that stage does the work, so the
harness leaves the evidence rather than papering over it. An injected run shares the
gate's mirror target, so run it while no leg is in flight. `c2` is in
the set because "two guards" is a claim that needs both halves proven: `c` lights
the counting guard, `c2` the ctest-level one. The harness reads the gate's exit
status from a marker printed inside the WSL command line - measured on this
machine, `wsl.exe` returns 0 for a gate that returned 1, which would reproduce
the exact fake green this section is about.

### Coupled to this machine

`/home/user1/sheller-linux`, the `user1` account, `/home/user1/vcpkg`, `gcc-13`
and the drvfs mount point are written into the scripts: the gates make one
machine's environment explicit instead of implicit. Rebuilding it is recorded in
the local handoff note (`.docs/HANDOFF.md`, untracked by the same ignore rule
that hid the old scripts), not duplicated here.

Measured 2026-10-22 against one mirror (16 MB of source after the excludes):
`linux-debug` 48/48 (100.08 s of tests) plus the install leg, `linux-sanitizer`
46/46 (135.67 s), both scripts exit 0. The same day's Windows runs: Release
63/63, Debug 62/63 (the pre-existing `event_baseline` Debug golden above). The sanitizer leg is the retro verification of
19324d3 on that preset - it had not been run since the commit landed.

## Samples and fixtures

- `capture_syscall_sample.asm` - ml64 direct-syscall sample, five entries:
  hello (write + terminate), default-deny probe, budget spinner, multi-write,
  and the burn-loop delay corpus (outer 16 x inner 100000h counter loop).
- `capture_behavior_sample.asm` - ml64 read-mode sample for the behavior
  layer: PEB walk, BeingDebugged probe, `call $+5` / `pop` GetPC,
  unregistered direct syscall.
- `capture_seh_sample.c` + `capture_seh_thunks.asm` - MSVC C sample with two
  nested `__try` frames (unwind tables required); the thunks file also
  provides the fastfail entry.
- `capture_seh_veh_sample.c` - vector handler registration and dispatch.
- `capture_seh_finally_sample.c` - `__finally` termination handlers run on
  the unwind second pass.
- `capture_cpp_eh_sample.cpp` / `capture_cpp_eh_av_sample.cpp` - C++ EH
  corpus (`/MD` so the real vcruntime guest code runs; the optimization
  shape follows the build config), plus the hardware-AV-into-C++ variant.
- `capture_xfer_sample.c` + `capture_xfer_thunks.asm` - cross-section
  transfer sample: entry (default .text) calls a function in an explicitly
  declared second executable section (`text2`); the thunks file also
  serves the alloc-jump sample below.
- `capture_xfer_delay_sample.c` - the same transfer behind a guest-visible
  counter loop; `unpack` with a 1 ms wall clock crosses the timeout inside the
  leg the transfer ends, proving the xfer stop's veto and still landing the
  image.
- `capture_allocjump_sample.c` - alloc-jump corpus: VirtualAlloc private
  data memory, write a payload, protect it executable, jump in; the
  payload reads TEB/PEB from inside the allocation, flips its own page
  same-class, and both allocations repeat the jump (xfer sentinels,
  reader-fact guard, MBI carve answers).
- `capture_unknownjump_sample.c` - unknown-image corpus (the thunks file
  provides its terminate thunk): calls into a hand-mapped image the test
  crafts into the captured snapshot as contiguous MEM_IMAGE regions (or
  MEM_PRIVATE, for the no-synthesis twin), checks the MBI/MII answers,
  then faults inside the image.
- `capture_sample.c` - real compiler-built PE with a TLS callback.
- `corpus/*.asm` - NASM blobs (built at test time): `byhash_shell` (x64/x86
  Ldr walks), `import_blob_x86`, `thread_blob` (x64/x86), `seh_x86_smoke`.
- `synth_modules/manifest/` - frozen JSON manifests; the deterministic
  synthetic system-module PEs are generated into the build dir at configure
  time (`tools/gen_synth_modules.py`, python3 stdlib only).
- `minimal_pe.h` - hand-crafted PE bytes for the portable parser tests.
- `snapshot_fixture.h` - the crafted in-memory snapshot serializer shared by the
  suites that drive the engine entry directly (`analysis_facade_test`,
  `engine_trace_test`, `concurrency_test`, `cli_run_test`): one RWX image page
  carrying guest code, a stack page and a TEB page, plus the terminate / single-write
  / two-write / spin code sequences. The two-section variant adds a minimal PE32+
  header with `.text` and `text2`, a counter loop that stores to the stack (so the
  burn-loop probe cannot fast-forward it), and one cross-section jump - the portable
  xfer-stop and mid-leg wall-clock fixture. It exists so "the same fixture" means the
  same bytes rather than a second approximation per file.
- `test_temp.hpp` - per-process unique temp paths, so concurrent ctest jobs and a
  stale run's leftovers cannot collide on fixed names.
- `host_stream_capture.h` - moves descriptors 1 and 2 onto temp files for the length of
  a case and reads back what landed there, for the assertions that are about the host's
  own streams ("the library wrote nothing", "the guest's bytes went to the sink and not
  to stdout"). It restores before the text is read, so a gtest failure printed inside
  the window cannot be counted as a library write, and it fails the case rather than
  skipping it when the redirection cannot be installed - a no-op capture would answer a
  "zero bytes" claim with an untouched stream. Shared by `analysis_facade_test` and
  `engine_trace_test`.

## Golden baselines (`goldens/`)

- `snapshot_v1_synthetic.snap` - v1 snapshot layout sentinel (regenerate via
  `SHELLER_REGEN_SNAPSHOT_GOLDEN`).
- `contract_events.golden` - TLV wire layout sentinel
  (`SHELLER_REGEN_CONTRACT_GOLDEN`).
- `event_stream_{hello,deny,spin}.{debug,release}.xxh64` - relocation-normalized
  event-stream digests for the deterministic-termination corpus, per build
  config (the digest pins the sample's linked block sequence, which differs
  between /Od and /O2 links). Regenerate per tree via
  `SHELLER_REGEN_EVENT_BASELINE`.

`data/admission-plans/*.plan` is the runner-admission counterpart: one file per
differential-corpus sample (`packed`, `kernel32_by_name`, `user32_by_name`,
`ntdll_by_ordinal`, `kernelbase_by_name`), each a `# <arrival name>` header and
one `module<TAB>symbol<TAB>ordinal` row per plan import in generation order.
`admission_diff` compares the synthetic route's text against it on every
platform and the capture route's text on Windows. Regenerate with
`SHELLER_ADMISSION_PLAN_WRITE=1` when the corpus or the shared selection rule
changes; the files are ordinary check-in artifacts, not binary goldens.

## Corpus

`packed.exe` - UPX-packed x64 sample kept as the dump-engine and
unpack-acceptance corpus fixture: regenerable with UPX, not a real-world
sample. `packed.exe.unp` is its repaired ground truth (the `iat_repair` /
`unpack_cli` acceptance compares against it). Real family samples stay out
of the repository by policy.

## DLL corpus (dll-sample-support)

`tests/packed.dll` (UPX-packed x64 DLL) and `tests/packed.dll.unp` (the
`upx -d` reference) drive the DLL-input route: `capture` spawns a generated
load-stub runner and stores the sample bytes as the container's pending
module; `unpack` reproduces the reference entry point (0x13E4, the real
DllMain) with rebuilt imports. The source is `tests/packed_dll_sample.c`
(kernel32 + user32 imports, one export, DllMain/export print markers through
`kernel32!GetStdHandle`+`WriteFile` - the `--guest-stdout` path). Rebuild:
`vcvars64 && cl /nologo /W4 /O1 /MT /LD tests\packed_dll_sample.c user32.lib
/Fe:<tmp>\packed_orig.dll`, then `upx -o tests\packed.dll
<tmp>\packed_orig.dll` and `upx -d -o tests\packed.dll.unp
tests\packed.dll`. Re-test the anchors (packed entry, reference entry,
import/export directories) after any rebuild and update the acceptance
test. Suites: `dll_admission` (system-dependency admission + staged-runner
real-loader smoke), `dll_e2e` (capture → unpack acceptance, the xfer=1
stop face, and the cross-process report pin
`DllE2E.ReplayReportIsIdenticalAcrossProcesses`: one container, two
independent `run --from-snapshot --report` processes, byte-identical
reports - no wall clock, compared only after the deterministic
`terminated=1` stop), and `dll_capture_e2e` (the live-capture replay chain:
--guest-stdout marker, saved-snapshot round trip, esp miss closing the run,
plus the artifact-chain pin
`DllCaptureE2E.ReplayArtifactsAreIdenticalAcrossProcesses`: the resident
`det_helper` target serializes the complete raw event stream, the exit
dump and the repaired `.unp` per process, and the test byte-compares the
three groups across two helper processes over one container) - all
WIN32-gated. The admission algorithm those routes share is pinned from the
other side by `admission_diff` (see the portable table above): T1 compares the
capture route's plan with the synthetic route's plan, and T2 freezes both in
`tests/data/admission-plans/*.plan`, so a change that fixes one route and
forgets the other fails by name instead of silently splitting the corpus.
`dll_capture_e2e` stays excluded from shared CI runners: the
old runner-hardware crash past the OEP was steered by the captured world's
per-process entropy (the virtual-TSC answer leaked host stack into its high
bits through a narrow register write), which the captured-world-determinism
change fixed - the replay is now cross-process byte-identical on the
development machine - but the fixed trajectory itself has not been
exercised on shared runner hardware, so the suite waits there.

### Real-DLL directory corpus (real-dll-module-dir, env-gated)

`loader_directory_test` grows one opt-in test behind an environment variable -
it drives real Windows DLLs you supply locally and never runs in CI:

* `SHELLER_REALDLL_DIR` - a directory holding real x64 copies of
  `ntdll.dll`, `kernel32.dll` and `kernelbase.dll` plus the API Set map for
  the corpus ntdll (`apiset-map.bin`, generated from a reviewed text source
  with `tools/gen_apiset_map.py` and anchored to the corpus ntdll's
  whole-file xxhash64). That ntdll build must be registered in
  `tools/boundary_manifest/ntdll.x64.real.json` (the real-build manifest; the
  separate `ntdll.x64.json` binds the committed CI fixture, not your corpus).
  An unregistered build skips with a naming message rather than guessing;
  regenerate the seed (`tools/gen_boundary_seed.py`) when you register rows.

`RealDllCorpusStringCallExecutesRealCode` generates a sample that imports
`kernel32!lstrlenA` and `ntdll!NtTerminateProcess`, then proves the chain
end to end: the real kernel32 thunk jumps into the real kernelbase body
executing against guest memory, and the derived ntdll's stub terminates with
the string length as the exit code (16 = `strlen("sheller-real-dll")`).
The test skips when the variable is unset - nothing corpus-shaped lands in
the repository.

Stop-target note for the packed DLL corpus above: the UPX DllMain stub opens
with argument-shadow stores and a reason branch before its register saves,
so the esp scan finds no contiguous push sequence at the re-armed entry and
`--stop esp` / `--stop esp+xfer` are a documented silent miss (the run
closes normally, unpack completes). `--stop xfer=1` is the usable stop
face - the stub's post-restore jump to the unpacked entry is the first
counted transfer (the OEP dump stop); pinned by
`DllE2E.Xfer1StopsAtTheOepTransfer`, with the miss face pinned by
`DllCaptureE2E.EspStopMissClosesTheRunNormally`.
