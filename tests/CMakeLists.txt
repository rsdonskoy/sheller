set(gtest_force_shared_crt ON)
# googletest ships install rules of its own, and MakeAvailable brings them in as
# an ordinary subdirectory: without this, `cmake --install` of a test-enabled
# build puts gtest/gmock headers, libraries and a GTestConfig.cmake into the
# consumer's prefix. The delivery surface is the library, the CLI and their
# dependencies (specs/delivery-surface), and a test framework a host never asked
# for is not part of it.
set(INSTALL_GTEST OFF)
FetchContent_MakeAvailable(googletest)

# The C++ EH corpus carries its per-config optimization shape on the sample
# targets (see the capture_cpp_eh_* targets below); the Debug-built-in /RTC1
# is incompatible with the release pin (/O2, D8016) and no test here relies
# on runtime checks, so strip it for this directory - the two C++ EH corpus
# targets re-add it explicitly for their Debug shape.
string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

add_executable(cli_version_test cli_version_test.cpp)
target_compile_definitions(cli_version_test PRIVATE
  SHELLER_CLI_FILE_NAME="${SHELLER_CLI_FILE_NAME}")
target_link_libraries(cli_version_test PRIVATE GTest::gtest_main)
sheller_apply_common(cli_version_test)
add_dependencies(cli_version_test sheller)

add_test(NAME cli_version COMMAND cli_version_test)
set_tests_properties(cli_version PROPERTIES
  WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

# Log facade: merged sink install, level threshold, silence - portable by
# design (pure standard library); the state TU lives in the engine. The suite
# drives the internal setter name (the public sheller::log::set_sink is defined
# only by the shared interface library), so it reads the engine's detail header.
add_executable(log_test log_test.cpp)
target_include_directories(log_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(log_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(log_test)

add_test(NAME log COMMAND log_test)

# Diagnostic helper: the two conditions that gate a trace record, measured with a
# formatter that counts its own invocations (see the TU header). Runs with no trace
# environment set - which is the point: the switch-off half of the contract is what a
# normal process pays. The switch-on half is tests/engine_trace_test.cpp.
add_executable(engine_diag_test engine_diag_test.cpp)
target_include_directories(engine_diag_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(engine_diag_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(engine_diag_test)

add_test(NAME engine_diag COMMAND engine_diag_test)

# Public-header self-containment gates: an empty TU whose sole include is one
# public header must compile (see the TU comment for the red-green usage -
# the CI third-party-include grep cannot catch a missing standard header).
add_executable(self_contained_syscallrun self_contained_syscallrun.cpp)
target_include_directories(self_contained_syscallrun PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include")
sheller_apply_common(self_contained_syscallrun)

add_test(NAME self_contained_syscallrun COMMAND self_contained_syscallrun)

# Analysis facade: direct sheller_api coverage - routing, failure kinds,
# semantic/timeline tiers, host subscription, guest-output discard. Portable
# routes run everywhere; capture-route faces are Windows-gated in the file.
# It stays on the static core by design: it builds snapshots through
# snapshot::Writer, which is not part of the export face (shared_api_test is
# the DLL-side counterpart). The facade entries are called under their
# internal names, declared in src/api/wiring.h.
add_executable(analysis_facade_test analysis_facade_test.cpp)
target_include_directories(analysis_facade_test PRIVATE
  "${CMAKE_BINARY_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/api"
  # The throwing-sink case installs a sink through the internal setter, the same
  # route log_test takes: the product name is defined only in the shared library.
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_compile_definitions(analysis_facade_test PRIVATE
  SHELLER_FACADE_GOLDEN="${CMAKE_CURRENT_SOURCE_DIR}/goldens/snapshot_v1_synthetic.snap"
  SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
  SYNTH_MODULE_DIR="${CMAKE_BINARY_DIR}/synth_modules")
target_link_libraries(analysis_facade_test
  PRIVATE GTest::gtest_main sheller_api sheller_capture)
sheller_apply_common(analysis_facade_test)
add_dependencies(analysis_facade_test synth_modules container_size_bound)

add_test(NAME analysis_facade COMMAND analysis_facade_test)

# Full-container copy regression: static linkage makes operator new interposition
# available on Windows as well as POSIX without changing the shipped library.
add_executable(analysis_memory_test analysis_memory_test.cpp)
target_include_directories(analysis_memory_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/api"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(analysis_memory_test PRIVATE GTest::gtest_main sheller_api)
sheller_apply_common(analysis_memory_test)
add_test(NAME analysis_memory COMMAND analysis_memory_test)


add_executable(self_contained_analysis self_contained_analysis.cpp)
target_include_directories(self_contained_analysis PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include")
sheller_apply_common(self_contained_analysis)

add_test(NAME self_contained_analysis COMMAND self_contained_analysis)

# IAT repair: mapper/audit unit tests over crafted export tables, the full
# pipeline over a crafted snapshot + dump directory, and - on a Windows
# capture host - the packed.exe acceptance. The pipeline is engine-native
# and portable by design; only the packed-corpus acceptance needs the
# Windows capture route, so its sample path is the one WIN32-conditioned
# definition (the test guards it with #ifndef).
add_executable(iat_repair_test iat_repair_test.cpp)
target_include_directories(iat_repair_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/unpack"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include")
if(WIN32)
  target_compile_definitions(iat_repair_test PRIVATE
    SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe")
endif()
target_link_libraries(iat_repair_test
  PRIVATE GTest::gtest_main
  PRIVATE sheller_unpack
  PRIVATE sheller_engine
  PRIVATE sheller_capture)
sheller_apply_common(iat_repair_test)
add_dependencies(iat_repair_test sheller)

add_test(NAME iat_repair COMMAND iat_repair_test)
set_tests_properties(iat_repair PROPERTIES
  WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

# Portability gate for the test file itself: no Windows or unicorn specifics
# may creep back in (same boundary discipline as the CI include gates).
add_test(NAME iat_repair_portability
  COMMAND ${CMAKE_COMMAND}
    -DGATE_FILE=${CMAKE_CURRENT_SOURCE_DIR}/iat_repair_test.cpp
    -P ${CMAKE_CURRENT_SOURCE_DIR}/iat_repair_portability_gate.cmake)

# Unpack CLI: the one-shot subcommand over the packed corpus sample, portable
# like the pipeline it drives - Windows captures, other hosts take the loader
# route against the generated synthetic modules (hence the synth_modules
# dependency: the CLI fails without them). Both routes land the .unp, the
# three-state repair report and the behavior report - at full event level that
# one report also carries the merged event stream; the verdict differs by route
# fidelity and the test asserts per platform.
add_executable(unpack_cli_test unpack_cli_test.cpp)
target_include_directories(unpack_cli_test PRIVATE "${CMAKE_BINARY_DIR}")
target_compile_definitions(unpack_cli_test PRIVATE
  SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
  SHELLER_CLI_FILE_NAME="${SHELLER_CLI_FILE_NAME}"
  SYNTH_MODULE_DIR="${CMAKE_BINARY_DIR}/synth_modules")
target_link_libraries(unpack_cli_test PRIVATE GTest::gtest_main)
sheller_apply_common(unpack_cli_test)
add_dependencies(unpack_cli_test sheller synth_modules container_size_bound)

add_test(NAME unpack_cli COMMAND unpack_cli_test)
set_tests_properties(unpack_cli PROPERTIES
  WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

# Shared interface library smoke: links sheller_shared and nothing else from
# the core, includes public headers only - every name it calls crossed a library
# boundary. The CLI subprocess cases above prove the library loads; this one
# proves the six exports resolve and answer (the symbol-visibility face a
# subprocess cannot see). Windows chains capture::run into analyze over the
# hello sample; other hosts take the loader route, which needs the generated
# synthetic modules (without them it fails as a capture-class error - a shape
# that reads exactly like a platform boundary).
add_executable(shared_api_test shared_api_test.cpp)
target_compile_definitions(shared_api_test PRIVATE
  SHELLER_FACADE_GOLDEN="${CMAKE_CURRENT_SOURCE_DIR}/goldens/snapshot_v1_synthetic.snap"
  SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
  SYNTH_MODULE_DIR="${CMAKE_BINARY_DIR}/synth_modules")
target_link_libraries(shared_api_test PRIVATE GTest::gtest_main sheller_shared)
sheller_apply_common(shared_api_test)
add_dependencies(shared_api_test synth_modules)

add_test(NAME shared_api COMMAND shared_api_test)
set_tests_properties(shared_api PROPERTIES
  WORKING_DIRECTORY "$<TARGET_FILE_DIR:shared_api_test>")

# Containment-helper units: the export layer's guard and its message rendering.
# Header-only and free of engine types, so this target links no sheller library
# at all - which is also the proof that guard.h stands on its own.
add_executable(shared_guard_test shared_guard_test.cpp)
target_link_libraries(shared_guard_test PRIVATE GTest::gtest_main)
sheller_apply_common(shared_guard_test)
add_test(NAME shared_guard COMMAND shared_guard_test)

# Allocation-failure injection at the export face. Linux only, and not by
# convenience: the test replaces global operator new in the executable and the
# library has to reach it through its undefined dynamic symbol. The POSIX
# runtime does interpose that way; the Windows CRT does not do it across a DLL
# boundary, so the same shape cannot be built there (the gap is recorded in
# tests/export_guard_injection_test.cpp's header). The target links sheller_shared and nothing from
# the static core - it is the second shared-route binary, after shared_api_test.
if(NOT WIN32)
  add_executable(export_guard_injection_test export_guard_injection_test.cpp)
  target_compile_definitions(export_guard_injection_test PRIVATE
    SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
    SYNTH_MODULE_DIR="${CMAKE_BINARY_DIR}/synth_modules")
  target_link_libraries(export_guard_injection_test PRIVATE GTest::gtest_main sheller_shared)
  sheller_apply_common(export_guard_injection_test)
  add_dependencies(export_guard_injection_test sheller_shared synth_modules)

  add_test(NAME export_guard_injection COMMAND export_guard_injection_test)
  set_tests_properties(export_guard_injection PROPERTIES
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:export_guard_injection_test>")
endif()

# Export-surface gate: the built library's dynamic face against the checked-in
# list for this platform, compared symbol by symbol (a count-only check would
# pass while the wrong names shipped). Skipped on sanitizer builds - there the
# .so carries detector-runtime symbols no list should pin.
find_program(SHELLER_NM_EXECUTABLE nm)
find_program(SHELLER_CXXFILT_EXECUTABLE c++filt)
if(WIN32)
  # The Visual Studio generator records no CMAKE_CXX_COMPILER path; link.exe,
  # dumpbin.exe and undname.exe share a tool directory.
  get_filename_component(SHELLER_MSVC_TOOL_DIR "${CMAKE_LINKER}" DIRECTORY)
  set(SHELLER_EXPORT_LIST "${CMAKE_CURRENT_SOURCE_DIR}/expected_symbols.windows.txt")
  set(SHELLER_EXPORT_GATE_ARGS -DMSVC_TOOL_DIR=${SHELLER_MSVC_TOOL_DIR})
else()
  set(SHELLER_EXPORT_LIST "${CMAKE_CURRENT_SOURCE_DIR}/expected_symbols.linux.txt")
  set(SHELLER_EXPORT_GATE_ARGS
    -DNM_EXECUTABLE=${SHELLER_NM_EXECUTABLE}
    -DCXXFILT_EXECUTABLE=${SHELLER_CXXFILT_EXECUTABLE})
endif()
if(NOT CMAKE_CXX_FLAGS MATCHES "fsanitize")
  add_test(NAME export_surface
    COMMAND ${CMAKE_COMMAND}
      -DGATE_LIBRARY=$<TARGET_FILE:sheller_shared>
      -DEXPECTED_LIST=${SHELLER_EXPORT_LIST}
      -DGATE_TMP_DIR=${CMAKE_CURRENT_BINARY_DIR}
      ${SHELLER_EXPORT_GATE_ARGS}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/export_surface_gate.cmake)
endif()

# ---------------------------------------------------------------- engine gates
# Source-scanning gates over the engine's translation units (no-throw, host
# standard streams, throwing standard-library API, .at() ratchet). They share one
# file set, derived here from the build system rather than from a directory glob:
# the engine is not a directory - it spans src/engine, src/syscalls, src/behavior,
# src/loader, src/runtime/craft and src/unpack. Three targets make up the set:
# sheller_engine and sheller_capture are the two that once carried the
# no-exceptions compile flag, and sheller_unpack is the IAT repair pipeline, whose
# export mapping is engine-native (no peconv) and whose objects reach the shared
# library through the same engine link - so it is inside the discipline it links
# against, not next to it unswept. Listing the targets' SOURCES is the only way
# the set cannot silently drift from what actually compiles.
#
# The set is the UNION over both platforms: sheller_capture compiles
# capture/capture.cpp on Windows and capture/capture_stub.cpp elsewhere, and a
# gate that scanned only the host it runs on would leave the other host's file
# unswept forever. Both names are therefore appended by hand - the one place the
# list is not derived - and the gate hard-fails on any path that stops existing,
# so the hand-written pair cannot rot either.
#
# Turn a target's recorded sources into project-relative paths. A relative entry
# is relative to the directory target_sources() was called from, which is the
# target's own source directory (an absolute entry is what CMake records when the
# call comes from a different directory) - resolving against either of the two
# wrong bases silently drops files from the scan, so the base is passed in.
function(sheller_gate_relative_files out base_dir)
  set(files "")
  foreach(src IN LISTS ARGN)
    if(NOT IS_ABSOLUTE "${src}")
      set(src "${base_dir}/${src}")
    endif()
    file(RELATIVE_PATH rel "${CMAKE_SOURCE_DIR}" "${src}")
    list(APPEND files "${rel}")
  endforeach()
  set(${out} "${files}" PARENT_SCOPE)
endfunction()

get_target_property(sheller_engine_gate_sources sheller_engine SOURCES)
get_target_property(sheller_capture_gate_sources sheller_capture SOURCES)
get_target_property(sheller_unpack_gate_sources sheller_unpack SOURCES)
get_target_property(sheller_engine_gate_dir sheller_engine SOURCE_DIR)
get_target_property(sheller_capture_gate_dir sheller_capture SOURCE_DIR)
get_target_property(sheller_unpack_gate_dir sheller_unpack SOURCE_DIR)
sheller_gate_relative_files(sheller_engine_gate_files_engine
  "${sheller_engine_gate_dir}" ${sheller_engine_gate_sources})
sheller_gate_relative_files(sheller_engine_gate_files_capture
  "${sheller_capture_gate_dir}" ${sheller_capture_gate_sources})
sheller_gate_relative_files(sheller_engine_gate_files_unpack
  "${sheller_unpack_gate_dir}" ${sheller_unpack_gate_sources})
set(sheller_engine_gate_files
  ${sheller_engine_gate_files_engine} ${sheller_engine_gate_files_capture}
  ${sheller_engine_gate_files_unpack}
  "src/runtime/capture/capture.cpp" "src/runtime/capture/capture_stub.cpp")
list(REMOVE_DUPLICATES sheller_engine_gate_files)
foreach(rel IN LISTS sheller_engine_gate_files)
  if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${rel}")
    message(FATAL_ERROR "sheller: engine gate file set names a missing file: ${rel}")
  endif()
endforeach()
list(SORT sheller_engine_gate_files)
list(LENGTH sheller_engine_gate_files sheller_engine_gate_count)
string(REPLACE ";" "\n" sheller_engine_gate_files "${sheller_engine_gate_files}")
set(SHELLER_ENGINE_GATE_LIST
  "${CMAKE_CURRENT_BINARY_DIR}/engine_gate_sources.txt" CACHE INTERNAL "engine gate file set")
file(WRITE "${SHELLER_ENGINE_GATE_LIST}" "${sheller_engine_gate_files}\n")
message(STATUS "sheller: engine gate file set: ${sheller_engine_gate_count} source file(s)")

# The host-standard-stream rule is the library's, not the exception-free core's:
# the facade TUs (src/api) are library code too, but they deliberately carry the
# observer's try/catch, so they join the stream scan as their own set rather than
# widening the ratchets that must stay exception-free.
get_target_property(sheller_api_stream_sources sheller_api SOURCES)
get_target_property(sheller_api_stream_dir sheller_api SOURCE_DIR)
sheller_gate_relative_files(sheller_api_stream_files
  "${sheller_api_stream_dir}" ${sheller_api_stream_sources})
set(sheller_stdstream_gate_files ${sheller_engine_gate_files} ${sheller_api_stream_files})
list(REMOVE_DUPLICATES sheller_stdstream_gate_files)
list(SORT sheller_stdstream_gate_files)
list(LENGTH sheller_stdstream_gate_files sheller_stdstream_gate_count)
string(REPLACE ";" "\n" sheller_stdstream_gate_files "${sheller_stdstream_gate_files}")
set(SHELLER_STDSTREAM_GATE_LIST
  "${CMAKE_CURRENT_BINARY_DIR}/stdstream_gate_sources.txt" CACHE INTERNAL
  "host-standard-stream gate file set")
file(WRITE "${SHELLER_STDSTREAM_GATE_LIST}" "${sheller_stdstream_gate_files}\n")
message(STATUS "sheller: stdstream gate file set: ${sheller_stdstream_gate_count} source file(s)")

# No-throw gate: no throw/try/catch statement in an engine translation unit. The
# rule replaced -fno-exceptions, which neither stopped an exception from passing
# through a frame nor let that frame's locals unwind cleanly.
add_test(NAME engine_nothrow
  COMMAND ${CMAKE_COMMAND}
    -DGATE_ROOT=${CMAKE_SOURCE_DIR}
    -DGATE_SOURCE_LIST=${SHELLER_ENGINE_GATE_LIST}
    -DGATE_ALLOWLIST=${CMAKE_CURRENT_SOURCE_DIR}/engine_nothrow_allowlist.txt
    -P ${CMAKE_CURRENT_SOURCE_DIR}/engine_nothrow_gate.cmake)

# Throwing standard-library API gate: std::sto* and a filesystem operation called
# without its error_code overload are hard-banned in an engine TU - both throw, and the
# engine has a typed failure channel for exactly the condition that makes them throw.
add_test(NAME engine_stdapi
  COMMAND ${CMAKE_COMMAND}
    -DGATE_ROOT=${CMAKE_SOURCE_DIR}
    -DGATE_SOURCE_LIST=${SHELLER_ENGINE_GATE_LIST}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/engine_stdapi_gate.cmake)

# .at() ratchet gate: bounds-checked subscripting registered per file, ceiling
# semantics (a file may shrink, never grow). See the table for the classification
# behind each number.
add_test(NAME engine_at_sites
  COMMAND ${CMAKE_COMMAND}
    -DGATE_ROOT=${CMAKE_SOURCE_DIR}
    -DGATE_SOURCE_LIST=${SHELLER_ENGINE_GATE_LIST}
    -DGATE_AT_TABLE=${CMAKE_CURRENT_SOURCE_DIR}/engine_at_sites.txt
    -P ${CMAKE_CURRENT_SOURCE_DIR}/engine_at_ratchet_gate.cmake)

# Host-standard-stream ratchet: no engine TU writes the host's stdout or stderr.
# Existing sites are registered in the allowlist by file, needle and count; the
# table can only shrink, and an entry whose site has been rerouted fails until it
# is removed. See the gate's header for the pattern family and the walking rules.
add_test(NAME engine_stdstream
  COMMAND ${CMAKE_COMMAND}
    -DGATE_ROOT=${CMAKE_SOURCE_DIR}
    -DGATE_SOURCE_LIST=${SHELLER_STDSTREAM_GATE_LIST}
    -DGATE_ALLOWLIST=${CMAKE_CURRENT_SOURCE_DIR}/engine_stdstream_allowlist.txt
    -P ${CMAKE_CURRENT_SOURCE_DIR}/engine_stdstream_gate.cmake)

# Version reconciliation: project() is the only place the version is written, and
# the public header's literals plus version_string() have to agree with it. The
# header stays a checked-in file on purpose (the include-boundary and
# self-containment gates grep it directly), so the agreement needs a mechanism
# rather than a comment that says "must stay in sync".
add_test(NAME version_consistency
  COMMAND ${CMAKE_COMMAND}
    -DGATE_ROOT=${CMAKE_SOURCE_DIR}
    -DPROJECT_VERSION=${PROJECT_VERSION}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/version_gate.cmake)

# Local-corpus equivalence (NOT built by default - the corpora are local
# only): build and run explicitly to review facade equivalence against the
# pinned faces. See tests/README.md. The instoll default is the analyzed
# run30 snapshot (the pinned 57077/5/3/1/0 face); SHELLER_INSTOLL_SNAP
# overrides the path.
add_executable(analysis_facade_local_corpus EXCLUDE_FROM_ALL analysis_facade_local_corpus.cpp)
target_include_directories(analysis_facade_local_corpus PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/api")
target_compile_definitions(analysis_facade_local_corpus PRIVATE
  SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
  SHELLER_INSTOLL_SNAPSHOT="C:/devdrv/tmp/instoll_run30/snap.snap")
target_link_libraries(analysis_facade_local_corpus
  PRIVATE GTest::gtest_main sheller_api sheller_capture)
sheller_apply_common(analysis_facade_local_corpus)

# Snapshot format codec: portable, runs on every platform. The golden file is
# the layout regression sentinel; regenerate it via SHELLER_REGEN_SNAPSHOT_GOLDEN.
add_executable(snapshot_format_test snapshot_format_test.cpp)
target_compile_definitions(snapshot_format_test PRIVATE
  SHELLER_SNAPSHOT_GOLDEN="${CMAKE_CURRENT_SOURCE_DIR}/goldens/snapshot_v1_synthetic.snap")
target_link_libraries(snapshot_format_test PRIVATE GTest::gtest_main sheller_capture)
sheller_apply_common(snapshot_format_test)

add_test(NAME snapshot_format COMMAND snapshot_format_test)

# PE header parser: portable by design, exercised from fixture bytes.
add_executable(pe_headers_test pe_headers_test.cpp)
target_include_directories(pe_headers_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_link_libraries(pe_headers_test PRIVATE GTest::gtest_main sheller_capture)
sheller_apply_common(pe_headers_test)

add_test(NAME pe_headers COMMAND pe_headers_test)

# Guest contract types: pure header-only types + TLV codec, both platforms.
add_executable(contract_test contract_test.cpp)
target_include_directories(contract_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_compile_definitions(contract_test PRIVATE
  SHELLER_CONTRACT_GOLDEN="${CMAKE_CURRENT_SOURCE_DIR}/goldens/contract_events.golden")
target_link_libraries(contract_test PRIVATE GTest::gtest_main)
sheller_apply_common(contract_test)

add_test(NAME contract COMMAND contract_test)

# Behavior event ledger: ring semantics + TLV/JSON outputs, portable by
# design (pure standard library), exercised on both platforms.
add_executable(event_ledger_test event_ledger_test.cpp)
target_include_directories(event_ledger_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior")
target_link_libraries(event_ledger_test PRIVATE GTest::gtest_main sheller_engine sheller_cli_render)
sheller_apply_common(event_ledger_test)

add_test(NAME event_ledger COMMAND event_ledger_test)

# Report events section: tally + deterministic events render for the
# behavior report - portable by design (pure standard library).
add_executable(report_events_test report_events_test.cpp)
target_include_directories(report_events_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior")
target_link_libraries(report_events_test PRIVATE GTest::gtest_main sheller_engine sheller_cli_render)
sheller_apply_common(report_events_test)

add_test(NAME report_events COMMAND report_events_test)

# API-call codec: kApiCall / function-form
# kSyscall payload wire contract, pure header-only, both platforms.
add_executable(api_call_codec_test api_call_codec_test.cpp)
target_include_directories(api_call_codec_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(api_call_codec_test PRIVATE GTest::gtest_main)
sheller_apply_common(api_call_codec_test)

add_test(NAME api_call_codec COMMAND api_call_codec_test)

# API description table: seed lookups, invariants,
# calls-flow render + sample-origin view. Pure standard library.
add_executable(api_descriptions_test api_descriptions_test.cpp)
target_include_directories(api_descriptions_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior")
target_link_libraries(api_descriptions_test PRIVATE GTest::gtest_main sheller_engine sheller_cli_render)
sheller_apply_common(api_descriptions_test)

add_test(NAME api_descriptions COMMAND api_descriptions_test)

# Registry interception e2e: Windows-host loader
# route against the resident advapi32.
add_executable(registry_intercept_e2e_test registry_intercept_e2e_test.cpp)
target_include_directories(registry_intercept_e2e_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_link_libraries(registry_intercept_e2e_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(registry_intercept_e2e_test)

add_test(NAME registry_intercept_e2e COMMAND registry_intercept_e2e_test)

# Memory region map: PE32+ section-table parse + three-tier
# attribution queries, portable by design.
add_executable(mem_region_map_test mem_region_map_test.cpp)
target_include_directories(mem_region_map_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(mem_region_map_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(mem_region_map_test)

add_test(NAME mem_region_map COMMAND mem_region_map_test)

# Loop-native gate: closed-CFG classification over fixture bytes - portable
# by design (a pure Zydis scan; the read callback serves a flat buffer).
add_executable(native_gate_test native_gate_test.cpp)
target_include_directories(native_gate_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(native_gate_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(native_gate_test)

add_test(NAME native_gate COMMAND native_gate_test)

# Syscall number resolution: fake-ntdll export walk, stub-immediate
# decode, and semantic policy dispatch - portable by design.
add_executable(syscall_number_map_test syscall_number_map_test.cpp)
target_include_directories(syscall_number_map_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls")
target_include_directories(syscall_number_map_test SYSTEM PRIVATE
  ${SHELLER_UNICORN_INCLUDE_DIR})
target_link_libraries(syscall_number_map_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(syscall_number_map_test)

add_test(NAME syscall_number_map COMMAND syscall_number_map_test)

# Write ledger + raw region dump tests: ledger semantics, dump
# determinism, and a live-uc export byte check - portable by design.
add_executable(write_ledger_test write_ledger_test.cpp)
target_include_directories(write_ledger_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_include_directories(write_ledger_test SYSTEM PRIVATE
  ${SHELLER_UNICORN_INCLUDE_DIR})
target_link_libraries(write_ledger_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(write_ledger_test)

add_test(NAME write_ledger COMMAND write_ledger_test)

# Synthetic DLL load transactions: no host process or system DLL fixtures.
add_executable(dll_loader_test dll_loader_test.cpp)
target_include_directories(dll_loader_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_include_directories(dll_loader_test SYSTEM PRIVATE ${SHELLER_UNICORN_INCLUDE_DIR})
target_link_libraries(dll_loader_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(dll_loader_test)
add_test(NAME dll_loader COMMAND dll_loader_test)


# Behavior rules: signal synthesis over synthetic fact sequences -
# portable by design (the layer never touches unicorn).
add_executable(behavior_rules_test behavior_rules_test.cpp)
target_include_directories(behavior_rules_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(behavior_rules_test PRIVATE GTest::gtest_main sheller_engine sheller_cli_render)
sheller_apply_common(behavior_rules_test)

add_test(NAME behavior_rules COMMAND behavior_rules_test)

# Wrapper blob-embed: pure byte construction of the minimal PE -
# portable by design.
add_executable(wrapper_test wrapper_test.cpp)
target_include_directories(wrapper_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_link_libraries(wrapper_test PRIVATE GTest::gtest_main sheller_capture)
sheller_apply_common(wrapper_test)

add_test(NAME wrapper COMMAND wrapper_test)

# Syscall-chain micro-benchmark and red-line gate: portable,
# runs on every platform and CI job; the 10us/call red line fails the test on
# breach.
add_executable(syscall_bench syscall_bench.cpp)
target_include_directories(syscall_bench PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls")
target_include_directories(syscall_bench SYSTEM PRIVATE
  # unicorn.h is a PRIVATE include of sheller_engine; the bench drives its
  # own unicorn instance, so it needs the header path explicitly - with the
  # same third-party warning suppression the engine target uses.
  "${SHELLER_UNICORN_INCLUDE_DIR}")
if(MSVC)
  target_compile_options(syscall_bench PRIVATE /external:W0)
endif()
target_link_libraries(syscall_bench PRIVATE sheller_engine)
sheller_apply_common(syscall_bench)

add_test(NAME syscall_bench COMMAND syscall_bench)

# Event-stream baselines: portable XXH64 anchor vectors
# plus the Windows corpus digests over relocation-normalized streams. xxhash
# is a tests-only consumer (the digest compresses the baseline, nothing else).
find_package(xxHash CONFIG REQUIRED)

add_executable(event_baseline_test event_baseline_test.cpp)
target_include_directories(event_baseline_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/api"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_compile_definitions(event_baseline_test PRIVATE
  SHELLER_EVENT_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/goldens")
target_link_libraries(event_baseline_test
  PRIVATE GTest::gtest_main sheller_api sheller_engine xxHash::xxhash)
sheller_apply_common(event_baseline_test)

add_test(NAME event_baseline COMMAND event_baseline_test)

# Snapshot rebuild: portable (synthetic snapshots drive Unicorn on both
# platforms) plus a Windows-only end-to-end test over a real capture.
add_executable(rebuild_test rebuild_test.cpp)
target_include_directories(rebuild_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_link_libraries(rebuild_test PRIVATE GTest::gtest_main sheller_engine sheller_capture)
sheller_apply_common(rebuild_test)

add_test(NAME rebuild COMMAND rebuild_test)

add_executable(capture_cli_test capture_cli_test.cpp)
target_compile_definitions(capture_cli_test PRIVATE
  SHELLER_CLI_FILE_NAME="${SHELLER_CLI_FILE_NAME}")
target_include_directories(capture_cli_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_link_libraries(capture_cli_test PRIVATE GTest::gtest_main sheller_capture)
sheller_apply_common(capture_cli_test)
add_dependencies(capture_cli_test sheller)

add_test(NAME capture_cli COMMAND capture_cli_test)
set_tests_properties(capture_cli PROPERTIES
  WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

# DLL-input admission (Windows): the system-dependency contract plus the
# staged-runner real-loader smoke.
if(WIN32)
  add_executable(dll_admission_test dll_admission_test.cpp)
  target_compile_definitions(dll_admission_test PRIVATE
    SHELLER_SAMPLE_PACKED_DLL_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.dll")
  target_include_directories(dll_admission_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(dll_admission_test PRIVATE GTest::gtest_main sheller_capture)
  sheller_apply_common(dll_admission_test)
  add_test(NAME dll_admission COMMAND dll_admission_test)

  # DLL-input route end-to-end (Windows): the acceptance line - capture →
  # unpack reproducing the reference entry point, and the xfer=1 stop face.
  add_executable(dll_e2e_test dll_e2e_test.cpp)
  target_compile_definitions(dll_e2e_test PRIVATE
    SHELLER_CLI_FILE_NAME="${SHELLER_CLI_FILE_NAME}"
    SHELLER_SAMPLE_PACKED_DLL_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.dll")
  target_include_directories(dll_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(dll_e2e_test PRIVATE GTest::gtest_main sheller_capture)
  sheller_apply_common(dll_e2e_test)
  add_dependencies(dll_e2e_test sheller)
  add_test(NAME dll_e2e COMMAND dll_e2e_test)
  set_tests_properties(dll_e2e PROPERTIES
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

  # Live-capture replay chain (Windows): DllMain marker through
  # --guest-stdout, the saved-snapshot round trip, and the esp miss closing
  # the unpack normally. Excluded from shared CI runners - the captured
  # world's per-process entropy crashes the payload past the OEP there (same
  # family as capture_x86_e2e); green on the development machine.
  add_executable(dll_capture_e2e_test dll_capture_e2e_test.cpp)
  target_compile_definitions(dll_capture_e2e_test PRIVATE
    SHELLER_CLI_FILE_NAME="${SHELLER_CLI_FILE_NAME}"
    SHELLER_SAMPLE_PACKED_DLL_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.dll"
    SHELLER_DET_HELPER_PATH="$<TARGET_FILE:det_helper>")
  target_include_directories(dll_capture_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../include")
  target_link_libraries(dll_capture_e2e_test PRIVATE GTest::gtest_main)
  sheller_apply_common(dll_capture_e2e_test)
  add_dependencies(dll_capture_e2e_test sheller det_helper)
  add_test(NAME dll_capture_e2e COMMAND dll_capture_e2e_test)
  set_tests_properties(dll_capture_e2e PROPERTIES
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

  # Resident artifact-chain determinism helper (captured-world-determinism
  # task 3.2): one replay per invocation - raw event stream to disk, exit
  # dump, repair into a .unp. The dll_capture_e2e pin drives two independent
  # helper processes over one container and byte-compares the artifacts.
  add_executable(det_helper det_helper.cpp)
  target_include_directories(det_helper PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/api"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
  target_link_libraries(det_helper PRIVATE sheller_api)
  sheller_apply_common(det_helper)
endif()

  # Synthetic system modules: the frozen manifests are committed, the
  # deterministic PEs are generated into the build dir at configure/build time
  # (python3 stdlib only). The engine's synthetic-mode option reads them.
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  set(SYNTH_MANIFEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/synth_modules/manifest")
  set(SYNTH_MODULE_DIR "${CMAKE_BINARY_DIR}/synth_modules")
  file(GLOB SYNTH_MANIFESTS "${SYNTH_MANIFEST_DIR}/*.json")
  add_custom_command(
    OUTPUT "${SYNTH_MODULE_DIR}/.generated"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SYNTH_MODULE_DIR}"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_synth_modules.py"
            "${SYNTH_MANIFEST_DIR}" "${SYNTH_MODULE_DIR}"
    DEPENDS ${SYNTH_MANIFESTS}
            "${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_synth_modules.py"
    COMMENT "Generating synthetic system modules")
  add_custom_target(synth_modules ALL
    DEPENDS "${SYNTH_MODULE_DIR}/.generated")

  # Container size bound: derived from the generated modules,
  # the test sample and the engine reserves by tools/container_size_bound.py.
  # The generated header is the only source of the threshold - tests never
  # spell the number themselves.
  set(CONTAINER_BOUND_HEADER "${CMAKE_BINARY_DIR}/container_size_bound.h")
  add_custom_command(
    OUTPUT "${CONTAINER_BOUND_HEADER}"
    COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/../tools/container_size_bound.py"
            --synth-dir "${SYNTH_MODULE_DIR}"
            --sample "${CMAKE_SOURCE_DIR}/tests/packed.exe"
            --loader-env "${CMAKE_SOURCE_DIR}/src/loader/env.h"
            --rebuild-state "${CMAKE_SOURCE_DIR}/src/engine/rebuild_state.h"
            --header "${CONTAINER_BOUND_HEADER}"
    DEPENDS "${SYNTH_MODULE_DIR}/.generated"
            "${CMAKE_CURRENT_SOURCE_DIR}/../tools/container_size_bound.py"
            "${CMAKE_SOURCE_DIR}/tests/packed.exe"
            "${CMAKE_SOURCE_DIR}/src/loader/env.h"
            "${CMAKE_SOURCE_DIR}/src/engine/rebuild_state.h"
    COMMENT "Deriving the crafted-container size bound")
  add_custom_target(container_size_bound ALL
    DEPENDS "${CONTAINER_BOUND_HEADER}")

  add_executable(synth_modules_test synth_modules_test.cpp)
  target_include_directories(synth_modules_test SYSTEM PRIVATE
    ${SHELLER_UNICORN_INCLUDE_DIR})
  target_include_directories(synth_modules_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include")
  target_compile_definitions(synth_modules_test PRIVATE
    SYNTH_GEN_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_synth_modules.py"
    SYNTH_MANIFEST_DIR="${SYNTH_MANIFEST_DIR}"
    SYNTH_MODULE_DIR="${SYNTH_MODULE_DIR}"
    SYNTH_PYTHON="${Python3_EXECUTABLE}"
    SHELLER_SAMPLE_PACKED_PATH="${CMAKE_SOURCE_DIR}/tests/packed.exe")
  target_link_libraries(synth_modules_test
    PRIVATE GTest::gtest_main sheller_engine)
  sheller_apply_common(synth_modules_test)
  add_dependencies(synth_modules_test synth_modules)
  add_test(NAME synth_modules COMMAND synth_modules_test)

  # Boundary description seed (change real-dll-module-dir): the codegen over
  # tools/boundary_manifest/*.json is deterministic, the committed
  # src/engine/boundary_seed.inc stays fresh, and the committed table
  # compiles standalone with the pinned fixture-image binding.
  add_executable(boundary_seed_test boundary_seed_test.cpp)
  target_include_directories(boundary_seed_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
  target_compile_definitions(boundary_seed_test PRIVATE
    BOUNDARY_GEN_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_boundary_seed.py"
    BOUNDARY_MANIFEST_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../tools/boundary_manifest"
    BOUNDARY_SEED="${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/boundary_seed.inc"
    BOUNDARY_PYTHON="${Python3_EXECUTABLE}")
  target_link_libraries(boundary_seed_test PRIVATE GTest::gtest_main)
  sheller_apply_common(boundary_seed_test)
  add_test(NAME boundary_seed COMMAND boundary_seed_test)

  # Boundary manifest binding (change real-dll-module-dir): the committed
  # seed's applicability verdicts are named rejections, the seed rows drive
  # the derive end-to-end, and forwarded exports classify along the chain.
  add_executable(boundary_manifest_test boundary_manifest_test.cpp)
  target_include_directories(boundary_manifest_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader")
  target_link_libraries(boundary_manifest_test PRIVATE GTest::gtest_main sheller_engine)
  sheller_apply_common(boundary_manifest_test)
  add_test(NAME boundary_manifest COMMAND boundary_manifest_test)

  # Boundary metadata codec (change real-dll-module-dir): deterministic
  # encode, the named over-limit rejection, damage-by-name decode
  # rejections, and the DOS e_res2 marker round trip.
  add_executable(boundary_metadata_test boundary_metadata_test.cpp)
  target_include_directories(boundary_metadata_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
  target_link_libraries(boundary_metadata_test PRIVATE GTest::gtest_main sheller_engine)
  sheller_apply_common(boundary_metadata_test)
  add_test(NAME boundary_metadata COMMAND boundary_metadata_test)

  # API Set map (change real-dll-module-dir): generator determinism, the
  # bounded reader's named rejections, and the explicit context resolving
  # directory maps while the synthetic prefix route stays unchanged.
  add_executable(apiset_map_test apiset_map_test.cpp)
  target_include_directories(apiset_map_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tests")
  target_compile_definitions(apiset_map_test PRIVATE
    APISET_GEN_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_apiset_map.py"
    APISET_SOURCE_JSON="${CMAKE_CURRENT_SOURCE_DIR}/../tools/apisetmap/ntdll.x64.json"
    APISET_PYTHON="${Python3_EXECUTABLE}")
  target_link_libraries(apiset_map_test PRIVATE GTest::gtest_main sheller_engine)
  sheller_apply_common(apiset_map_test)
  add_test(NAME apiset_map COMMAND apiset_map_test)

  # Directory-mode loader route (change real-dll-module-dir): the strict
  # source tiers over a user directory - derived boundary pair, real-byte
  # modules, required anchored API Set map, named closure rejections, the
  # marked synthetic fallback, and the untouched synthetic route.
  add_executable(loader_directory_test loader_directory_test.cpp)
  target_include_directories(loader_directory_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_compile_definitions(loader_directory_test PRIVATE
    SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
    SHELLER_SAMPLE_PACKED_DLL_PATH="${CMAKE_SOURCE_DIR}/tests/packed.dll"
    SYNTH_MODULE_DIR="${SYNTH_MODULE_DIR}"
    APISET_GEN_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_apiset_map.py"
    APISET_SOURCE_JSON="${CMAKE_CURRENT_SOURCE_DIR}/../tools/apisetmap/ntdll.x64.json"
    APISET_PYTHON="${Python3_EXECUTABLE}")
  target_link_libraries(loader_directory_test PRIVATE GTest::gtest_main sheller_engine sheller_api)
  sheller_apply_common(loader_directory_test)
  add_test(NAME loader_directory COMMAND loader_directory_test)

  # Crafted containers: construction from a prepared guest, record fidelity,
  # attribution, determinism, synthetic-world reattach and its exact-base
  # predicate, LdrLoadDll handles, and the machine-derived size bound.
  add_executable(snapshot_craft_test snapshot_craft_test.cpp)
  target_include_directories(snapshot_craft_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_BINARY_DIR}")
  target_compile_definitions(snapshot_craft_test PRIVATE
    SYNTH_MODULE_DIR="${SYNTH_MODULE_DIR}"
    SHELLER_SAMPLE_PACKED_PATH="${CMAKE_SOURCE_DIR}/tests/packed.exe"
    SHELLER_SAMPLE_PACKED_DLL_PATH="${CMAKE_SOURCE_DIR}/tests/packed.dll")
  target_link_libraries(snapshot_craft_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(snapshot_craft_test)
  add_dependencies(snapshot_craft_test synth_modules container_size_bound)
  add_test(NAME snapshot_craft COMMAND snapshot_craft_test)

  # DLL fixture semantics: the hand-built TLS + push-prefix
  # DllMain fixture through the crafted runner world - ATTACH frame arguments,
  # TLS directory order, IAT-bound calls, TRUE/FALSE continuations, and the
  # esp/esp+xfer stop faces at the re-armed DllMain window.
  add_executable(dll_fixture_semantics_test dll_fixture_semantics_test.cpp)
  target_include_directories(dll_fixture_semantics_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_BINARY_DIR}")
  target_compile_definitions(dll_fixture_semantics_test PRIVATE
    SYNTH_MODULE_DIR="${SYNTH_MODULE_DIR}")
  target_link_libraries(dll_fixture_semantics_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(dll_fixture_semantics_test)
  add_dependencies(dll_fixture_semantics_test synth_modules)
  add_test(NAME dll_fixture_semantics COMMAND dll_fixture_semantics_test)

  # Linux packed e2e: the packed.exe snapshot (captured on a Windows
  # host) is replayed on the Linux engine, the dump is repaired and the .unp
  # is produced. Skips when the snapshot file has not been transferred.
  add_executable(linux_packed_e2e_test EXCLUDE_FROM_ALL linux_packed_e2e_test.cpp)
  target_compile_definitions(linux_packed_e2e_test PRIVATE
    LINUX_PACKED_SNAPSHOT="${CMAKE_CURRENT_SOURCE_DIR}/packed_lin.snap")
  target_link_libraries(linux_packed_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_unpack)
  sheller_apply_common(linux_packed_e2e_test)



if(WIN32)
  target_compile_definitions(event_baseline_test PRIVATE
    SHELLER_SAMPLE_HELLO_PATH="$<TARGET_FILE:capture_syscall_sample>"
    SHELLER_SAMPLE_DENY_PATH="$<TARGET_FILE:capture_syscall_deny>"
    SHELLER_SAMPLE_SPIN_PATH="$<TARGET_FILE:capture_syscall_spin>")
  add_dependencies(event_baseline_test capture_syscall_sample capture_syscall_deny
    capture_syscall_spin)

  # Facade test: the hello sample drives the save-snapshot and repair-failure
  # faces; packed.exe drives the full unpack pipeline and its concurrency.
  target_compile_definitions(analysis_facade_test PRIVATE
    SHELLER_SAMPLE_HELLO_PATH="$<TARGET_FILE:capture_syscall_sample>"
    SHELLER_SAMPLE_XFER_DELAY_PATH="$<TARGET_FILE:capture_xfer_delay_sample>")
  add_dependencies(analysis_facade_test capture_syscall_sample capture_xfer_delay_sample)

  # The DLL-side chain (capture::run -> analyze) rides the same hello sample.
  target_compile_definitions(shared_api_test PRIVATE
    SHELLER_SAMPLE_HELLO_PATH="$<TARGET_FILE:capture_syscall_sample>")
  add_dependencies(shared_api_test capture_syscall_sample)

  # CLI run subcommand: snapshot syscall runs with per-number reject config.
  add_executable(cli_run_test cli_run_test.cpp)
  target_compile_definitions(cli_run_test PRIVATE
    SHELLER_CLI_FILE_NAME="${SHELLER_CLI_FILE_NAME}"
    SHELLER_SAMPLE_HELLO_PATH="$<TARGET_FILE:capture_syscall_sample>"
    SHELLER_SAMPLE_SPIN_PATH="$<TARGET_FILE:capture_syscall_spin>"
    SHELLER_SAMPLE_XFER_PATH="$<TARGET_FILE:capture_xfer_sample>"
    SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe")
  target_link_libraries(cli_run_test PRIVATE GTest::gtest_main sheller_capture)
  sheller_apply_common(cli_run_test)
  add_dependencies(cli_run_test sheller capture_syscall_sample capture_syscall_spin
    capture_xfer_sample)

  add_test(NAME cli_run COMMAND cli_run_test)
  set_tests_properties(cli_run PROPERTIES
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:sheller>")

  # SEH-driven sample for the exception dispatch: MSVC C for the .pdata/
  # .xdata unwind tables the real dispatcher walks, plus ml64 thunks for the
  # direct syscalls and the fastfail entry.
  # The scope-table language handler is implemented inside the sample itself
  # (static-CRT-only symbol, no DLL exports it); ntdll provides RtlUnwindEx.
  # Cross-section transfer sample: two executable sections, the
  # jump between them triggers the xfer event.
  add_executable(capture_xfer_sample capture_xfer_sample.c capture_xfer_thunks.asm)
  set_target_properties(capture_xfer_sample PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_xfer_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB /SECTION:text2,ER)

  # The same transfer behind a guest-visible counter loop: the unpack
  # wall-clock-veto case needs the transfer inside the first leg but after a
  # 1 ms clock crossing.
  add_executable(capture_xfer_delay_sample capture_xfer_delay_sample.c capture_xfer_thunks.asm)
  set_target_properties(capture_xfer_delay_sample PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_xfer_delay_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB /SECTION:text2,ER)

  # Alloc-jump corpus: VirtualAlloc private data memory, write a payload,
  # protect it executable, jump in - the runtime-region classification
  # sequence as guest code (kernel32 imports, no CRT).
  add_executable(capture_allocjump_sample capture_allocjump_sample.c capture_xfer_thunks.asm)
  set_target_properties(capture_allocjump_sample PROPERTIES LINKER_LANGUAGE C)
  target_compile_options(capture_allocjump_sample PRIVATE /GS- /RTC-)
  target_link_libraries(capture_allocjump_sample PRIVATE kernel32 ntdll)
  target_link_options(capture_allocjump_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB)

  # Unknown-image corpus: calls into a hand-mapped image the test crafts
  # into the captured snapshot (contiguous MEM_IMAGE regions the Ldr list
  # never enumerates), checks the MBI/MII answers, then faults inside the
  # image under a continue-search VEH (kernel32 imports, no CRT).
  add_executable(capture_unknownjump_sample capture_unknownjump_sample.c capture_xfer_thunks.asm)
  set_target_properties(capture_unknownjump_sample PROPERTIES LINKER_LANGUAGE C)
  target_compile_options(capture_unknownjump_sample PRIVATE /GS- /RTC-)
  target_link_libraries(capture_unknownjump_sample PRIVATE kernel32 ntdll)
  target_link_options(capture_unknownjump_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB)

  # MSVC Debug defaults inject /RTC1 into these C+asm mixed samples; the
  # hand-written thunks have no RTC frame machinery, so the link pulls
  # _RTC_InitBase and dies. Strip it for this scope (samples only).
  string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
  string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

  add_executable(capture_seh_sample capture_seh_sample.c capture_seh_thunks.asm)
  set_target_properties(capture_seh_sample PROPERTIES LINKER_LANGUAGE C)
  target_compile_options(capture_seh_sample PRIVATE /GS- /RTC-)
  target_link_libraries(capture_seh_sample PRIVATE ntdll)
  target_link_options(capture_seh_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB)

  add_executable(capture_seh_fastfail capture_seh_sample.c capture_seh_thunks.asm)
  set_target_properties(capture_seh_fastfail PROPERTIES LINKER_LANGUAGE C)
  target_compile_options(capture_seh_fastfail PRIVATE /GS- /RTC-)
  target_link_libraries(capture_seh_fastfail PRIVATE ntdll)
  target_link_options(capture_seh_fastfail PRIVATE
    /ENTRY:entry_fastfail /SUBSYSTEM:CONSOLE /NODEFAULTLIB)

  add_executable(capture_seh_veh_sample capture_seh_veh_sample.c capture_seh_thunks.asm)
  set_target_properties(capture_seh_veh_sample PROPERTIES LINKER_LANGUAGE C)
  target_compile_options(capture_seh_veh_sample PRIVATE /GS- /RTC-)
  target_link_libraries(capture_seh_veh_sample PRIVATE ntdll)
  target_link_options(capture_seh_veh_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB)

  # SEH __finally corpus: the unwind second pass runs the
  # termination handler; the language handler is self-provided with real
  # __finally-on-unwind semantics.
  add_executable(capture_seh_finally_sample capture_seh_finally_sample.c capture_seh_thunks.asm)
  set_target_properties(capture_seh_finally_sample PROPERTIES LINKER_LANGUAGE C)
  target_compile_options(capture_seh_finally_sample PRIVATE /GS- /RTC-)
  target_link_libraries(capture_seh_finally_sample PRIVATE ntdll)
  target_link_options(capture_seh_finally_sample PRIVATE
    /ENTRY:entry_main /SUBSYSTEM:CONSOLE /NODEFAULTLIB)

  # C++ EH corpus: full CRT startup (the emulated heap and
  # the interception layer already carry it - see packed), /MD so the
  # __CxxFrameHandler4 path runs the real vcruntime140(_1).dll guest code.
  # Corpus contract: /MD + /GS- in every config; the optimization shape
  # follows the build config - Debug builds the diagnosed /Od + /RTC1 shape
  # (the engine C++ unwind misattributed establisher frames exactly there,
  # see OPENSPEC-BACKLOG "C++ EH corpus shape") and release configs keep the
  # /O2 baseline. exception_e2e pins both shapes through its two configs.
  add_executable(capture_cpp_eh_sample capture_cpp_eh_sample.cpp capture_seh_thunks.asm)
  set_target_properties(capture_cpp_eh_sample PROPERTIES LINKER_LANGUAGE CXX
    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  target_compile_options(capture_cpp_eh_sample PRIVATE /GS-
    "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Debug>>:/RTC1>"
    "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CONFIG:Debug>>>:/O2 /RTC->")
  target_link_options(capture_cpp_eh_sample PRIVATE /SUBSYSTEM:CONSOLE)

  # Engine-dispatch entry variant: a hardware AV inside C++
  # code - the engine walk opens __CxxFrameHandler4 frames; /EHa so
  # catch(...) accepts the hardware exception code.
  add_executable(capture_cpp_eh_av_sample capture_cpp_eh_av_sample.cpp capture_seh_thunks.asm)
  set_target_properties(capture_cpp_eh_av_sample PROPERTIES LINKER_LANGUAGE CXX
    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  target_compile_options(capture_cpp_eh_av_sample PRIVATE /GS- /EHa
    "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Debug>>:/RTC1>"
    "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CONFIG:Debug>>>:/O2 /RTC->")
  target_link_options(capture_cpp_eh_av_sample PRIVATE /SUBSYSTEM:CONSOLE)

  # Exception dispatch end-to-end: SEH frame walk + crash fallback.
  add_executable(exception_e2e_test exception_e2e_test.cpp)
  target_include_directories(exception_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(exception_e2e_test PRIVATE
    SHELLER_SAMPLE_SEH_PATH="$<TARGET_FILE:capture_seh_sample>"
    SHELLER_SAMPLE_SEH_FASTFAIL_PATH="$<TARGET_FILE:capture_seh_fastfail>"
    SHELLER_SAMPLE_SEH_VEH_PATH="$<TARGET_FILE:capture_seh_veh_sample>"
    SHELLER_SAMPLE_SEH_FINALLY_PATH="$<TARGET_FILE:capture_seh_finally_sample>"
    SHELLER_SAMPLE_CPP_EH_PATH="$<TARGET_FILE:capture_cpp_eh_sample>"
    SHELLER_SAMPLE_CPP_EH_AV_PATH="$<TARGET_FILE:capture_cpp_eh_av_sample>"
    SHELLER_SAMPLE_HELLO_PATH="$<TARGET_FILE:capture_syscall_sample>"
    SHELLER_SAMPLE_XFER_PATH="$<TARGET_FILE:capture_xfer_sample>"
    SHELLER_SAMPLE_ALLOCJUMP_PATH="$<TARGET_FILE:capture_allocjump_sample>"
    SHELLER_SAMPLE_UNKNOWNJUMP_PATH="$<TARGET_FILE:capture_unknownjump_sample>"
    SHELLER_SAMPLE_SPIN_PATH="$<TARGET_FILE:capture_syscall_spin>")
  target_link_libraries(exception_e2e_test PRIVATE GTest::gtest_main sheller_engine sheller_capture sheller_cli_render)
  sheller_apply_common(exception_e2e_test)
  add_dependencies(exception_e2e_test capture_seh_sample capture_seh_fastfail
    capture_seh_veh_sample capture_seh_finally_sample capture_cpp_eh_sample
    capture_cpp_eh_av_sample capture_xfer_sample capture_allocjump_sample
    capture_unknownjump_sample capture_syscall_spin)

  add_test(NAME exception_e2e COMMAND exception_e2e_test)

  # Real compiler-built sample for the capture tests: a valid PE with a TLS
  # callback (see capture_sample.c). The hand-crafted bytes in minimal_pe.h
  # only feed the portable parser test, never the real loader.
  add_executable(capture_sample capture_sample.c)

  # ml64 direct-syscall sample for the syscall skeleton: three entries in one
  # object, linked three times with different entry points (hello lifecycle,
  # default-deny probe, budget-exhaustion spinner). No CRT: /NODEFAULTLIB
  # plus /ENTRY; /DYNAMICBASE keeps the relocations the real loader needs.
  enable_language(ASM_MASM)
  add_executable(capture_syscall_sample capture_syscall_sample.asm)
  set_target_properties(capture_syscall_sample PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_syscall_sample PRIVATE
    /ENTRY:entry /SUBSYSTEM:CONSOLE /DYNAMICBASE /NODEFAULTLIB)

  add_executable(capture_syscall_deny capture_syscall_sample.asm)
  set_target_properties(capture_syscall_deny PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_syscall_deny PRIVATE
    /ENTRY:entry_deny /SUBSYSTEM:CONSOLE /DYNAMICBASE /NODEFAULTLIB)

  add_executable(capture_syscall_spin capture_syscall_sample.asm)
  set_target_properties(capture_syscall_spin PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_syscall_spin PRIVATE
    /ENTRY:entry_spin /SUBSYSTEM:CONSOLE /DYNAMICBASE /NODEFAULTLIB)

  # Same object, fourth entry point: three NtWriteFile calls before terminating.
  # The guest-sink cases need more than one write in a run, because "only the
  # throwing write is dropped" cannot be shown with a single one.
  add_executable(capture_syscall_multiwrite capture_syscall_sample.asm)
  set_target_properties(capture_syscall_multiwrite PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_syscall_multiwrite PRIVATE
    /ENTRY:entry_multi /SUBSYSTEM:CONSOLE /DYNAMICBASE /NODEFAULTLIB)

  # Same object, fifth entry point: the burn-loop corpus - outer 16 x inner
  # 100000h counter delay, then terminate. Without the fast-forward the default
  # 1M instruction budget ends inside the delay instead of the exit syscall.
  add_executable(capture_syscall_delay capture_syscall_sample.asm)
  set_target_properties(capture_syscall_delay PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_syscall_delay PRIVATE
    /ENTRY:entry_delay /SUBSYSTEM:CONSOLE /DYNAMICBASE /NODEFAULTLIB)

  # ml64 read-mode sample for the behavior layer: PEB walk,
  # BeingDebugged probe, call $+5 / pop GetPC, unregistered direct syscall.
  add_executable(capture_behavior_sample capture_behavior_sample.asm)
  set_target_properties(capture_behavior_sample PROPERTIES LINKER_LANGUAGE C)
  target_link_options(capture_behavior_sample PRIVATE
    /ENTRY:entry /SUBSYSTEM:CONSOLE /DYNAMICBASE /NODEFAULTLIB)

  add_executable(behavior_e2e_test behavior_e2e_test.cpp)
  target_include_directories(behavior_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/api"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(behavior_e2e_test PRIVATE
    SHELLER_SAMPLE_BEHAVIOR_PATH="$<TARGET_FILE:capture_behavior_sample>"
    SHELLER_SAMPLE_SEH_VEH_PATH="$<TARGET_FILE:capture_seh_veh_sample>"
    SHELLER_SAMPLE_DELAY_PATH="$<TARGET_FILE:capture_syscall_delay>")
  target_link_libraries(behavior_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture sheller_cli_render sheller_api)
  sheller_apply_common(behavior_e2e_test)
  add_dependencies(behavior_e2e_test capture_behavior_sample capture_seh_veh_sample
    capture_syscall_delay)

  add_test(NAME behavior_e2e COMMAND behavior_e2e_test)

  # Wrapper e2e: a bare blob rides the standard capture route and the
  # blob executes in the emulator (direct syscall + terminate assertions).
  add_executable(wrapper_pe_e2e_test wrapper_pe_e2e_test.cpp)
  target_include_directories(wrapper_pe_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(wrapper_pe_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(wrapper_pe_e2e_test)

  add_test(NAME wrapper_pe_e2e COMMAND wrapper_pe_e2e_test)
endif()

# Loader route: PE parse/layout/reloc/TLS pure functions plus the
# loader-run e2e (TLS order, direct syscall, terminate, budget, determinism).
add_executable(loader_env_x86_test loader_env_x86_test.cpp)
target_include_directories(loader_env_x86_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader")
target_link_libraries(loader_env_x86_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(loader_env_x86_test)
add_test(NAME loader_env_x86 COMMAND loader_env_x86_test)

# uc_context save/restore contract: pins the unicorn behaviors
# the thread scheduler's context switching builds on. Pure unicorn - both CI
# platforms cover it.
add_executable(uc_context_contract_test uc_context_contract_test.cpp)

# UNWIND_CODE prolog accounting table (engine-side SEH dispatcher)
add_executable(seh_dispatcher_test seh_dispatcher_test.cpp)
target_include_directories(seh_dispatcher_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_include_directories(seh_dispatcher_test SYSTEM PRIVATE
  ${SHELLER_UNICORN_INCLUDE_DIR})
target_link_libraries(seh_dispatcher_test
  PRIVATE GTest::gtest_main sheller_engine ${SHELLER_UNICORN_LIBRARY})
sheller_apply_common(seh_dispatcher_test)
add_test(NAME seh_dispatcher COMMAND seh_dispatcher_test)
target_include_directories(uc_context_contract_test SYSTEM PRIVATE
  ${SHELLER_UNICORN_INCLUDE_DIR})
target_link_libraries(uc_context_contract_test
  PRIVATE GTest::gtest_main sheller_engine ${SHELLER_UNICORN_LIBRARY})
sheller_apply_common(uc_context_contract_test)
add_test(NAME uc_context_contract COMMAND uc_context_contract_test)

add_executable(loader_test loader_test.cpp)
target_include_directories(loader_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader")
target_link_libraries(loader_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(loader_test)

add_test(NAME loader COMMAND loader_test)

# Boundary derivation (change real-dll-module-dir): the pure byte-level
# directory-file -> stub-image function - syscall numbers validated in the
# source body, names/ordinals/aliases/forwarders preserved, EAT rebuilt,
# weld-slot and marker-slot layout, double-derive determinism, named
# rejections. Portable by design.
add_executable(boundary_derive_test boundary_derive_test.cpp)
target_include_directories(boundary_derive_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader")
target_link_libraries(boundary_derive_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(boundary_derive_test)

add_test(NAME boundary_derive COMMAND boundary_derive_test)

add_executable(loader_pe_e2e_test loader_pe_e2e_test.cpp)
target_compile_definitions(loader_pe_e2e_test PRIVATE
  SYNTH_MODULE_DIR="${CMAKE_BINARY_DIR}/synth_modules")
add_dependencies(loader_pe_e2e_test synth_modules)
target_include_directories(loader_pe_e2e_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
target_link_libraries(loader_pe_e2e_test
  PRIVATE GTest::gtest_main sheller_engine sheller_capture sheller_cli_render)
sheller_apply_common(loader_pe_e2e_test)

add_test(NAME loader_pe_e2e COMMAND loader_pe_e2e_test)

if(WIN32)
# Loader imports: IAT resolution with forwarder chains against the
# host's real system DLLs - Windows-host-only.
if(WIN32)
  add_executable(loader_imports_test loader_imports_test.cpp)
  target_include_directories(loader_imports_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader")
  target_link_libraries(loader_imports_test PRIVATE GTest::gtest_main sheller_engine)
  sheller_apply_common(loader_imports_test)

  add_test(NAME loader_imports COMMAND loader_imports_test)

  add_executable(loader_imports_e2e_test loader_imports_e2e_test.cpp)
  target_include_directories(loader_imports_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(loader_imports_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(loader_imports_e2e_test)

  add_test(NAME loader_imports_e2e COMMAND loader_imports_e2e_test)

  # by-hash shellcode e2e: a bare blob walks the Ldr
  # triple-chain, verifies MZ at each module, exits with the count.
  add_executable(loader_byhash_e2e_test loader_byhash_e2e_test.cpp)
  target_include_directories(loader_byhash_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(loader_byhash_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  target_compile_definitions(loader_byhash_e2e_test PRIVATE
    SHELLER_BYHASH_BIN="${CMAKE_CURRENT_BINARY_DIR}/byhash_shell.bin")

  # x86 by-hash shellcode e2e: 32-bit blob walks the PEB32/Ldr
  # chain and exits with the module count via raw int 2e.
  add_executable(loader_byhash_x86_e2e_test loader_byhash_x86_e2e_test.cpp)
  target_include_directories(loader_byhash_x86_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(loader_byhash_x86_e2e_test PRIVATE
    SHELLER_BYHASH_X86_BIN="${CMAKE_CURRENT_BINARY_DIR}/byhash_shell_x86.bin")
  target_link_libraries(loader_byhash_x86_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(loader_byhash_x86_e2e_test)
  add_dependencies(loader_byhash_x86_e2e_test byhash_blob)
  add_test(NAME loader_byhash_x86_e2e COMMAND loader_byhash_x86_e2e_test)

  # x86 loader import e2e: stdcall IAT calls through the
  # interception layer against the SysWOW64 modules.
  add_executable(loader_imports_x86_e2e_test loader_imports_x86_e2e_test.cpp)
  target_include_directories(loader_imports_x86_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(loader_imports_x86_e2e_test PRIVATE
    SHELLER_IMPORT_X86_BIN="${CMAKE_CURRENT_BINARY_DIR}/import_blob_x86.bin")
  target_link_libraries(loader_imports_x86_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(loader_imports_x86_e2e_test)
  add_dependencies(loader_imports_x86_e2e_test byhash_blob)
  add_test(NAME loader_imports_x86_e2e COMMAND loader_imports_x86_e2e_test)

  # x86 SEH smoke e2e: raw FS:[0] registration, AV, the
  # handler continues execution, the guest exits 0x5678.
  add_executable(seh_x86_smoke_test seh_x86_smoke_test.cpp)
  target_include_directories(seh_x86_smoke_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(seh_x86_smoke_test PRIVATE
    SHELLER_SEH_X86_BIN="${CMAKE_CURRENT_BINARY_DIR}/seh_x86_smoke.bin")
  target_link_libraries(seh_x86_smoke_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(seh_x86_smoke_test)
  add_dependencies(seh_x86_smoke_test byhash_blob)
  add_test(NAME seh_x86_smoke COMMAND seh_x86_smoke_test)

  # x86 snapshot-route e2e: capture a real WOW64 process, rebuild
  # and run the snapshot in 32-bit mode.
  add_executable(capture_x86_e2e_test capture_x86_e2e_test.cpp)
  target_include_directories(capture_x86_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(capture_x86_e2e_test PRIVATE
    SHELLER_BYHASH_X86_BIN="${CMAKE_CURRENT_BINARY_DIR}/byhash_shell_x86.bin")
  target_link_libraries(capture_x86_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(capture_x86_e2e_test)
  add_dependencies(capture_x86_e2e_test byhash_blob)
  add_test(NAME capture_x86_e2e COMMAND capture_x86_e2e_test)

  # multi-thread scheduler e2e: create + cross-thread handoff +
  # blocking wait + exit, all via raw synthetic syscalls.
  add_executable(thread_e2e_test thread_e2e_test.cpp)
  target_include_directories(thread_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(thread_e2e_test PRIVATE
    SHELLER_THREAD_BIN="${CMAKE_CURRENT_BINARY_DIR}/thread_blob.bin")
  target_link_libraries(thread_e2e_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(thread_e2e_test)
  add_dependencies(thread_e2e_test byhash_blob)
  add_test(NAME thread_e2e COMMAND thread_e2e_test)

  # shim memory-access failure semantics: VEX.256
  # load/store against unmapped memory synthesizes AV, never #UD.
  add_executable(shim_pf_test shim_pf_test.cpp)
  target_include_directories(shim_pf_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(shim_pf_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(shim_pf_test)
  add_test(NAME shim_pf COMMAND shim_pf_test)

  # x86 multi-thread smoke: same semantics via int 2e in 32-bit.
  add_executable(thread_x86_smoke_test thread_x86_smoke_test.cpp)
  target_include_directories(thread_x86_smoke_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/loader"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(thread_x86_smoke_test PRIVATE
    SHELLER_THREAD_X86_BIN="${CMAKE_CURRENT_BINARY_DIR}/thread_blob_x86.bin")
  target_link_libraries(thread_x86_smoke_test
    PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(thread_x86_smoke_test)
  add_dependencies(thread_x86_smoke_test byhash_blob)
  add_test(NAME thread_x86_smoke COMMAND thread_x86_smoke_test)
  sheller_apply_common(loader_byhash_e2e_test)
  add_dependencies(loader_byhash_e2e_test byhash_blob)
  add_test(NAME loader_byhash_e2e COMMAND loader_byhash_e2e_test)

  # by-hash shellcode blobs (NASM, x64 + x86)
  add_custom_command(OUTPUT byhash_shell.bin
    COMMAND nasm -f bin ${CMAKE_CURRENT_SOURCE_DIR}/corpus/byhash_shell.asm -o byhash_shell.bin
    DEPENDS corpus/byhash_shell.asm
    COMMENT "nasm byhash_shell")
  add_custom_command(OUTPUT byhash_shell_x86.bin
    COMMAND nasm -f bin ${CMAKE_CURRENT_SOURCE_DIR}/corpus/byhash_shell_x86.asm -o byhash_shell_x86.bin
    DEPENDS corpus/byhash_shell_x86.asm
    COMMENT "nasm byhash_shell_x86")
  add_custom_command(OUTPUT import_blob_x86.bin
    COMMAND nasm -f bin ${CMAKE_CURRENT_SOURCE_DIR}/corpus/import_blob_x86.asm -o import_blob_x86.bin
    DEPENDS corpus/import_blob_x86.asm
    COMMENT "nasm import_blob_x86")
  add_custom_command(OUTPUT thread_blob.bin
    COMMAND nasm -f bin ${CMAKE_CURRENT_SOURCE_DIR}/corpus/thread_blob.asm -o thread_blob.bin
    DEPENDS corpus/thread_blob.asm
    COMMENT "nasm thread_blob")
  add_custom_command(OUTPUT thread_blob_x86.bin
    COMMAND nasm -f bin ${CMAKE_CURRENT_SOURCE_DIR}/corpus/thread_blob_x86.asm -o thread_blob_x86.bin
    DEPENDS corpus/thread_blob_x86.asm
    COMMENT "nasm thread_blob_x86")
  add_custom_command(OUTPUT seh_x86_smoke.bin
    COMMAND nasm -f bin ${CMAKE_CURRENT_SOURCE_DIR}/corpus/seh_x86_smoke.asm -o seh_x86_smoke.bin
    DEPENDS corpus/seh_x86_smoke.asm
    COMMENT "nasm seh_x86_smoke")
  add_custom_target(byhash_blob DEPENDS byhash_shell.bin byhash_shell_x86.bin
    import_blob_x86.bin thread_blob.bin thread_blob_x86.bin
    seh_x86_smoke.bin)
endif()

  add_executable(capture_test capture_test.cpp)
  target_include_directories(capture_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_compile_definitions(capture_test PRIVATE
    SHELLER_CAPTURE_SAMPLE_PATH="$<TARGET_FILE:capture_sample>")
  target_link_libraries(capture_test PRIVATE GTest::gtest_main sheller_capture)
  sheller_apply_common(capture_test)
  add_dependencies(capture_test capture_sample)

  add_test(NAME capture COMMAND capture_test)

  target_compile_definitions(capture_cli_test PRIVATE
    SHELLER_CAPTURE_SAMPLE_PATH="$<TARGET_FILE:capture_sample>")
  add_dependencies(capture_cli_test capture_sample)

  target_compile_definitions(rebuild_test PRIVATE
    SHELLER_CAPTURE_SAMPLE_PATH="$<TARGET_FILE:capture_sample>")
  add_dependencies(rebuild_test capture_sample)

  # Syscall skeleton end-to-end tests over the three direct-syscall samples.
  add_executable(syscall_e2e_test syscall_e2e_test.cpp)
  target_include_directories(syscall_e2e_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/behavior")
  target_compile_definitions(syscall_e2e_test PRIVATE
    SHELLER_SAMPLE_HELLO_PATH="$<TARGET_FILE:capture_syscall_sample>"
    SHELLER_SAMPLE_DENY_PATH="$<TARGET_FILE:capture_syscall_deny>"
    SHELLER_SAMPLE_SPIN_PATH="$<TARGET_FILE:capture_syscall_spin>"
    SHELLER_SAMPLE_MULTIWRITE_PATH="$<TARGET_FILE:capture_syscall_multiwrite>")
  target_link_libraries(syscall_e2e_test PRIVATE GTest::gtest_main sheller_engine sheller_capture)
  sheller_apply_common(syscall_e2e_test)
  add_dependencies(syscall_e2e_test capture_syscall_sample capture_syscall_deny
    capture_syscall_spin capture_syscall_multiwrite)

  add_test(NAME syscall_e2e COMMAND syscall_e2e_test)
endif()

# The guest-output sink's guard: what the engine does when the host's
# options.write_sink throws. Built and run on both platforms on purpose - the
# frame under test (engine's sink_trampoline) is the delivery point itself, not the
# capture route that feeds it, so the containment claim does not have to wait for
# a Windows-only corpus. The end-to-end half of the same contract - a real guest
# writing more than once, the event stream and the run statistics unchanged - is
# covered on both platforms as well, from two directions: over a crafted snapshot
# in analysis_facade_test.cpp's EngineGuestOutput group (portable, needs no corpus
# file), and over a captured sample in syscall_e2e_test.cpp (Windows, where the
# capture route exists to produce one). This file is the unit level under both.
add_executable(guest_sink_guard_test guest_sink_guard_test.cpp)
target_include_directories(guest_sink_guard_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/syscalls")
target_link_libraries(guest_sink_guard_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(guest_sink_guard_test)

add_test(NAME guest_sink_guard COMMAND guest_sink_guard_test)

# ESP-law stop target (change esp-law-oep): crafted save/restore corpora
# drive the engine entry directly through the public run_snapshot_syscalls -
# portable by design (crafted snapshots, no capture route), with the two
# stop forms, the anti-debug rejection, the silent cells and the probe-leg
# coexistence as fixture-pinned faces.
add_executable(esp_target_test esp_target_test.cpp)
target_include_directories(esp_target_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(esp_target_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(esp_target_test)

add_test(NAME esp_target COMMAND esp_target_test)


# Engine trace routing: ONE binary, TWO runs. The site switches cache
# their getenv in function-local statics, so the switch-on and switch-off halves of
# the contract cannot share a process - they are two ctest entries over the same
# executable, and the mode is carried by argv (see the TU's main()). Which corpus
# reaches which site is recorded in the TU header: the spin fixture is portable, the
# SEH and hello samples need the Windows capture route, and off Windows the same
# [file] site is reached through the loader route on packed.exe.
add_executable(engine_trace_test engine_trace_test.cpp)
target_include_directories(engine_trace_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine")
target_link_libraries(engine_trace_test PRIVATE GTest::gtest_main sheller_engine)
sheller_apply_common(engine_trace_test)

if(WIN32)
  # The SEH and fastfail corpora come through the capture route, which only exists on
  # Windows - see the TU header for what each platform's binary asserts.
  target_include_directories(engine_trace_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/runtime/capture")
  target_link_libraries(engine_trace_test PRIVATE sheller_capture)
  target_compile_definitions(engine_trace_test PRIVATE
    SHELLER_SAMPLE_SEH_PATH="$<TARGET_FILE:capture_seh_sample>"
    SHELLER_SAMPLE_SEH_FASTFAIL_PATH="$<TARGET_FILE:capture_seh_fastfail>")
  add_dependencies(engine_trace_test capture_seh_sample capture_seh_fastfail)
endif()

add_test(NAME engine_trace COMMAND engine_trace_test --traces-on
         "--gtest_filter=-EngineTraceNoSink.*")
add_test(NAME engine_trace_quiet COMMAND engine_trace_test
         "--gtest_filter=-EngineTraceNoSink.*")
# The third cell of the triple gate: switches set and no host sink installed, which is
# the combination the batch argues about (the environment is the face an attacker can
# reach). Only the one case runs here; engine_trace_test's main() fails the entry if it
# did not run, so a filter that stops matching cannot read as a green test.
add_test(NAME engine_trace_nosink COMMAND engine_trace_test --traces-on --no-sink
         "--gtest_filter=EngineTraceNoSink.*")

# Static-side concurrency: four threads inside the analysis and unpack
# entries at once, over the static core. Portable by design - the analysis half drives
# a crafted snapshot, the unpack half uses the packed corpus, whose route differs by
# platform (see the TU comments for what each platform can therefore assert).
add_executable(concurrency_test concurrency_test.cpp)
target_include_directories(concurrency_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/engine"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/api")
target_compile_definitions(concurrency_test PRIVATE
  SHELLER_SAMPLE_PACKED_PATH="${CMAKE_CURRENT_SOURCE_DIR}/packed.exe"
  SYNTH_MODULE_DIR="${CMAKE_BINARY_DIR}/synth_modules")
target_link_libraries(concurrency_test PRIVATE GTest::gtest_main sheller_api)
sheller_apply_common(concurrency_test)
add_dependencies(concurrency_test synth_modules)

add_test(NAME concurrency COMMAND concurrency_test)

