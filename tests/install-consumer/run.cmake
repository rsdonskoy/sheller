# Driver for the minimal installed consumer (specs/delivery-surface).
#
# Installs a configured build tree to a throwaway prefix, then configures, builds
# and runs tests/install-consumer against that prefix alone. A cmake -P script
# rather than a shell script, because the same readable logic has to work on a
# Visual Studio multi-config generator and on a single-config one, and on both a
# bash and a plain cmd host.
#
# This is deliberately NOT part of the default ctest set: it needs an installed
# prefix, and a normal build does not have one. Run it after a build:
#
#   Windows: cmake -DSHELLER_ROOT=C:/devdrv/src/sheller -DBUILD_DIR=<...>/build/windows-release
#            -DCONFIG=Release -DSNAPSHOT=<a replayable snapshot> -P tests/install-consumer/run.cmake
#   Linux:   cmake -DSHELLER_ROOT=$HOME/rv -DBUILD_DIR=$HOME/rv/build/linux-release
#            -DCONFIG=Release -DSNAPSHOT=... -P tests/install-consumer/run.cmake
#
# What it proves, in order:
#   1. the package installs: library, import library, headers, package config,
#      CLI, and on Windows the third-party runtimes the public header promises;
#   2. the installed header set is the source tree's set, compared by name by this
#      script rather than by eye, and none of them pulls in a third-party header
#      (the CI gate re-run against the copy a consumer actually reads);
#   3. a consumer that sees only the prefix configures, builds and RUNS, and the
#      run does real analyses across the boundary;
#   4. the consumer's configuration has to match the library's: against a Release
#      install, a Debug consumer must fail to compile naming the mismatch, and a
#      Release consumer must build, link and run. Only the configuration differs
#      between the two - which is the scenario "flipping the outcome by flipping
#      the consumer's config is not allowed" being checked rather than asserted;
#   5. the static core never reaches the consumer's link line and no internal name
#      lands in its executable: the same invariant the in-tree link-route rule
#      protects, checked where a host actually meets it.
#      "It built" is not evidence for that; the link line and the symbol table are.

foreach(required SHELLER_ROOT BUILD_DIR SNAPSHOT)
  if(NOT DEFINED "${required}" OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "install-consumer driver: -D${required} is required")
  endif()
endforeach()
foreach(must_exist SHELLER_ROOT BUILD_DIR SNAPSHOT)
  if(NOT EXISTS "${${must_exist}}")
    message(FATAL_ERROR "install-consumer driver: ${must_exist} does not exist: ${${must_exist}}")
  endif()
endforeach()

if(NOT DEFINED CONFIG OR CONFIG STREQUAL "")
  set(CONFIG Release)
endif()
if(CMAKE_HOST_WIN32)
  set(exe_suffix ".exe")
else()
  set(exe_suffix "")
endif()

set(PREFIX "${BUILD_DIR}/install-consumer-prefix")
set(WORK "${BUILD_DIR}/install-consumer-work")
set(LOGS "${WORK}/logs")
set(CONSUMER_SRC "${SHELLER_ROOT}/tests/install-consumer")

execute_process(COMMAND "${CMAKE_COMMAND}" -E rm -rf "${PREFIX}" "${WORK}")
execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${PREFIX}" "${WORK}" "${LOGS}")

function(step banner)
  message("")
  message("################ ${banner}")
endfunction()

function(show_command tag)
  string(REPLACE ";" " " shown "${ARGN}")
  message("  [${tag}] $ ${shown}")
endfunction()

# --------------------------------------------------------------------------- 0
step("0. what is being installed")
file(READ "${BUILD_DIR}/CMakeCache.txt" build_cache)
string(REGEX MATCH "CMAKE_GENERATOR:INTERNAL=([^\r\n]+)" _gen "${build_cache}")
set(GENERATOR "${CMAKE_MATCH_1}")
if(GENERATOR MATCHES "Visual Studio|Xcode")
  set(MULTI_CONFIG TRUE)
else()
  set(MULTI_CONFIG FALSE)
endif()
message("  source tree:  ${SHELLER_ROOT}")
message("  build tree:   ${BUILD_DIR}")
message("  generator:    '${GENERATOR}' (multi-config: ${MULTI_CONFIG})")
message("  config:       ${CONFIG}")
message("  prefix:       ${PREFIX}")
message("  replay input: ${SNAPSHOT}")

# --------------------------------------------------------------------------- 1
step("1. cmake --install")
set(install_cmd "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${PREFIX}")
if(MULTI_CONFIG)
  list(APPEND install_cmd --config "${CONFIG}")
endif()
show_command(install ${install_cmd})
execute_process(COMMAND ${install_cmd} RESULT_VARIABLE rc
  OUTPUT_VARIABLE out ERROR_VARIABLE err)
file(WRITE "${LOGS}/install.log" "${out}${err}")
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "install-consumer driver: cmake --install failed (rc=${rc}):\n${err}")
endif()
string(REGEX MATCHALL "-- Installing: [^\r\n]+" installed_lines "${out}")
list(LENGTH installed_lines installed_count)
message("  ${installed_count} file(s) installed:")
foreach(line IN LISTS installed_lines)
  string(REPLACE "-- Installing: " "    " line "${line}")
  file(TO_NATIVE_PATH "${PREFIX}" native_prefix)
  string(REPLACE "${native_prefix}/" "<prefix>/" line "${line}")
  string(REPLACE "${PREFIX}" "<prefix>" line "${line}")
  message("  ${line}")
endforeach()

# --------------------------------------------------------------------------- 2
step("2. the installed tree, checked by name")
file(GLOB_RECURSE source_headers RELATIVE "${SHELLER_ROOT}/include/sheller" "${SHELLER_ROOT}/include/sheller/*")
file(GLOB_RECURSE prefix_headers RELATIVE "${PREFIX}/include/sheller" "${PREFIX}/include/sheller/*")
list(SORT source_headers)
list(SORT prefix_headers)
list(LENGTH source_headers source_header_count)
list(LENGTH prefix_headers prefix_header_count)
message("  include/sheller: ${source_header_count} header(s) in the source tree, "
  "${prefix_header_count} in the prefix")
if(NOT source_headers STREQUAL prefix_headers)
  message(FATAL_ERROR
    "install-consumer driver: the installed header set is not the source tree's.\n"
    "  source: ${source_headers}\n"
    "  prefix: ${prefix_headers}")
endif()
message("  identical, name for name")

# The CI public-header boundary check (.github/workflows/linux.yml, "Public header
# boundary check") re-run against the installed copy with the same spellings. The
# source tree is already gated in ctest; this is the copy a consumer reads.
set(third_party "unicorn/|windows\\.h|spdlog/|gtest|fmt/|peconv")
set(boundary_hits "")
foreach(header IN LISTS prefix_headers)
  file(READ "${PREFIX}/include/sheller/${header}" text)
  string(REGEX MATCHALL "#[ \t]*include[ \t]*[<\"](${third_party})" hits "${text}")
  foreach(hit IN LISTS hits)
    string(APPEND boundary_hits "\n    ${header}: ${hit}")
  endforeach()
endforeach()
if(boundary_hits)
  message(FATAL_ERROR
    "install-consumer driver: third-party include in an installed public header:${boundary_hits}")
endif()
message("  no third-party include in any installed header")

foreach(expected
    "lib/cmake/sheller/shellerConfig.cmake"
    "lib/cmake/sheller/shellerConfigVersion.cmake"
    "lib/cmake/sheller/shellerTargets.cmake"
    "lib/cmake/sheller/shellerAbiConfig.cmake")
  if(NOT EXISTS "${PREFIX}/${expected}")
    message(FATAL_ERROR "install-consumer driver: package file missing: ${PREFIX}/${expected}")
  endif()
endforeach()
message("  package files present: config, version, targets, ABI literal")

# The prefix has to hold the delivery and nothing else. A test framework that
# ships its own install rules (googletest does) would otherwise land here silently
# - 63 gtest/gmock headers plus a competing GTestConfig.cmake appeared in the first
# run of this driver, which is the "the install is the library, the CLI and their
# dependencies" clause being broken by somebody else's CMakeLists.
file(GLOB top_entries RELATIVE "${PREFIX}" "${PREFIX}/*")
list(SORT top_entries)
string(REPLACE ";" " " top_shown "${top_entries}")
message("  prefix top level: ${top_shown}")
foreach(dir include lib bin)
  if(EXISTS "${PREFIX}/${dir}")
    file(GLOB_RECURSE found RELATIVE "${PREFIX}/${dir}" "${PREFIX}/${dir}/*")
    list(LENGTH found count)
    message("    ${dir}/: ${count} entr(ies)")
  endif()
endforeach()

file(GLOB include_dirs RELATIVE "${PREFIX}/include" "${PREFIX}/include/*")
file(GLOB cmake_dirs RELATIVE "${PREFIX}/lib/cmake" "${PREFIX}/lib/cmake/*")
list(SORT include_dirs)
list(SORT cmake_dirs)
set(unexpected "")
foreach(entry IN LISTS include_dirs)
  if(NOT entry STREQUAL "sheller")
    string(APPEND unexpected "\n    include/${entry}")
  endif()
endforeach()
foreach(entry IN LISTS cmake_dirs)
  get_filename_component(name "${entry}" NAME)
  if(NOT name STREQUAL "sheller")
    string(APPEND unexpected "\n    lib/cmake/${name}")
  endif()
endforeach()
if(unexpected)
  message(FATAL_ERROR
    "install-consumer driver: the prefix carries something that is not sheller:"
    "${unexpected}\n  A consumer that runs find_package() in this prefix would pick up"
    " another project's targets. Only the library, the CLI and their dependencies ship.")
endif()
message("  nothing but sheller in include/ and lib/cmake/")

# The runtime set, and the claim that what installed is what was built: a
# multi-config generator is exactly where installing the other configuration's DLL is
# easy to do and hard to notice. The expected set is spelled per platform:
# Windows ships three DLLs plus the CLI, POSIX ships the CLI and the library under
# lib/ (unicorn and Zydis are linked in there, so there is nothing to deploy).
if(CMAKE_HOST_WIN32)
  set(expected_bin "Zydis.dll;sheller.dll;sheller.exe;unicorn.dll")
  list(SORT expected_bin)
  file(GLOB_RECURSE prefix_bin RELATIVE "${PREFIX}/bin" "${PREFIX}/bin/*")
  list(SORT prefix_bin)
  message("  prefix bin/: ${prefix_bin}")
  if(NOT prefix_bin STREQUAL expected_bin)
    message(FATAL_ERROR "install-consumer driver: prefix bin/ is not the expected runtime set"
      "\n  expected: ${expected_bin}\n  found:    ${prefix_bin}")
  endif()
  if(MULTI_CONFIG)
    set(built_bin_dir "${BUILD_DIR}/src/cli/${CONFIG}")
    set(built_shared_dir "${BUILD_DIR}/src/shared/${CONFIG}")
  else()
    set(built_bin_dir "${BUILD_DIR}/src/cli")
    set(built_shared_dir "${BUILD_DIR}/src/shared")
  endif()
  foreach(name sheller.dll unicorn.dll Zydis.dll)
    set(built "${built_shared_dir}/${name}")
    if(NOT EXISTS "${built}")
      message(FATAL_ERROR "install-consumer driver: the build tree has no ${built} to compare with")
    endif()
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files "${PREFIX}/bin/${name}" "${built}"
      RESULT_VARIABLE same)
    if(NOT same EQUAL 0)
      message(FATAL_ERROR "install-consumer driver: <prefix>/bin/${name} is NOT the ${CONFIG}"
        " artifact in the build tree (${built}). The install picked up a different configuration.")
    endif()
    message("    ${name}: byte-identical to ${built}")
  endforeach()
  set(built_cli "${built_bin_dir}/sheller${exe_suffix}")
  if(NOT EXISTS "${built_cli}")
    message(FATAL_ERROR "install-consumer driver: the build tree has no ${built_cli}")
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files "${PREFIX}/bin/sheller${exe_suffix}"
    "${built_cli}" RESULT_VARIABLE same)
  if(NOT same EQUAL 0)
    message(FATAL_ERROR "install-consumer driver: the installed CLI is not the built one")
  endif()
  message("    sheller${exe_suffix}: byte-identical to ${built_cli}")
else()
  find_program(READELF_PROGRAM NAMES readelf)
  if(NOT READELF_PROGRAM)
    message(FATAL_ERROR "install-consumer driver: readelf not found, cannot check the SONAME face")
  endif()
  execute_process(COMMAND "${READELF_PROGRAM}" -d "${PREFIX}/lib/libsheller.so"
    OUTPUT_VARIABLE so_out ERROR_QUIET)
  string(REGEX MATCH "Library soname: \\[([^]]*)\\]" _son "${so_out}")
  set(installed_soname "${CMAKE_MATCH_1}")
  message("  installed libsheller.so SONAME: ${installed_soname}")
  if(NOT installed_soname MATCHES "^libsheller\\.so\\.[0-9]+$")
    message(FATAL_ERROR "install-consumer driver: the installed SONAME is"
      " \"${installed_soname}\" - it must be the library name plus the major version alone, or a"
      " patch release would require every consumer to re-link.")
  endif()
  foreach(want libsheller.so libsheller.so.0)
    if(NOT EXISTS "${PREFIX}/lib/${want}")
      message(FATAL_ERROR "install-consumer driver: ${want} missing from the prefix's lib/ - the"
        " three-name chain (link name, SONAME, versioned file) is part of the delivery")
    endif()
  endforeach()
  execute_process(COMMAND "${READELF_PROGRAM}" -d "${PREFIX}/bin/sheller"
    OUTPUT_VARIABLE cli_out ERROR_QUIET)
  string(REGEX MATCH "Shared library: \\[([^]]*)\\]" _nd "${cli_out}")
  message("  installed CLI NEEDED (first): ${CMAKE_MATCH_1}")
  string(REGEX MATCH "(RUNPATH|RPATH)[^]]*\\[([^]]*)\\]" _rp "${cli_out}")
  set(installed_runpath "${CMAKE_MATCH_2}")
  message("  installed CLI ${CMAKE_MATCH_1}: ${installed_runpath}")
  if(NOT CMAKE_MATCH_1 STREQUAL "RUNPATH")
    message(FATAL_ERROR "install-consumer driver: the installed CLI records no RUNPATH, so it"
      " cannot find the library next to the prefix without LD_LIBRARY_PATH")
  endif()
  if(NOT installed_runpath MATCHES "^\\$ORIGIN/\\.\\.")
    message(FATAL_ERROR "install-consumer driver: the installed CLI's RUNPATH is"
      " \"${installed_runpath}\" - it must be relative to the binary (\"\$ORIGIN/..\"), not a"
      " build directory that will not exist on the host.")
  endif()
  if(installed_runpath MATCHES "${BUILD_DIR}")
    message(FATAL_ERROR "install-consumer driver: the RUNPATH still names the build tree")
  endif()
endif()

file(READ "${PREFIX}/lib/cmake/sheller/shellerAbiConfig.cmake" abi_text)
string(REGEX MATCH "set\\(SHELLER_LIB_ABI_DEBUG_LITERAL ([01])\\)" _abi "${abi_text}")
set(abi_literal "${CMAKE_MATCH_1}")
message("  ABI literal in the package: SHELLER_LIB_ABI_DEBUG_LITERAL=${abi_literal} "
  "(installed config: ${CONFIG})")
if(CONFIG STREQUAL "Debug" AND NOT abi_literal STREQUAL "1")
  message(FATAL_ERROR "install-consumer driver: a Debug install wrote ${abi_literal}")
elseif(NOT CONFIG STREQUAL "Debug" AND NOT abi_literal STREQUAL "0")
  message(FATAL_ERROR "install-consumer driver: a ${CONFIG} install wrote ${abi_literal}")
endif()
# The exported interface must not carry a configuration-dependent spelling at
# all: whatever the consumer's generator expression would resolve to, it resolves
# in the consumer's configuration, which is the defect this package works around.
file(READ "${PREFIX}/lib/cmake/sheller/shellerTargets.cmake" targets_text)
if(targets_text MATCHES "SHELLER_LIB_ABI_DEBUG")
  message(FATAL_ERROR
    "install-consumer driver: the exported target interface still carries "
    "SHELLER_LIB_ABI_DEBUG, so a consumer's own configuration would decide what "
    "the ABI check reads. The BUILD_INTERFACE ring around it did not take.")
endif()
message("  exported target interface carries no SHELLER_LIB_ABI_DEBUG (it comes from the literal)")

# --------------------------------------------------------------------------- 3
step("3. a consumer that sees only the prefix")

# The shipped command line, run out of the prefix with no environment touched.
# On POSIX this is the rpath test: without CMAKE_INSTALL_RPATH the binary would
# still carry the build directory, and a prefix copied to another machine would
# not start.
set(installed_cli "${PREFIX}/bin/sheller${exe_suffix}")
if(NOT EXISTS "${installed_cli}")
  message(FATAL_ERROR "install-consumer driver: no CLI in the prefix: ${installed_cli}")
endif()
show_command(run ${installed_cli} --version)
# execute_process cannot scrub the environment, so the claim "no environment
# variable was set" is only true if the caller's own environment does not carry
# one. Say so rather than measure something else and call it the rpath.
if(DEFINED ENV{LD_LIBRARY_PATH} AND NOT "$ENV{LD_LIBRARY_PATH}" STREQUAL "")
  message(FATAL_ERROR "install-consumer driver: LD_LIBRARY_PATH is set in this environment"
    " ($ENV{LD_LIBRARY_PATH}); running the installed CLI would then prove nothing about the"
    " install rpath. Unset it and re-run.")
endif()
execute_process(COMMAND "${installed_cli}" --version RESULT_VARIABLE cli_rc
  OUTPUT_VARIABLE cli_out ERROR_VARIABLE cli_err)
string(STRIP "${cli_out}" cli_out)
message("  <prefix>/bin/sheller --version: rc=${cli_rc} \"${cli_out}\"")
if(cli_err)
  message("  > ${cli_err}")
endif()
if(NOT cli_rc EQUAL 0)
  message(FATAL_ERROR "install-consumer driver: the installed CLI does not run from the prefix."
    " On Linux this is the install rpath failing, not a cosmetic issue.")
endif()

# The same version the tree's own binary reports, so "the package carries the
# version project() declared" is a comparison and not a plausibility check.
if(MULTI_CONFIG)
  set(tree_cli "${BUILD_DIR}/src/cli/${CONFIG}/sheller${exe_suffix}")
else()
  set(tree_cli "${BUILD_DIR}/src/cli/sheller${exe_suffix}")
endif()
execute_process(COMMAND "${tree_cli}" --version RESULT_VARIABLE tree_rc
  OUTPUT_VARIABLE tree_out ERROR_QUIET)
string(STRIP "${tree_out}" tree_out)
message("  build tree CLI --version:            \"${tree_out}\"")
if(NOT tree_rc EQUAL 0)
  message(FATAL_ERROR "install-consumer driver: the build tree's own CLI did not run (rc=${tree_rc})")
endif()
if(NOT cli_out STREQUAL tree_out)
  message(FATAL_ERROR "install-consumer driver: the installed CLI says \"${cli_out}\" but the"
    " built one says \"${tree_out}\". The version a host reads is not the version this"
    " build produced.")
endif()
message("  identical, and no environment variable was set for it")
# The consumer's own configuration equals the library's here; step 4 flips only
# this one thing. On a single-config generator the configuration is a configure
# variable, on a multi-config one it is a build variable - which is why the two
# are tracked separately below.
set(other_config Debug)
if(CONFIG STREQUAL "Debug")
  set(other_config Release)
endif()
if(MULTI_CONFIG)
  set(good_build_config "${CONFIG}")
  set(good_exe_dir "${WORK}/matching/${CONFIG}")
else()
  set(good_build_config "")
  set(good_exe_dir "${WORK}/matching")
endif()

function(configure_consumer name build_type)
  set(dir "${WORK}/${name}")
  set(args -S "${CONSUMER_SRC}" -B "${dir}"
    "-DCMAKE_PREFIX_PATH=${PREFIX}" "-DCMAKE_BUILD_TYPE=${build_type}")
  if(MULTI_CONFIG)
    list(REMOVE_ITEM args "-DCMAKE_BUILD_TYPE=${build_type}")
  endif()
  show_command(configure ${args})
  execute_process(COMMAND "${CMAKE_COMMAND}" ${args} RESULT_VARIABLE rc
    OUTPUT_VARIABLE out ERROR_VARIABLE err)
  file(WRITE "${LOGS}/${name}-configure.log" "${out}${err}")
  set(CONF_RC "${rc}" PARENT_SCOPE)
  set(CONF_OUT "${out}${err}" PARENT_SCOPE)
  set(CONF_DIR "${dir}" PARENT_SCOPE)
endfunction()

function(build_consumer name dir configuration)
  set(args --build "${dir}")
  if(configuration)
    list(APPEND args --config "${configuration}")
  endif()
  show_command(build ${args})
  execute_process(COMMAND "${CMAKE_COMMAND}" ${args} RESULT_VARIABLE rc
    OUTPUT_VARIABLE out ERROR_VARIABLE err)
  file(WRITE "${LOGS}/${name}-build.log" "${out}${err}")
  set(BUILD_RC "${rc}" PARENT_SCOPE)
  set(BUILD_OUT "${out}${err}" PARENT_SCOPE)
endfunction()

configure_consumer(matching "${CONFIG}")
if(NOT CONF_RC EQUAL 0)
  message(FATAL_ERROR "install-consumer driver: the consumer failed to CONFIGURE against "
    "the prefix:\n  ${CONF_OUT}")
endif()
set(good_dir "${CONF_DIR}")
message("  configure: ok (${good_dir})")

build_consumer(matching "${good_dir}" "${good_build_config}")
if(NOT BUILD_RC EQUAL 0)
  message(FATAL_ERROR "install-consumer driver: the consumer failed to BUILD in ${CONFIG}:\n"
    "  ${BUILD_OUT}")
endif()
message("  build: ok (${CONFIG})")

# Placed in the prefix's own bin/, because include/sheller/export.h states that on
# Windows the third-party runtimes must sit next to the consumer's executable.
# Only the consumer's exe moves there - no library is copied - so a successful run
# is the installed runtime set carrying it.
set(good_exe "${good_exe_dir}/install_consumer${exe_suffix}")
if(NOT EXISTS "${good_exe}")
  message(FATAL_ERROR "install-consumer driver: built the consumer but cannot find it: ${good_exe}")
endif()
set(run_exe "${PREFIX}/bin/install_consumer${exe_suffix}")
execute_process(COMMAND "${CMAKE_COMMAND}" -E copy "${good_exe}" "${run_exe}")
message("  run (from <prefix>/bin; no environment variable set, and the only file copied in")
message("  is the consumer's own executable)")
show_command(run ${run_exe} "${SNAPSHOT}")
execute_process(COMMAND "${run_exe}" "${SNAPSHOT}" RESULT_VARIABLE rc
  OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 600)
file(WRITE "${LOGS}/consumer-run.log" "${out}${err}")
message("  run: rc=${rc}")
message("  | ${out}")
if(err)
  message("  > ${err}")
endif()
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "install-consumer driver: the installed consumer did not RUN (rc=${rc})")
endif()

# --------------------------------------------------------------------------- 4
step("4. flipping only the consumer's configuration flips the outcome")
if(CMAKE_HOST_WIN32)
  message("  (the debug/release check in include/sheller/export.h is an MSVC one:")
  message("  _ITERATOR_DEBUG_LEVEL is what changes the container layout there)")
  configure_consumer(mismatching "${other_config}")
  build_consumer(mismatching "${CONF_DIR}" "${other_config}")
  message("  build in ${other_config} against a ${CONFIG} library: rc=${BUILD_RC}")
  if(BUILD_RC EQUAL 0)
    message(FATAL_ERROR
      "install-consumer driver: a ${other_config} consumer COMPILED against a ${CONFIG} "
      "library. The ABI check is not firing from the installed tree, which is the defect "
      "this step exists to catch.")
  endif()
  if(other_config STREQUAL "Debug")
    set(expected_text "debug consumer against a release library")
  else()
    set(expected_text "release consumer against a debug library")
  endif()
  if(NOT BUILD_OUT MATCHES "${expected_text}")
    message(FATAL_ERROR
      "install-consumer driver: the ${other_config} consumer failed to build, but not for"
      " the reason this step is about - no \"${expected_text}\" in the diagnostics:\n"
      "  ${BUILD_OUT}")
  endif()
  message("  and it named the configuration mismatch, as the check promises")
else()
  # Only half of this step is MSVC-only. The debug/release comparison is: export.h
  # rings it with #if defined(_WIN32), because _ITERATOR_DEBUG_LEVEL is what changes
  # container layout there, and that half stays a recorded coverage gap on this
  # host. The _GLIBCXX_DEBUG comparison is not MSVC-only - it is the POSIX half of
  # the same header, its value is exported unconditionally (a constant, not a
  # configuration reading, which is why it did not need the BUILD_INTERFACE ring),
  # and export.h compares it with no platform ring around it. So it is testable
  # here, and skipping the whole step would have claimed a wider gap than the
  # header actually leaves.
  message("  debug/release comparison: NOT APPLICABLE on this host - export.h rings that")
  message("  one with #if defined(_WIN32), because _ITERATOR_DEBUG_LEVEL is an MSVC thing.")
  message("  _GLIBCXX_DEBUG comparison: applicable, and checked now.")
  set(glibcxx_dir "${WORK}/glibcxx-mismatch")
  set(glibcxx_args -S "${CONSUMER_SRC}" -B "${glibcxx_dir}"
    "-DCMAKE_PREFIX_PATH=${PREFIX}" "-DCMAKE_BUILD_TYPE=${CONFIG}"
    "-DCMAKE_CXX_FLAGS=-D_GLIBCXX_DEBUG")
  show_command(configure ${glibcxx_args})
  execute_process(COMMAND "${CMAKE_COMMAND}" ${glibcxx_args} RESULT_VARIABLE rc
    OUTPUT_VARIABLE out ERROR_VARIABLE err)
  file(WRITE "${LOGS}/glibcxx-configure.log" "${out}${err}")
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "install-consumer driver: the _GLIBCXX_DEBUG consumer failed to"
      " CONFIGURE, which is not the failure this step is about:\n  ${out}${err}")
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" --build "${glibcxx_dir}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  file(WRITE "${LOGS}/glibcxx-build.log" "${out}${err}")
  message("  build with -D_GLIBCXX_DEBUG against a library built without it: rc=${rc}")
  if(rc EQUAL 0)
    message(FATAL_ERROR
      "install-consumer driver: a consumer that enables _GLIBCXX_DEBUG COMPILED against a"
      " library built without it - the container layouts differ while the mangled names do"
      " not, which is the silent-corruption case export.h's check exists to stop.")
  endif()
  if(NOT "${out}${err}" MATCHES "_GLIBCXX_DEBUG")
    message(FATAL_ERROR
      "install-consumer driver: the _GLIBCXX_DEBUG consumer failed to build, but not for"
      " the reason this step is about - no \"_GLIBCXX_DEBUG\" in the diagnostics:\n"
      "  ${out}${err}")
  endif()
  message("  and it named _GLIBCXX_DEBUG, as the check promises")
endif()

# --------------------------------------------------------------------------- 5
step("5. the static core stays out of the consumer")
# 5a. the link line. What the linker was told to open, read out of the generated
# build system - not inferred from what "ought" to be there.
if(MULTI_CONFIG)
  set(project_file "${good_dir}/install_consumer.vcxproj")
  set(look_for "link libraries")
else()
  set(project_file "${good_dir}/CMakeFiles/install_consumer.dir/link.txt")
  set(look_for "link line")
endif()
if(NOT EXISTS "${project_file}")
  message(FATAL_ERROR "install-consumer driver: cannot find ${project_file} to read the link line")
endif()
file(READ "${project_file}" link_text)
# What the census searches and what the log shows are deliberately different
# scopes. The census searches everything the linker was told to open: this is a
# negative assertion, and a truncated window would quietly turn "no static core
# library is on this line" into a claim about the first 400 characters of it - the
# failure direction is a pass that did not happen. The display is truncated
# because a Ninja link line carries absolute paths twice (once as -rpath, once as
# the library itself) and the interesting fact is how little is on it.
# On a multi-config generator the scope is the AdditionalDependencies element,
# which is already the whole link input list; on a single-config one it is the
# entire link.txt.
string(REGEX MATCH "<AdditionalDependencies>[^<]*" link_scope "${link_text}")
if(NOT link_scope)
  set(link_scope "${link_text}")
endif()
string(LENGTH "${link_scope}" link_scope_len)
if(link_scope_len GREATER 400)
  string(SUBSTRING "${link_scope}" 0 400 link_shown)
  string(APPEND link_shown " ...(truncated for display; all ${link_scope_len} characters searched)")
else()
  set(link_shown "${link_scope}")
endif()
message("  consumer ${look_for} (${link_scope_len} characters searched): ${link_shown}")
set(core_libs "sheller_api;sheller_engine;sheller_capture;sheller_unpack;sheller_cli_render")
set(leaks "")
foreach(core IN LISTS core_libs)
  if(link_scope MATCHES "${core}")
    string(APPEND leaks "\n    ${core} is on the consumer's link line")
  endif()
endforeach()
if(leaks)
  message(FATAL_ERROR
    "install-consumer driver: a static core library reached the consumer:${leaks}"
    " - the linker would extract a second copy of the process state next to the shared"
    " library, and nothing in this tree's own build would show it.")
endif()
message("  none of the five static core libraries is on the consumer's link line")

# 5b. the symbol table of the built consumer. An extracted duplicate is exactly
# what the link line check above is meant to prevent, so the binary is inspected
# for the internal names, not taken at its word for having linked successfully.
if(CMAKE_HOST_WIN32)
  string(REGEX MATCH "CMAKE_LINKER:FILEPATH=([^\r\n]+)" _linker "${build_cache}")
  set(linker_path "${CMAKE_MATCH_1}")
  get_filename_component(linker_dir "${linker_path}" DIRECTORY)
  set(symbol_tool "${linker_dir}/dumpbin.exe")
  if(NOT EXISTS "${symbol_tool}")
    find_program(symbol_tool NAMES dumpbin)
  endif()
  if(NOT symbol_tool)
    message(FATAL_ERROR "install-consumer driver: dumpbin not found (CMAKE_LINKER=${linker_path})")
  endif()
  execute_process(COMMAND "${symbol_tool}" /symbols "${good_exe}"
    OUTPUT_VARIABLE sym_out ERROR_VARIABLE sym_err)
  file(WRITE "${LOGS}/consumer-symbols.txt" "${sym_out}${sym_err}")
  # The same four names the POSIX census looks for, in the spelling this toolchain
  # prints them in: dumpbin shows decorated names, and a decorated name still
  # carries the identifier text, so log_state / set_sink_impl /
  # unpack_sample_impl are found by what they are called. The namespace cannot be
  # matched as "sheller::engine::" here - "@engine@" is what that looks like after
  # mangling, and it catches any name in it.
  set(internal_patterns "@engine@" "log_state" "set_sink_impl" "unpack_sample_impl")
  set(hits "")
  foreach(pattern IN LISTS internal_patterns)
    string(REGEX MATCHALL "[^\r\n]*${pattern}[^\r\n]*" found "${sym_out}")
    list(LENGTH found n)
    if(NOT n EQUAL 0)
      string(APPEND hits "\n    ${pattern}: ${n} hit(s), e.g. ${found}")
    endif()
  endforeach()
  string(REGEX MATCHALL "\n" sym_lines "${sym_out}")
  list(LENGTH sym_lines sym_count)
  message("  dumpbin /symbols read ${sym_count} line(s) for ${good_exe}")
  if(hits)
    message(FATAL_ERROR "install-consumer driver: internal names in the consumer's symbol"
      " table:${hits}")
  endif()
  message("  no internal name (@engine@ members, log_state, set_sink_impl,"
    " unpack_sample_impl) is present")
  if(sym_count LESS 100)
    message("  CAVEAT: dumpbin read only ${sym_count} line(s), so this executable carries no")
    message("  usable COFF symbol table (a Release link without debug info). The absence of")
    message("  internal names above is therefore weak evidence on its own on Windows - and")
    message("  measured, the duplicate this check guards against was extracted by the GNU")
    message("  linker, while MSVC put the archive on the link line and pulled nothing")
    message("  out. The link line above and the import table below are the load-bearing")
    message("  checks on this platform; the symbol census is the load-bearing one on Linux.")
  endif()
  execute_process(COMMAND "${symbol_tool}" /imports "${good_exe}"
    OUTPUT_VARIABLE imp_out ERROR_VARIABLE imp_err)
  file(WRITE "${LOGS}/consumer-imports.txt" "${imp_out}${imp_err}")
  string(REGEX MATCH "sheller\\.dll[^\r\n]*(\r?\n([ \t]+[^\r\n]*)?)*" imp_block "${imp_out}")
  # The two entries this consumer actually calls. Named here rather than counted as
  # "any substring that looks like a product name", because a loose substring list
  # can hit on unrelated text and report a proof that did not happen.
  set(product_names "unicorn_version_string" "analyze")
  set(imported "")
  foreach(name IN LISTS product_names)
    if(imp_block MATCHES "${name}")
      list(APPEND imported "${name}")
    endif()
  endforeach()
  list(LENGTH imported imported_count)
  message("  product names the consumer imports out of sheller.dll: ${imported}")
  if(NOT imported_count EQUAL 2)
    message(FATAL_ERROR "install-consumer driver: the consumer's import table does not show both"
      " entries it calls (${imported_count} of 2). Either the link went somewhere else or the"
      " pattern stopped matching what it matches today - full table in"
      " ${LOGS}/consumer-imports.txt")
  endif()
  message("  so the product names cross the DLL boundary rather than being defined inside the"
    " executable, which is what 'no second copy of the core' looks like on this platform")
  execute_process(COMMAND "${symbol_tool}" /dependents "${good_exe}"
    OUTPUT_VARIABLE dep_out ERROR_VARIABLE dep_err)
  file(WRITE "${LOGS}/consumer-dependents.txt" "${dep_out}${dep_err}")
  message("  DLLs the consumer actually resolves at load:")
  string(REGEX MATCHALL "[A-Za-z0-9_.-]+\\.dll" dlls "${dep_out}")
  list(REMOVE_DUPLICATES dlls)
  foreach(dll IN LISTS dlls)
    message("    ${dll}")
  endforeach()
  if(NOT dlls MATCHES "sheller\\.dll")
    message(FATAL_ERROR "install-consumer driver: the consumer does not depend on sheller.dll")
  endif()
else()
  find_program(symbol_tool NAMES nm REQUIRED)
  execute_process(COMMAND "${symbol_tool}" -C "${good_exe}"
    OUTPUT_VARIABLE sym_out ERROR_VARIABLE sym_err)
  file(WRITE "${LOGS}/consumer-symbols.txt" "${sym_out}${sym_err}")
  set(patterns "sheller::engine::" "log_state" "set_sink_impl" "unpack_sample_impl")
  # Only a DEFINED symbol can be a copy of the core, so only defined symbol
  # classes are counted (T D B R and their local t d b r). A weak definition of a
  # sheller::engine:: name inside the consumer's own binary is a public-header
  # instantiation, not a second core: AnalysisOptions holds an
  # engine::SyscallRunOptions member (include/sheller/analysis.h) and the
  # std::function overloads name engine::BehaviorFact, so those thunks are
  # emitted into the consumer's translation unit. Measured in this tree: a
  # binary that really links and calls the core carries those names as defined
  # symbols (iat_repair_test: 35 T + 1828 t; engine_diag_test: 7 t), which is
  # what this census has to keep seeing.
  set(hits "")
  foreach(pattern IN LISTS patterns)
    string(REGEX MATCHALL "\n[0-9a-f]+ (T|D|B|R|t|d|b|r) [^\r\n]*${pattern}[^\r\n]*" found "\n${sym_out}")
    list(LENGTH found n)
    if(NOT n EQUAL 0)
      string(APPEND hits "\n    ${pattern}: ${n} hit(s), e.g. ${found}")
    endif()
  endforeach()
  string(REGEX MATCHALL "\n" all_lines "${sym_out}")
  list(LENGTH all_lines sym_count)
  string(REGEX MATCHALL "\n[0-9a-f]+ (W|V) [^\r\n]*sheller::engine::[^\r\n]*" weak_lines "\n${sym_out}")
  list(LENGTH weak_lines weak_count)
  message("  nm -C read ${sym_count} symbol line(s) for ${good_exe}")
  message("  ${weak_count} weak (W/V) sheller::engine:: line(s): the consumer's own"
    " instantiations of the public-header types, not counted as the core")
  if(hits)
    message(FATAL_ERROR "install-consumer driver: internal names DEFINED in the consumer's"
      " symbol table:${hits}")
  endif()
  message("  no internal name (sheller::engine::*, log_state, set_sink_impl,"
    " unpack_sample_impl) is defined in the consumer's executable")
  # The clean answer above is only evidence if this census can still see the core when
  # the core really is there - "found nothing" and "cannot find anything" print the
  # same thing otherwise. So run the identical regex against an in-tree binary that
  # links the static core and calls into it, and require it to light up.
  set(control_exe "")
  foreach(candidate iat_repair_test engine_diag_test log_test)
    if(EXISTS "${BUILD_DIR}/tests/${candidate}")
      set(control_exe "${BUILD_DIR}/tests/${candidate}")
      break()
    endif()
  endforeach()
  if(control_exe)
    execute_process(COMMAND "${symbol_tool}" -C "${control_exe}"
      OUTPUT_VARIABLE ctl_out ERROR_QUIET)
    set(ctl_hits 0)
    foreach(pattern IN LISTS patterns)
      string(REGEX MATCHALL "\n[0-9a-f]+ (T|D|B|R|t|d|b|r) [^\r\n]*${pattern}[^\r\n]*"
        ctl_found "\n${ctl_out}")
      list(LENGTH ctl_found ctl_n)
      math(EXPR ctl_hits "${ctl_hits} + ${ctl_n}")
    endforeach()
    if(ctl_hits EQUAL 0)
      message(FATAL_ERROR "install-consumer driver: the internal-name census found nothing in "
        "${control_exe}, a binary that links and calls the static core. The census has gone"
        " blind, so the clean consumer result above proves nothing.")
    endif()
    message("  positive control: the same census reads ${ctl_hits} defined internal name(s)"
      " in ${control_exe} - it can still see the core")
  else()
    message("  positive control: NOT RUN - no in-tree core-linked test binary under"
      " ${BUILD_DIR}/tests, so the clean consumer result above is unverified, not evidence")
  endif()
endif()

message("")
message("install-consumer driver: every step above passed. Logs in ${LOGS}.")
