cmake_minimum_required(VERSION 3.24)

project(sheller VERSION 0.1.0 LANGUAGES CXX)

if(WIN32)
  set(SHELLER_CLI_FILE_NAME "sheller.exe")
else()
  set(SHELLER_CLI_FILE_NAME "sheller")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Where an installed sheller puts things. The directories are asked for rather
# than written down because "lib" is wrong on the distributions that ship
# 64-bit libraries in lib64 - a hardcoded path installs to a place the loader
# on that host does not look in.
include(GNUInstallDirs)

# The installed CLI has to find the installed library without anybody setting
# LD_LIBRARY_PATH, so the install tree carries a relocatable search path relative
# to the binary. The build tree keeps CMake's own build RPATH (which points at
# the build directory and must not be rewritten here), and
# CMAKE_INSTALL_RPATH_USE_LINK_PATH stays off so nothing from this machine's
# vcpkg tree gets baked into a shipped binary.
if(NOT MSVC)
  set(CMAKE_INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH OFF)
endif()

option(SHELLER_BUILD_TESTS "Build sheller tests" ON)

include(FetchContent)

# unicorn comes from the vcpkg toolchain (see vcpkg.json / CMakePresets.json).
# Prefer the release lib explicitly: in multi-config generators find_library can
# otherwise land in the debug/ directory of the vcpkg installed tree.
find_path(SHELLER_UNICORN_INCLUDE_DIR NAMES unicorn/unicorn.h REQUIRED)
find_library(SHELLER_UNICORN_LIBRARY NAMES unicorn
  PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib"
  NO_DEFAULT_PATH)
if(NOT SHELLER_UNICORN_LIBRARY)
  find_library(SHELLER_UNICORN_LIBRARY NAMES unicorn REQUIRED)
endif()
message(STATUS "sheller: unicorn include: ${SHELLER_UNICORN_INCLUDE_DIR}")
message(STATUS "sheller: unicorn library: ${SHELLER_UNICORN_LIBRARY}")

find_package(CLI11 CONFIG REQUIRED)

# zydis (v4) powers the loop-gate static scan: a pure decoder with no heap
# allocation and no global state, matching the hook hot-path discipline.
find_package(Zydis CONFIG REQUIRED)

# xxhash binds the directory-mode boundary manifest and API Set map to their
# input images (whole-file xxhash64 anchors, design D2/D5 of
# real-dll-module-dir).
find_package(xxHash CONFIG REQUIRED)

# Warnings-as-errors and hardening flags apply to first-party targets only
# (rationale lives in CONTRIBUTING.md).
function(sheller_apply_common target)
  target_compile_features(${target} PUBLIC cxx_std_23)
  set_target_properties(${target} PROPERTIES COMPILE_WARNING_AS_ERROR ON)
  if(MSVC)
    # /guard:cf- is explicit on purpose: unicorn2's TCG crashes in a
    # CFG-enabled host process (upstream unicorn-engine#2281,
    # pyinstaller#9352), and every engine binary executes TCG-generated code
    # in-process - re-enabling the flag reintroduces that crash.
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:preprocessor /guard:cf-)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Release,MinSizeRel,RelWithDebInfo>:-D_FORTIFY_SOURCE=2>)
  endif()
endfunction()

# The static core: the libraries the shared interface library links in. Two
# extra properties follow from that:
#   * POSITION_INDEPENDENT_CODE - their objects land inside a .so, and on
#     Windows it costs nothing (everything is already PIC there).
#   * hidden visibility on non-MSVC - the product surface is the six
#     SHELLER_API declarations in src/shared, and -fvisibility=hidden is what
#     makes that the *only* thing the dynamic symbol table can carry. Static
#     consumers (the CLI, the direct-link test suites) are unaffected: hidden
#     only keeps a symbol out of the dynamic table, the archive member still
#     resolves. MSVC has no equivalent - there dllexport/dllimport decides.
function(sheller_apply_static_core target)
  sheller_apply_common(${target})
  set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  if(NOT MSVC)
    target_compile_options(${target} PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
  endif()
endfunction()

# Engine discipline: no throw/try/catch *statement* in an engine translation
# unit, enforced by tests/engine_nothrow_gate.cmake - not by -fno-exceptions.
# Measured on g++-13 (-O0/-O2/-Os agree): compiling a TU with -fno-exceptions
# does not stop an exception from getting past it - GCC still emits .eh_frame,
# the frame carries no personality routine so the unwinder treats the frame as
# transparent, and even a noexcept intermediate frame is skipped - but the
# destructors of the locals in that frame do not run (measured 0/2, and 2/2 for
# the same model compiled with exceptions on). So the flag bought a compile-time
# guarantee while costing the cleanup: an escaping std::bad_alloc or a failed
# bounds check would leave the unicorn instance and the capture temporaries
# behind, once per failure. These targets therefore keep unwind info and stay
# throw-free at the source level, and the export layer contains whatever escapes
# (src/shared). Host-side targets (cli/, tests/) keep exceptions.
add_library(sheller_engine STATIC)
target_include_directories(sheller_engine
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
# SYSTEM keeps unicorn/spdlog-style third-party headers out of warning diagnostics.
target_include_directories(sheller_engine SYSTEM PRIVATE ${SHELLER_UNICORN_INCLUDE_DIR})
target_link_libraries(sheller_engine PUBLIC ${SHELLER_UNICORN_LIBRARY})
target_link_libraries(sheller_engine PUBLIC Zydis::Zydis)
target_link_libraries(sheller_engine PUBLIC xxHash::xxhash)
if(MSVC)
  target_compile_options(sheller_engine PRIVATE /external:W0)
endif()
sheller_apply_static_core(sheller_engine)

add_subdirectory(src/engine)
add_subdirectory(src/syscalls)
add_subdirectory(src/behavior)
add_subdirectory(src/loader)
add_subdirectory(src/unpack)
add_subdirectory(src/runtime)
# The facade library links engine + unpack + capture; it must stay outside
# sheller_engine (unpack's PRIVATE engine link would become a cycle).
add_subdirectory(src/api)
# The shared interface library: the product surface, one translation unit that
# forwards to the facade above. Before src/cli because the CLI links it.
add_subdirectory(src/shared)
add_subdirectory(src/cli)

# The engine reads snapshot files through the capture module's portable
# Reader (engine -> capture; capture never links engine, so no cycle, and
# the capture target keeps its zero-unicorn include path).
target_link_libraries(sheller_engine PRIVATE sheller_capture)

# ---------------------------------------------------------------------------
# Delivery surface: what `cmake --install` hands to a host that cannot read this
# source tree (specs/delivery-surface). The library and the CLI are installed by
# their own directories; the package files, the headers and the literal that
# carries the library's build configuration are assembled here, because that is
# the one place that sees the whole prefix.
include(CMakePackageConfigHelpers)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/shellerConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/shellerConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/sheller")
# SameMajorVersion is the same promise the SONAME makes: nothing breaks inside a
# major version, and a change that does has to raise the major in the same commit.
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/shellerConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/shellerConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/shellerConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/sheller")

install(EXPORT shellerTargets
  NAMESPACE sheller::
  FILE shellerTargets.cmake
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/sheller")

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/sheller"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# The library's own configuration, spelled as a literal in the package.
# $<CONFIG:Debug> inside install(CODE) is evaluated against the configuration
# being installed - measured, on a Visual Studio multi-config generator and on
# Ninja - which is what makes this a statement about the library rather than about
# whoever consumes it.
# Writing (not appending) keeps a prefix that is installed twice with two
# configurations coherent: the last install is the one whose library is there.
install(CODE "
if(\"$<CONFIG:Debug>\" STREQUAL \"1\")
  set(sheller_abi_debug_literal 1)
else()
  set(sheller_abi_debug_literal 0)
endif()
file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake/sheller/shellerAbiConfig.cmake\" \"
# Written by the install step of the sheller build that put this library here.
# Not hand-editable: it is the only truthful record, in an installed tree, of
# which configuration the library was compiled in.
set(SHELLER_LIB_ABI_DEBUG_LITERAL \${sheller_abi_debug_literal})
\")
")

if(SHELLER_BUILD_TESTS)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.18.0)
  enable_testing()
  add_subdirectory(tests)
endif()
