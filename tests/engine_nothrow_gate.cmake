# Engine no-throw gate: an engine translation unit must contain no throw, try
# or catch *statement*. The discipline used to be a compile flag
# (-fno-exceptions); it is a gate now because the flag turned out to be the
# wrong trade. Measured on g++-13 (-O0/-O2/-Os agree): a -fno-exceptions frame
# neither stops an exception - GCC still emits .eh_frame, the frame carries no
# personality routine so the unwinder treats it as transparent and an outer
# catch still catches, even through a noexcept intermediate frame - nor does it
# clean up: the destructors of the locals in that frame do not run (0/2
# measured, 2/2 for the same model compiled with exceptions on). So the engine
# keeps its unwind info, this script holds the source-level rule, and the export
# layer (src/shared) is what contains an escaping exception.
#
# Matching strips comments first and then anchors each keyword to a word boundary.
# That order is not cosmetic: these files talk about exceptions in comments
# constantly - "never throw", "catch funclet", "catch-all" - and the earlier build of
# this rule kept the prose out by requiring the keyword to start its line instead.
# Anchoring was therefore doing the job of comment stripping, and it also hid every
# statement that did not begin a line. Measured on the current tree: a plain token
# scan finds 21 lines, the comment stripper leaves exactly the 4 statements the
# allowlist covers - the engine's two host-callback delivery points, one try and
# one catch each - so the two numbers printed in the summary differ by the prose and
# by nothing else. Both rulers are reported so "zero hits" is always a statement about
# a defined ruler rather than about a grep that happened to find nothing.
#
# Invoked as a ctest command (see tests/CMakeLists.txt):
#   -DGATE_ROOT=<project source dir>
#   -DGATE_SOURCE_LIST=<generated file: one engine source path per line,
#                       relative to GATE_ROOT, the union of both platforms>
#   -DGATE_ALLOWLIST=<checked-in file: <path>:<pattern-id> per line>
#
# A missing or empty source list is a hard error, and so is a listed path that no
# longer exists: the list is generated from the build system, so a stale entry
# means that step and this script have drifted apart - exactly the way a gate
# goes quietly blind.

# Script mode (-P) inherits no cmake_minimum_required, so on CMake below 4 the
# policies default to OLD and IN_LIST stops being an operator. Say it explicitly
# - the gate has to behave the same on 3.25 (WSL), 3.28 (CI) and 4.x (local
# Windows), and a silently-OLD policy is how a gate goes green on one host and
# broken on another.
cmake_policy(SET CMP0057 NEW)
include("${CMAKE_CURRENT_LIST_DIR}/engine_gate_lines.cmake")

foreach(required GATE_ROOT GATE_SOURCE_LIST GATE_ALLOWLIST)
  if(NOT DEFINED "${required}" OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "engine_nothrow gate: -D${required} is required")
  endif()
endforeach()
foreach(must_exist GATE_SOURCE_LIST GATE_ALLOWLIST)
  if(NOT EXISTS "${${must_exist}}")
    message(FATAL_ERROR
      "engine_nothrow gate: ${must_exist} not found: ${${must_exist}} "
      "(re-run the configure step)")
  endif()
endforeach()

# Pattern id -> regex. A word boundary is written as a negated class, not as
# \b, on purpose: CMake's regex treats \b as a backspace escape rather than as
# an anchor (measured on 3.25 and 4.4 - a \b pattern matches nothing in a tree
# that plainly contains the words), and a gate whose anchor silently degrades is
# worse than no gate. The three ids are the three keywords the rule names, kept
# apart because the allowlisted files earn the first and the third and not the
# second: each of them may contain a handler, none of them may throw.
#
# No line-initial anchor: the rule is about the keyword, and a form of it that
# happens to sit at column one is not more legal than the same form mid-line. The
# anchor was previously doing the job of comment stripping - "never throw", "the
# catch-all funclet" and the rest of the prose in these files is why - so the scan
# strips comments (gate_strip_comments) and the patterns are free to match wherever
# the keyword appears. Measured: `[] { throw 1; }`, which
# clang-format leaves on one line, `if (true) throw 1;` and `int p = 0; throw p;`
# all passed the anchored form, so the ban had a spelling that evaded it.
set(try_pattern   "(^|[^A-Za-z0-9_])try([^A-Za-z0-9_]|$)")
set(throw_pattern "(^|[^A-Za-z0-9_])throw([^A-Za-z0-9_]|$)")
set(catch_pattern "(^|[^A-Za-z0-9_])catch([^A-Za-z0-9_]|$)")
# The same three words without stripping comments, reported alongside the counts so
# a reader can see how much of the tree's prose the stripper is absorbing. A gap
# between the two numbers that is not comment text is a bug in the stripper.
set(naive_pattern "(^|[^A-Za-z0-9_])(try|throw|catch)([^A-Za-z0-9_]|$)")
set(pattern_ids try throw catch)

# ------------------------------------------------------------------ allowlist
# One entry per line: "<source path>:<pattern id>", path relative to GATE_ROOT.
# The id scopes the exemption to that one pattern, so an allowlisted file gets
# the clause it earns and still may not throw.
file(STRINGS "${GATE_ALLOWLIST}" allowlist_raw)
set(allowlist "")
foreach(line IN LISTS allowlist_raw)
  string(STRIP "${line}" entry)
  if(entry AND NOT entry MATCHES "^#")
    list(APPEND allowlist "${entry}")
  endif()
endforeach()

# ---------------------------------------------------------------------- the scan
file(STRINGS "${GATE_SOURCE_LIST}" sources_raw)
set(sources "")
foreach(line IN LISTS sources_raw)
  string(STRIP "${line}" entry)
  if(entry AND NOT entry MATCHES "^#")
    list(APPEND sources "${entry}")
  endif()
endforeach()
list(LENGTH sources source_count)
if(NOT source_count)
  message(FATAL_ERROR "engine_nothrow gate: ${GATE_SOURCE_LIST} lists no source file")
endif()

set(translations 0)
set(statement_hits 0)
set(violation_count 0)
set(naive_hits 0)
set(violations "")

foreach(entry IN LISTS sources)
  if(entry MATCHES "\\.cpp$")
    math(EXPR translations "${translations} + 1")
  endif()

  set(path "${GATE_ROOT}/${entry}")
  if(NOT EXISTS "${path}")
    message(FATAL_ERROR "engine_nothrow gate: listed source does not exist: ${entry}")
  endif()

  # The exact walker, not file(STRINGS) and not a list of lines: engine_gate_lines.cmake
  # records what both do to real source. The walk visits every physical line, so
  # the number reported is the number a reader sees in the file.
  file(READ "${path}" blob)
  string(REGEX REPLACE "\r" "" blob "${blob}")
  set(in_block FALSE)
  set(number 0)
  set(walk TRUE)
  while(walk)
    gate_next_line("${blob}" line blob at_end)
    if(line STREQUAL "" AND at_end)
      break()
    endif()
    math(EXPR number "${number} + 1")
    if(line MATCHES "${naive_pattern}")
      math(EXPR naive_hits "${naive_hits} + 1")
    endif()
    # The keywords are matched in code, not in prose: comments carry the
    # documentation that discusses this very rule.
    gate_strip_comments("${line}" "${in_block}" scanned in_block)
    if(scanned STREQUAL "")
      continue()
    endif()
    foreach(id IN LISTS pattern_ids)
      set(pattern "${${id}_pattern}")
      if(NOT scanned MATCHES "${pattern}")
        continue()
      endif()
      math(EXPR statement_hits "${statement_hits} + 1")
      set(item "${entry}:${id}")
      if(item IN_LIST allowlist)
        continue()
      endif()
      math(EXPR violation_count "${violation_count} + 1")
      string(REPLACE ";" "," shown_line "${line}")
      string(APPEND violations
        "\n  ${entry}:${number}: ${shown_line}\n    (keyword pattern \"${pattern}\", "
        "allowlist entry would be ${item})")
    endforeach()
  endwhile()
endforeach()

if(violations)
  message(FATAL_ERROR
    "engine_nothrow gate: ${violation_count} of ${statement_hits} throw/try/catch "
    "statement(s) in the ${source_count} engine source file(s) are not on the "
    "allowlist:"
    "${violations}\n"
    "  An engine frame carries no exception mechanism: the export layer "
    "(src/shared) is where an escaping exception gets contained, and the sweep "
    "that keeps this rule is the no-throw discipline itself. Report the failure "
    "through the channel the file already uses instead. If a file genuinely has "
    "to be the exception, add it to ${GATE_ALLOWLIST} with the reason.")
endif()

list(LENGTH allowlist allowlist_count)
message(STATUS
  "engine_nothrow gate: ${source_count} engine source file(s) scanned "
  "(${translations} translation units), ${statement_hits} statement hit(s), "
  "${naive_hits} naive token hit(s) - comments, not violations - "
  "${allowlist_count} allowlist entry(ies)")
