# Engine .at() ratchet: bounds-checked subscripting in the engine sources is
# registered per file as "path count", and a file that carries more than its
# registered number fails. A count, not a per-site list: the call text repeats
# (seh_dispatcher.cpp alone has 32) and line numbers move with every edit, so an
# identity-based allowlist would need re-maintenance on unrelated changes and
# would get skipped when it mattered.
#
# Direction of the ratchet: the number can only go down. Lower than the register
# is reported in the summary so the table gets tightened - a registry that drifts
# above reality stops guarding the line where a new .at() would be caught.
#
# The classification behind each baseline number is guest-controlled /
# internal invariant / constant lookup, with the evidence per site. A new .at()
# in a file needs that classification decided first, not a bigger number here.
#
# INVOCATION (a ctest command, see tests/CMakeLists.txt):
#   -DGATE_ROOT=<project source dir>
#   -DGATE_SOURCE_LIST=<generated file: engine source paths, one per line>
#   -DGATE_AT_TABLE=<checked-in table: "<path> <count>" per line>

cmake_policy(SET CMP0057 NEW)
include("${CMAKE_CURRENT_LIST_DIR}/engine_gate_lines.cmake")

foreach(required GATE_ROOT GATE_SOURCE_LIST GATE_AT_TABLE)
  if(NOT DEFINED "${required}" OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "engine_at_sites gate: -D${required} is required")
  endif()
endforeach()
foreach(must_exist GATE_SOURCE_LIST GATE_AT_TABLE)
  if(NOT EXISTS "${${must_exist}}")
    message(FATAL_ERROR
      "engine_at_sites gate: ${must_exist} not found: ${${must_exist}} "
      "(re-run the configure step)")
  endif()
endforeach()

# --------------------------------------------------------------------- the table
file(STRINGS "${GATE_AT_TABLE}" table_raw)
set(registered "")
foreach(line IN LISTS table_raw)
  string(STRIP "${line}" entry)
  if(entry AND NOT entry MATCHES "^#")
    string(REGEX REPLACE "[ \t]+.*$" "" path "${entry}")
    string(REGEX REPLACE "^.*[ \t]" "" count "${entry}")
    if(NOT count MATCHES "^[0-9]+$")
      message(FATAL_ERROR
        "engine_at_sites gate: table entry without a numeric count: ${entry}")
    endif()
    list(APPEND registered "${path}=${count}")
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
  message(FATAL_ERROR "engine_at_sites gate: ${GATE_SOURCE_LIST} lists no source file")
endif()

set(total 0)
set(failures "")
set(stale "")
set(under "")
set(seen "")
foreach(item IN LISTS registered)
  string(REPLACE "=" ";" item_parts "${item}")
  list(GET item_parts 0 path)
  list(GET item_parts 1 limit)
  if(NOT path IN_LIST sources)
    list(APPEND stale "${path} is registered but no longer an engine source")
    continue()
  endif()
  set(actual 0)
  file(READ "${GATE_ROOT}/${path}" blob)
  string(REGEX REPLACE "\r" "" blob "${blob}")
  set(walk TRUE)
  while(walk)
    gate_next_line("${blob}" line blob at_end)
    if(line STREQUAL "" AND at_end)
      break()
    endif()
    # Occurrences, not lines: two .at() calls on one line are two bounds-checked
    # subscripts, and counting the line made the second one free (measured - the
    # gate stayed green and still printed "each at its registered count").
    string(REGEX MATCHALL "[.]at\\(" at_hits "${line}")
    list(LENGTH at_hits at_count)
    math(EXPR actual "${actual} + ${at_count}")
  endwhile()
  math(EXPR total "${total} + ${actual}")
  list(APPEND seen "${path}")
  if(actual GREATER limit)
    string(APPEND failures
      "\n  ${path}: registered ${limit}, actual ${actual} - new bounds-checked "
      "subscripting in an engine TU. Classify it in the .at() audit first "
      "(guest-controlled indices take an explicit check plus the file's own failure "
      "channel, not another .at()).")
  elseif(actual LESS limit)
    list(APPEND under "${path}: registered ${limit}, actual ${actual}")
  endif()
endforeach()

# Anything with .at() that the table does not name is a new file in the discipline -
# it has no registered allowance, so any count is over budget.
foreach(entry IN LISTS sources)
  if(entry IN_LIST seen)
    continue()
  endif()
  set(actual 0)
  file(READ "${GATE_ROOT}/${entry}" blob)
  string(REGEX REPLACE "\r" "" blob "${blob}")
  set(walk TRUE)
  while(walk)
    gate_next_line("${blob}" line blob at_end)
    if(line STREQUAL "" AND at_end)
      break()
    endif()
    # Occurrences, not lines: two .at() calls on one line are two bounds-checked
    # subscripts, and counting the line made the second one free (measured - the
    # gate stayed green and still printed "each at its registered count").
    string(REGEX MATCHALL "[.]at\\(" at_hits "${line}")
    list(LENGTH at_hits at_count)
    math(EXPR actual "${actual} + ${at_count}")
  endwhile()
  math(EXPR total "${total} + ${actual}")
  if(actual GREATER 0)
    string(APPEND failures
      "\n  ${entry}: ${actual} .at() call(s) and no table entry - register the file "
      "with its classification, or drop the bounds-checked subscript.")
  endif()
endforeach()

if(stale OR failures)
  set(report "engine_at_sites gate: the .at() ratchet is broken")
  foreach(item IN LISTS failures)
    string(APPEND report "${item}")
  endforeach()
  foreach(item IN LISTS stale)
    string(APPEND report "\n  STALE ENTRY ${item} - remove it")
  endforeach()
  message(FATAL_ERROR "${report}")
endif()

list(LENGTH registered registered_count)
if(under)
  message(STATUS
    "engine_at_sites gate: ${source_count} file(s) scanned, ${total} .at() in ${registered_count} "
    "registered file(s); tighten the table for: ${under}")
else()
  message(STATUS
    "engine_at_sites gate: ${source_count} file(s) scanned, ${total} .at() across "
    "${registered_count} registered file(s), each at its registered count")
endif()
