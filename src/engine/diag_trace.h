// Engine diagnostic traces. The log facade is the only way a diagnostic may leave
// this library - the host installs the sink, sets the threshold, and can silence the
// whole stream - so the traces that used to fprintf(stderr, ...) are routed here, and
// this header is the spelling that makes "send it to the host's stream" impossible to
// reach by accident.
//
// Two conditions gate a record, and both are checked before anything is rendered:
//   * the site switch - the environment variable this trace has always had, cached in
//     a function-local static because these paths run once per guest instruction and a
//     getenv per record would add an allocation and a lock to a hook path. It is
//     therefore a once-per-process decision: a test that wants a switch set has to set
//     it before the first record, which is what tests/engine_trace_test.cpp's main()
//     does.
//   * the host's threshold - log::would_log(), so a disabled host costs no rendering.
//
// Which is the contract the default path keeps: with the switch off, a trace site is
// one bool; with the switch on but the host's threshold above the record, one bool
// plus one would_log(); and std::format - the only allocation - runs for a record
// somebody asked for.
#pragma once

#include <sheller/log.h>

#include <cstdlib>
#include <format>
#include <string_view>
#include <utility>

namespace sheller::engine::diag {

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // the cached getenv is the point of these switches
#endif

// Exception-dispatch traces ([seh-diag], [seh-step], [seh-cb], and the per-instruction
// fidelity hooks that are installed only under this switch).
inline bool seh_on()
{
    static const bool on = std::getenv("SHELLER_SEH_TRACE") != nullptr;
    return on;
}

// Loop-gate traces ([loop-gate] window summaries and the run verdict distribution).
inline bool loop_gate_on()
{
    static const bool on = std::getenv("SHELLER_LOOP_GATE_TRACE") != nullptr;
    return on;
}

// Per-rdtsc answer traces ([rdtsc]/[rdtscp] block position + answer value per
// instruction): the replay=rerun acceptance channel - two independent runs'
// traces must be line-for-line identical. Off by default, so the event stream
// and every golden stay untouched.
inline bool rdtsc_on()
{
    static const bool on = std::getenv("SHELLER_RDTSC_TRACE") != nullptr;
    return on;
}

// Guest file-serve decisions ([file]).
inline bool file_on()
{
    static const bool on = std::getenv("SHELLER_FILE_TRACE") != nullptr;
    return on;
}

// Code-hook registration surface ([hookinv]): the trap/stub half at apply time
// and the intercept/window half at hook registration, once per run. The two
// lines sum to the chain unicorn scans for every covered instruction, which is
// what makes a registration-form change measurable without a probe build.
inline bool hook_on()
{
    static const bool on = std::getenv("SHELLER_HOOK_TRACE") != nullptr;
    return on;
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

// Would this record be rendered and delivered? Multi-part traces that assemble one
// line out of several pieces call this once and build the string themselves; a
// one-line trace calls emit() below instead.
inline bool wanted(const sheller::log::level level, const bool site_enabled)
{
    return site_enabled && sheller::log::would_log(level);
}

// Render one record and hand it to the host's sink. The level is the caller's, not a
// constant of this header: the traces are kDebug, while a line the operator needs even
// with no diagnostics asked for - the unhandled-crash line - is kWarning, which is what
// keeps it visible to the CLI's own threshold.
template <typename... Args>
void emit(const sheller::log::level level, const bool site_enabled,
          const std::format_string<Args...> fmt, Args&&... args)
{
    if (!wanted(level, site_enabled)) {
        return;
    }
    sheller::log::write(level, std::format(fmt, std::forward<Args>(args)...));
}

// The same, for a line the caller assembled already.
inline void emit(const sheller::log::level level, const bool site_enabled,
                 const std::string_view line)
{
    if (!wanted(level, site_enabled)) {
        return;
    }
    sheller::log::write(level, line);
}

} // namespace sheller::engine::diag
