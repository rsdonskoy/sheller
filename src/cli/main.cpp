// sheller CLI entry. CLI11 owns parsing: --help/-h prints usage (exit 0),
// --version prints name and version (exit 0), unknown arguments exit non-zero.
// A bare invocation prints the same banner as --version. The run/unpack
// subcommands are thin shells over the analysis facade (analyze /
// unpack_sample): run states its route - with --from-snapshot the positional
// is a v1 snapshot replayed, without it the positional is an x64 PE sample
// run as a pass-through on the host platform - and unpack is the one-shot
// pipeline on every host. capture re-photographs a suspended sample process
// into a v1 snapshot file (Windows hosts only).

#include <CLI/CLI.hpp>

#include <sheller/analysis.h>
#include <sheller/capture.h>
#include <sheller/version.h>

#include "render.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "log.h"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;

std::uint32_t cli_pid()
{
#ifdef _WIN32
    return static_cast<std::uint32_t>(_getpid());
#else
    return static_cast<std::uint32_t>(getpid());
#endif
}

// The unpack wall clock defaults: a run with no instruction budget gets a
// short leash because a timeout writes no dump, so failing fast is the point;
// a budgeted run gets the generous backstop.
constexpr std::uint32_t kUnpackTimeoutWithoutBudgetMs = 30000;
constexpr std::uint32_t kUnpackTimeoutWithBudgetMs = 600000;

// Numeric engine bounds shared by the run-reaching subcommands. Grouped so a
// positional swap between the two uint64 fields cannot compile silently.
struct EngineBounds {
    std::uint64_t max_instructions{};
    std::uint32_t timeout_ms{};
    std::uint64_t xfer_number{};
    sheller::engine::EspStopGoal esp_stop_goal{sheller::engine::EspStopGoal::kNone};
};

// The parsed --stop goal. `xfer=<n>` is the xfer stop target (0 = off);
// `esp` and `esp+xfer` are the ESP-law stop targets.
struct StopGoal {
    sheller::engine::EspStopGoal esp{sheller::engine::EspStopGoal::kNone};
    std::uint64_t xfer_number{};
    bool xfer_goal{}; // spelled xfer=<n>; a value of 0 is still explicit off
};

std::optional<StopGoal> parse_stop_goal(const std::string_view text)
{
    if (text == "esp") {
        return StopGoal{.esp = sheller::engine::EspStopGoal::kStopAtRestore,
                        .xfer_number = 0,
                        .xfer_goal = false};
    }
    if (text == "esp+xfer") {
        return StopGoal{.esp = sheller::engine::EspStopGoal::kArmThenNextXfer,
                        .xfer_number = 0,
                        .xfer_goal = false};
    }
    if (text.starts_with("xfer=")) {
        const auto digits = text.substr(5);
        std::uint64_t number = 0;
        const auto [end, ec] =
            std::from_chars(digits.data(), digits.data() + digits.size(), number);
        if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size()) {
            return std::nullopt;
        }
        return StopGoal{
            .esp = sheller::engine::EspStopGoal::kNone, .xfer_number = number, .xfer_goal = true};
    }
    return std::nullopt;
}

// The membership of the three goals is the validator's business, so a typo or
// a non-integer after `xfer=` is a usage error before any run starts.
CLI::Validator stop_goal_validator()
{
    return CLI::Validator(
        [](std::string& value) -> std::string {
            if (!parse_stop_goal(value).has_value()) {
                return "expected a stop goal: xfer=<n>, esp or esp+xfer";
            }
            return {};
        },
        "");
}

std::string version_banner()
{
    return std::format("sheller v{} (unicorn {})", sheller::version_string(),
                       sheller::unicorn_version_string());
}

// --budget is an integer count of millions ("5M"); 0M keeps the documented
// unlimited value. Bare integers are rejected so the unit is never ambiguous.
std::optional<std::uint64_t> parse_instruction_budget(std::string_view text)
{
    constexpr std::uint64_t kPerMillion = 1000000;
    if (text.size() < 2 || text.back() != 'M') {
        return std::nullopt;
    }
    const auto digits = text.substr(0, text.size() - 1);
    std::uint64_t millions = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), millions);
    if (ec != std::errc{} || end != digits.data() + digits.size() ||
        millions > std::numeric_limits<std::uint64_t>::max() / kPerMillion) {
        return std::nullopt;
    }
    return millions * kPerMillion;
}

// The value carries its unit, so "5M" reaches the uint64 option as
// "5000000"; the parse error names the expected spelling.
CLI::Validator instruction_budget_validator()
{
    return CLI::Validator(
        [](std::string& value) -> std::string {
            const auto parsed = parse_instruction_budget(value);
            if (!parsed.has_value()) {
                return "expected an integer number of millions, e.g. 5M";
            }
            value = std::to_string(*parsed);
            return {};
        },
        "");
}

int run_capture(std::string_view sample, std::string_view output, const bool disable_aslr,
                const bool shellcode, std::string_view sample_args)
{
    const sheller::capture::Options options{
        .sample_path = sample,
        .output_path = output,
        .disable_aslr = disable_aslr,
        .shellcode = shellcode,
        .sample_args = std::string(sample_args),
    };
    const auto result = sheller::capture::run(options);
    if (result.status != sheller::capture::Status::kOk) {
        std::cerr << std::format("sheller capture: {}\n", result.detail);
        return 1;
    }
    std::cout << std::format("sheller capture: {}\n", result.detail);
    return 0;
}

// Parses "<number>=<status>", both hexadecimal, into one rejection override.
std::optional<std::pair<std::uint32_t, std::uint32_t>> parse_reject_spec(const std::string& spec)
{
    const auto split = spec.find('=');
    if (split == std::string::npos) {
        return std::nullopt;
    }
    const auto parse_hex = [](const std::string& text, std::uint32_t& value) {
        // from_chars takes digits only; accept the common 0x spelling too.
        const std::string_view digits{text.size() > 2 && text[0] == '0' &&
                                              (text[1] == 'x' || text[1] == 'X')
                                          ? std::string_view{text}.substr(2)
                                          : std::string_view{text}};
        if (digits.empty()) {
            return false;
        }
        const auto result =
            std::from_chars(digits.data(), digits.data() + digits.size(), value, 16);
        return result.ec == std::errc{} && result.ptr == digits.data() + digits.size();
    };
    std::pair<std::uint32_t, std::uint32_t> parsed{};
    if (!parse_hex(spec.substr(0, split), parsed.first) ||
        !parse_hex(spec.substr(split + 1), parsed.second)) {
        return std::nullopt;
    }
    return parsed;
}

bool write_text_file(const fs::path& path, const std::string_view content)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        std::cerr << std::format("sheller: cannot write {}\n", path.string());
        return false;
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return static_cast<bool>(out);
}

// The parsed --event-level value. CLI11's membership check has already
// rejected every other spelling, so this mapping is total.
sheller::cli::EventLevel event_level_of(const std::string& text)
{
    if (text == "full") {
        return sheller::cli::EventLevel::Full;
    }
    return text == "counts" ? sheller::cli::EventLevel::Counts : sheller::cli::EventLevel::Semantic;
}

// The behavior report: {"events":{...}} rendered from the facade's artifacts
// at the requested event level, plus the one-line summary (nonzero counts and,
// at full level, the loss counters - the report stating that only the window
// side is lossy).
void write_behavior_report(const fs::path& path, const sheller::AnalysisArtifacts& artifacts,
                           const sheller::cli::EventLevel level)
{
    const std::string report =
        "{\"events\":" + sheller::cli::render_events_section(artifacts, level) + "}";
    static_cast<void>(write_text_file(path, report));
    // One detail entry per line, with one newline opening the list before the
    // first entry and one before the closing bracket: the entry count is the
    // newline count minus that closing newline (zero when the list is empty).
    const auto newline_count =
        static_cast<std::size_t>(std::count(report.begin(), report.end(), '\n'));
    const auto detail_entries = newline_count == 0 ? 0 : newline_count - 1;
    std::string summary;
    for (std::size_t i = 0; i < artifacts.event_counts.size(); ++i) {
        const auto count = artifacts.event_counts[i];
        if (count == 0) {
            continue;
        }
        if (!summary.empty()) {
            summary.push_back(' ');
        }
        summary += sheller::kEventTypeNames[i];
        summary += '=';
        summary += std::to_string(count);
    }
    if (level == sheller::cli::EventLevel::Full) {
        summary += std::format("; loss dropped={} truncated={}", artifacts.timeline_dropped,
                               artifacts.timeline_truncated);
    }
    const auto detail_summary =
        level == sheller::cli::EventLevel::Counts
            ? std::format("counts-only; {}", summary.empty() ? "none" : summary)
            : std::format("{} default-column records -> {} detail entries; {}",
                          artifacts.semantic_events.size(), detail_entries,
                          summary.empty() ? "none" : summary);
    std::cout << std::format("sheller: behavior report -> {} ({})", path.string(), detail_summary)
              << std::endl;
    // A window whose tail failed to decode renders short: that has to show on
    // the console too, not only in a file nobody opened.
    if (level == sheller::cli::EventLevel::Full &&
        sheller::cli::tlv_window_has_malformed_tail(artifacts.timeline_tlv)) {
        std::cout << "sheller: event stream stopped at a malformed tail (truncated render)\n";
    }
}

// Which limit, if any, closed the run before a stop goal: a miss hint names
// it so "not reached" cannot be read as "the goal never fires here". A
// successful stop or a non-limit closeout (normal completion, guest
// termination) leaves the hint bare.
enum class LimitFirst { kNone, kBudget, kWallClock };

std::string_view limit_first_note(const LimitFirst limit)
{
    switch (limit) {
    case LimitFirst::kBudget:
        return "; instruction budget arrived first";
    case LimitFirst::kWallClock:
        return "; wall clock arrived first";
    case LimitFirst::kNone:
    default:
        return {};
    }
}

// The limit named from the typed run error, on the failure paths both
// subcommands share (a limit-closed run is a typed failure carrying partial
// statistics).
LimitFirst limit_first_of(const std::optional<sheller::engine::SyscallRunError> error)
{
    if (!error.has_value()) {
        return LimitFirst::kNone;
    }
    if (*error == sheller::engine::SyscallRunError::kBudgetExhausted) {
        return LimitFirst::kBudget;
    }
    if (*error == sheller::engine::SyscallRunError::kTimeout) {
        return LimitFirst::kWallClock;
    }
    return LimitFirst::kNone;
}

// One line for the xfer stop goal: a hit is the stop, a miss is a hint and
// never changes the exit code.
void report_xfer_stop(const std::string_view command, const std::uint64_t xfer_number,
                      const sheller::engine::SyscallRunStats& stats, const LimitFirst limit)
{
    if (xfer_number == 0) {
        return;
    }
    if (stats.xfer_stop) {
        std::cout << std::format("sheller {}: xfer target reached (xfers={})\n", command,
                                 stats.xfers);
    } else {
        std::cout << std::format("sheller {}: xfer target {} not reached (xfers={}){}\n", command,
                                 xfer_number, stats.xfers, limit_first_note(limit));
    }
}

// One line for the esp targets, same hit/miss shape. The discriminator is
// stats.esp_stop itself: the arm form's hit is the armed transfer's stop
// (esp_stop true alongside xfer_stop), while a transfer stop the arm never
// preceded - an explicit xfer ordinal arriving first - is the xfer target's
// hit and the esp goal's miss. Every miss (window never read, decode never
// confirmed, transfer first) is a hint on the run's own closing terms.
void report_esp_stop(const std::string_view command, const sheller::engine::EspStopGoal goal,
                     const sheller::engine::SyscallRunStats& stats, const LimitFirst limit)
{
    if (goal == sheller::engine::EspStopGoal::kNone) {
        return;
    }
    if (stats.esp_stop) {
        if (goal == sheller::engine::EspStopGoal::kArmThenNextXfer) {
            std::cout << std::format(
                "sheller {}: esp target armed; xfer target reached (xfers={})\n", command,
                stats.xfers);
        } else {
            std::cout << std::format("sheller {}: esp target reached (stack restore confirmed)\n",
                                     command);
        }
        return;
    }
    std::cout << std::format("sheller {}: esp target not reached{}\n", command,
                             limit_first_note(limit));
}

std::optional<fs::path> locate_synthetic_modules();

int run_snapshot(const std::string& input, const std::vector<std::string>& reject_specs,
                 const std::string& dump_dir, const EngineBounds& bounds,
                 const std::string& report_path, const sheller::cli::EventLevel event_level,
                 const bool from_snapshot, const std::string& save_snapshot,
                 const bool guest_stdout, const std::string& system_modules_dir,
                 const bool system_modules_fallback)
{
    sheller::AnalysisOptions options;
    if (!system_modules_dir.empty()) {
        options.run.system_modules_dir = system_modules_dir;
        options.run.system_modules_fallback = system_modules_fallback;
    }
    // Only the legacy non-Windows sample route requires a synthetic
    // directory. Directory worlds and their snapshots are self-contained;
    // locate the synthetic set opportunistically for explicit fallback.
    const bool needs_synthetic =
#ifndef _WIN32
        !from_snapshot && system_modules_dir.empty();
#else
        false; // plain Windows samples capture; strict directory worlds are self-contained
#endif
    if (const auto synth = locate_synthetic_modules(); synth.has_value()) {
        options.run.synthetic_system_modules = true;
        options.run.synthetic_module_dir = *synth;
    } else if (needs_synthetic) {
        std::cerr << "sheller run: synthetic modules not found (looked next to the "
                     "executable); build with synth_modules enabled\n";
        return 2;
    }
    // The route is the flag's, never a guess about the bytes: without
    // --from-snapshot the positional goes to the sample route, and a snapshot
    // file there is refused as the capture-class failure the facade reports.
    options.input_kind =
        from_snapshot ? sheller::AnalysisInputKind::kSnapshot : sheller::AnalysisInputKind::kSample;
    options.run.max_instructions = bounds.max_instructions;
    options.run.timeout_ms = bounds.timeout_ms;
    options.run.xfer_number = bounds.xfer_number;
    options.run.esp_stop_goal = bounds.esp_stop_goal;
    // The ledger only gets built when the report asks for the instruction-level
    // tier; a semantic-level run costs exactly what it always cost.
    options.timeline = (event_level == sheller::cli::EventLevel::Full);
    for (const auto& spec : reject_specs) {
        const auto parsed = parse_reject_spec(spec);
        if (!parsed.has_value()) {
            std::cerr << std::format(
                "sheller run: bad --reject spec '{}' (want <hex number>=<hex status>)\n", spec);
            return 2;
        }
        options.run.reject_overrides.emplace(parsed->first, parsed->second);
    }
    if (!dump_dir.empty()) {
        options.run.dump_directory = dump_dir;
    }
    if (!save_snapshot.empty()) {
        options.save_snapshot = save_snapshot;
    }
    if (guest_stdout) {
        // Explicit host choice: the library default discards guest output.
        options.run.write_sink = [](const std::uint8_t* data, const std::size_t size) {
            std::fwrite(data, 1, size, stdout);
            std::fflush(stdout);
        };
    }

    const auto result = sheller::analyze(input, options);
    if (!result.has_value()) {
        const auto& failure = result.error();
        // Failed runs still carry the artifacts produced before the failure
        // (budget exhaustion and post-unpack crashes are the normal shape) -
        // write the requested report from them, then report the failure. A
        // full-level run renders whatever window the ledger kept.
        if (!report_path.empty()) {
            write_behavior_report(report_path, failure.artifacts, event_level);
        }
        if (failure.artifacts.run_stats.has_value()) {
            const auto& stats = *failure.artifacts.run_stats;
            const auto limit =
                failure.kind == sheller::AnalysisFailure::Kind::kRun && failure.run.has_value()
                    ? limit_first_of(failure.run->error)
                    : LimitFirst::kNone;
            std::cout << std::format("sheller run: terminated={} exit={:#x} syscalls={} "
                                     "rejects={} blocks={}\n",
                                     stats.terminated ? 1 : 0, stats.exit_code, stats.syscalls,
                                     stats.rejects, stats.blocks);
            report_xfer_stop("run", bounds.xfer_number, stats, limit);
            report_esp_stop("run", bounds.esp_stop_goal, stats, limit);
        }
        // A deterministic budget stop is the normal end of a bounded run at
        // this surface; the library still carries it as a typed failure for
        // hosts. Other run failures keep their nonzero exit.
        if (failure.kind == sheller::AnalysisFailure::Kind::kRun && failure.run.has_value() &&
            failure.run->error == sheller::engine::SyscallRunError::kBudgetExhausted) {
            std::cout << "sheller run: instruction budget exhausted (bounded run)\n";
            return 0;
        }
        std::cerr << std::format(
            "sheller run: {}: {}\n",
            failure.kind == sheller::AnalysisFailure::Kind::kCapture      ? "capture failed"
            : failure.kind == sheller::AnalysisFailure::Kind::kSnapshotIo ? "snapshot io failed"
                                                                          : "run failed",
            failure.message);
        return 1;
    }
    const auto& artifacts = result.value();

    if (!report_path.empty()) {
        write_behavior_report(report_path, artifacts, event_level);
    }
    if (artifacts.run_stats.has_value()) {
        const auto& stats = *artifacts.run_stats;
        std::cout << std::format("sheller run: terminated={} exit={:#x} syscalls={} rejects={} "
                                 "blocks={}\n",
                                 stats.terminated ? 1 : 0, stats.exit_code, stats.syscalls,
                                 stats.rejects, stats.blocks);
        report_xfer_stop("run", bounds.xfer_number, stats, LimitFirst::kNone);
        report_esp_stop("run", bounds.esp_stop_goal, stats, LimitFirst::kNone);
    }
    if (!artifacts.note.empty()) {
        std::cout << std::format("sheller run: {}\n", artifacts.note);
    }
    return 0;
}

// One-shot unpack: everything below the CLI is the facade's
// unpack_sample pipeline. --keep preserves the intermediates by passing an
// explicit work directory (the facade deletes the ones it generates).
// The loader route (non-Windows hosts) and the directory-mode crafted route
// (every host) need the generated synthetic system modules; they are located
// relative to the executable, exactly where the build places them.
std::optional<fs::path> locate_synthetic_modules()
{
    std::error_code ec;
#ifdef _WIN32
    char exe_path[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) == 0) {
        return std::nullopt;
    }
    fs::path exe(exe_path);
#else
    fs::path exe = fs::path("/proc/self/exe");
    if (fs::is_symlink(exe, ec)) {
        exe = fs::read_symlink(exe, ec);
        if (ec) {
            return std::nullopt;
        }
    }
#endif
    // <build>/<config>/src/cli/sheller -> <build>/<config>/synth_modules
    // (the single-config layout), the multi-config step up (<build>/<config>
    // is four levels above the executable), then a sibling of the
    // executable as the fallback layout.
    for (const auto& candidate :
         {exe.parent_path().parent_path().parent_path() / "synth_modules",
          exe.parent_path().parent_path().parent_path().parent_path() / "synth_modules",
          exe.parent_path() / "synth_modules"}) {
        if (fs::is_directory(candidate, ec)) {
            return candidate;
        }
    }
    return std::nullopt;
}

int run_unpack(std::string_view sample, std::string_view out_override, const bool keep,
               const bool shellcode, const sheller::cli::EventLevel event_level,
               const EngineBounds& bounds, const std::string& report_override,
               const std::string& save_snapshot, const std::string& system_modules_dir,
               const bool system_modules_fallback)
{
    const fs::path out =
        out_override.empty() ? fs::path(std::string(sample) + ".unp") : fs::path(out_override);

    sheller::UnpackOptions options;
    options.output = out;
    options.shellcode = shellcode;
    options.timeline = (event_level == sheller::cli::EventLevel::Full);
    options.max_instructions = bounds.max_instructions;
    options.xfer_number = bounds.xfer_number;
    options.esp_stop_goal = bounds.esp_stop_goal;
    options.timeout_ms = bounds.timeout_ms;
    if (!save_snapshot.empty()) {
        options.save_snapshot = save_snapshot;
    }
    // Strict directory worlds need no synthetic set; legacy non-Windows
    // construction does. Locate optional fallback modules on either host.
    const bool unpack_needs_synthetic =
#ifndef _WIN32
        system_modules_dir.empty()
#else
        false
#endif
        ;
    if (const auto synth = locate_synthetic_modules(); synth.has_value()) {
        options.synthetic_module_dir = *synth;
    } else if (unpack_needs_synthetic) {
        std::cerr << "sheller unpack: synthetic modules not found (looked next to the "
                     "executable); build with synth_modules enabled\n";
        return 2;
    }
    if (!system_modules_dir.empty()) {
        options.system_modules_dir = system_modules_dir;
        options.system_modules_fallback = system_modules_fallback;
    }
    if (keep) {
        std::error_code ec;
        auto work = fs::temp_directory_path(ec) / ("sheller_unpack_" + std::to_string(cli_pid()));
        if (ec) {
            std::cerr << std::format("sheller unpack: cannot resolve the work directory ({})\n",
                                     ec.message());
            return 1;
        }
        fs::create_directories(work, ec);
        if (ec) {
            std::cerr << std::format("sheller unpack: cannot create the work directory {} ({})\n",
                                     work.string(), ec.message());
            return 1;
        }
        // An explicit work directory survives the call - that is --keep's
        // whole contract. Silently falling back to a generated (deleted)
        // one would make the flag a no-op.
        options.work_dir = work;
    }

    const auto outcome = sheller::unpack_sample(sample, options);
    if (outcome.failure.has_value()) {
        if (outcome.artifacts.run_stats.has_value()) {
            const auto limit = outcome.failure->run.has_value()
                                   ? limit_first_of(outcome.failure->run->error)
                                   : LimitFirst::kNone;
            report_xfer_stop("unpack", bounds.xfer_number, *outcome.artifacts.run_stats, limit);
            report_esp_stop("unpack", bounds.esp_stop_goal, *outcome.artifacts.run_stats, limit);
        }
        std::cerr << std::format("sheller unpack: {}\n", outcome.failure->message);
        return 1;
    }

    // The behavior artifacts render next to the image (CLI-side formatting):
    // one artifact, the same shape run writes at the same level. --report
    // overrides the default landing path; exactly one report is written.
    const fs::path report = report_override.empty()
                                ? fs::path(outcome.output.string() + ".report.json")
                                : fs::path(report_override);
    write_behavior_report(report, outcome.artifacts, event_level);

    // One-line repair verdict summary derived from the structured field -
    // independent of the log threshold (the log's per-region records are the
    // diagnostic rendering, this line is the product answer).
    if (outcome.repair.has_value()) {
        std::size_t complete = 0;
        std::size_t partial = 0;
        std::size_t failed = 0;
        std::size_t not_image = 0;
        std::size_t uncovered = 0;
        for (const auto& region : outcome.repair->regions) {
            switch (region.verdict) {
            case sheller::unpack::RepairVerdict::kComplete:
                ++complete;
                break;
            case sheller::unpack::RepairVerdict::kPartial:
                ++partial;
                break;
            case sheller::unpack::RepairVerdict::kFailed:
                ++failed;
                break;
            case sheller::unpack::RepairVerdict::kNotImage:
                ++not_image;
                break;
            }
            uncovered += region.uncovered.size();
        }
        std::cout << std::format(
            "sheller unpack: repair regions={} complete={} partial={} failed={} not-image={} "
            "uncovered={}\n",
            outcome.repair->regions.size(), complete, partial, failed, not_image, uncovered);
    }

    if (outcome.oep_found) {
        std::cout << std::format("sheller unpack: OEP 0x{:x} (rva 0x{:x}) stamped\n",
                                 outcome.oep_va, outcome.oep_rva);
    }
    if (outcome.artifacts.run_stats.has_value()) {
        const auto& stats = *outcome.artifacts.run_stats;
        std::cout << std::format("sheller unpack: run stopped (terminated={} exit={:#x} "
                                 "syscalls={} blocks={})\n",
                                 stats.terminated ? 1 : 0, stats.exit_code, stats.syscalls,
                                 stats.blocks);
        report_xfer_stop("unpack", bounds.xfer_number, stats, LimitFirst::kNone);
        report_esp_stop("unpack", bounds.esp_stop_goal, stats, LimitFirst::kNone);
    }
    if (keep && !outcome.work_dir.empty()) {
        std::cout << std::format("sheller unpack: intermediates in {}\n",
                                 outcome.work_dir.string());
    }
    std::cout << std::format("sheller unpack: {}\n", outcome.output.string());
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    // The default threshold first, so the CLI has a channel for its own messages before
    // an argument that names a different one has been read; --log-level re-installs it
    // once parsing is done.
    sheller::cli::install_log_sink(sheller::log::level::kWarning);

    CLI::App app{"sheller - PE unpacker & shellcode behavior analyzer (snapshot replay, "
                 "sample pass-through, one-shot unpack)"};
    app.set_version_flag("--version", version_banner());

    // One variable, offered by each subcommand that reaches the library: the threshold is
    // a property of the process, not of the subcommand, and the three commands cannot be
    // used in one invocation.
    std::string log_level = "warn";

    // Same shape for the report's event granularity: one variable, offered by
    // each subcommand that writes a behavior report (capture writes a snapshot,
    // not a report). The membership check is what makes a typo an error.
    std::string event_level = "semantic";

    // Applied inside each subcommand's callback rather than after parsing, because CLI11
    // runs those callbacks while it parses: a threshold set after the parse would be a
    // threshold set after the run it is supposed to affect.
    const auto apply_log_level = [&] {
        if (const auto level = sheller::cli::parse_log_level(log_level); level.has_value()) {
            // Both halves of the channel move together: the facade's filter and spdlog's
            // own level, so a record the library passes is not then dropped by the
            // renderer.
            sheller::cli::install_log_sink(*level);
        }
    };

    std::string sample_path;
    std::string output_path;
    auto disable_aslr = false;
    auto* capture_command = app.add_subcommand(
        "capture", "re-photograph a suspended sample process into a v1 snapshot file");
    capture_command->add_option("sample", sample_path, "path to the x64 PE sample")->required();
    capture_command->add_option("-o,--output", output_path, "path of the snapshot file to write")
        ->required();
    auto capture_shellcode = false;
    capture_command->add_flag("--shellcode", capture_shellcode,
                              "treat the input as a bare shellcode blob (wrap into a minimal PE)");
    capture_command->add_flag("--no-aslr", disable_aslr,
                              "disable dynamic base for a deterministic layout");
    std::string capture_sample_args;
    capture_command->add_option("--args", capture_sample_args,
                                "argument tail appended to the sample's command line");

    int capture_exit_code = 0;
    capture_command->callback([&] {
        apply_log_level();
        capture_exit_code = run_capture(sample_path, output_path, disable_aslr, capture_shellcode,
                                        capture_sample_args);
    });

    std::string run_input;
    std::vector<std::string> reject_specs;
    int run_exit_code = 0;
    auto* run_command = app.add_subcommand("run", "run a sample until termination or budget end "
                                                  "(--from-snapshot replays a v1 snapshot)");
    run_command
        ->add_option("sample", run_input,
                     "path to an x64 PE sample (a v1 snapshot path with --from-snapshot)")
        ->required();
    auto run_from_snapshot = false;
    run_command->add_flag("--from-snapshot", run_from_snapshot,
                          "replay the positional path as a v1 snapshot; without it the path runs "
                          "as a sample pass-through on the host platform");
    std::string run_dump_dir;
    run_command->add_option("--dump", run_dump_dir,
                            "write the exit-time region dump into this directory");
    run_command
        ->add_option(
            "--reject", reject_specs,
            "per-number rejection override <number>=<status>, both hexadecimal; repeatable")
        ->take_all();
    auto run_budget = std::uint64_t{3000000};
    run_command
        ->add_option("-b,--budget", run_budget,
                     "instruction budget in integer millions, e.g. 5M; 0M = unlimited")
        ->transform(instruction_budget_validator());
    auto run_timeout_ms = std::uint32_t{10000};
    run_command->add_option("--timeout-ms", run_timeout_ms, "wall-clock budget in milliseconds");
    std::string run_stop_goal;
    auto* run_stop_option =
        run_command
            ->add_option("--stop", run_stop_goal,
                         "stop target: xfer=<n> (0 = off), esp (stop at the confirmed "
                         "entry-stack restore) or esp+xfer (arm on it, stop at the next "
                         "transfer)")
            ->check(stop_goal_validator());
    std::string run_report_path;
    run_command->add_option("--report", run_report_path,
                            "synthesize behavior signals into this JSON report");
    std::string run_save_snapshot;
    run_command->add_option("--save-snapshot", run_save_snapshot,
                            "sample pass-through: write the executing snapshot to this path "
                            "(Windows: the captured snapshot; other hosts: the constructed "
                            "container)");
    auto run_guest_stdout = false;
    run_command->add_flag("--guest-stdout", run_guest_stdout,
                          "forward guest file-output bytes to standard output (default: discard)");
    std::string run_system_modules_dir;
    run_command
        ->add_option("--system-modules", run_system_modules_dir,
                     "directory-mode system modules: the resident set comes strictly from this "
                     "directory (boundary pair derived, everything else real bytes)")
        ->check(CLI::ExistingDirectory);
    auto run_system_modules_fallback = false;
    run_command->add_flag("--system-modules-fallback", run_system_modules_fallback,
                          "with --system-modules: a closure member the directory lacks falls back "
                          "to the synthetic directory and is marked in the module source table");
    run_command->callback([&] {
        apply_log_level();
        std::optional<StopGoal> stop;
        if (run_stop_option->count() != 0) {
            stop = parse_stop_goal(run_stop_goal);
        }
        run_exit_code = run_snapshot(
            run_input, reject_specs, run_dump_dir,
            EngineBounds{.max_instructions = run_budget,
                         .timeout_ms = run_timeout_ms,
                         .xfer_number = stop.has_value() && stop->xfer_goal ? stop->xfer_number : 0,
                         .esp_stop_goal =
                             stop.has_value() ? stop->esp : sheller::engine::EspStopGoal::kNone},
            run_report_path, event_level_of(event_level), run_from_snapshot, run_save_snapshot,
            run_guest_stdout, run_system_modules_dir, run_system_modules_fallback);
    });

    std::string unpack_sample_path;
    std::string unpack_out;
    auto unpack_keep = false;
    auto* unpack_command = app.add_subcommand(
        "unpack", "one-shot unpack: capture (Windows) / loader route, run with dump and repair");
    unpack_command->add_option("sample", unpack_sample_path, "path to the packed x64 PE sample")
        ->required();
    unpack_command->add_option("-o,--output", unpack_out, "output file (default: <sample>.unp)");
    auto unpack_shellcode = false;
    unpack_command->add_flag("--shellcode", unpack_shellcode,
                             "treat the input as a bare shellcode blob (wrap into a minimal PE)");
    unpack_command->add_flag("--keep", unpack_keep,
                             "keep the intermediate dump/reconstruction directory");
    auto unpack_budget = std::uint64_t{0};
    auto* unpack_budget_option =
        unpack_command
            ->add_option("-b,--budget", unpack_budget,
                         "instruction budget for the unpack run in integer millions, e.g. 5M; 0M = "
                         "unlimited (default)")
            ->transform(instruction_budget_validator());
    auto unpack_timeout_ms = kUnpackTimeoutWithBudgetMs;
    auto* unpack_timeout_option = unpack_command->add_option(
        "--timeout-ms", unpack_timeout_ms,
        std::format("wall-clock budget for the unpack run in milliseconds; 0 = unbounded "
                    "(default: {} without -b, {} with it)",
                    kUnpackTimeoutWithoutBudgetMs, kUnpackTimeoutWithBudgetMs));
    std::string unpack_stop_goal;
    auto* unpack_stop_option =
        unpack_command
            ->add_option("--stop", unpack_stop_goal,
                         "stop target: xfer=<n> (0 = off), esp (stop at the confirmed "
                         "entry-stack restore) or esp+xfer (arm on it, stop at the next "
                         "transfer)")
            ->check(stop_goal_validator());
    std::string unpack_save_snapshot;
    unpack_command->add_option("--save-snapshot", unpack_save_snapshot,
                               "write the executing snapshot to this path (captured on "
                               "Windows, constructed elsewhere)");
    std::string unpack_report_path;
    unpack_command->add_option("--report", unpack_report_path,
                               "behavior/event report path (default: <output>.report.json)");
    std::string unpack_system_modules_dir;
    unpack_command
        ->add_option("--system-modules", unpack_system_modules_dir,
                     "directory-mode system modules: the resident set comes strictly from this "
                     "directory (boundary pair derived, everything else real bytes)")
        ->check(CLI::ExistingDirectory);
    auto unpack_system_modules_fallback = false;
    unpack_command->add_flag("--system-modules-fallback", unpack_system_modules_fallback,
                             "with --system-modules: a closure member the directory lacks falls "
                             "back to the synthetic directory and is marked in the module source "
                             "table");

    // Offered by each subcommand that reaches the library, because an app-level option
    // would have to precede the subcommand name on the command line.
    const auto add_log_level_option = [&](CLI::App* command) {
        command
            ->add_option("--log-level", log_level,
                         "library diagnostics threshold: debug|info|warn|error")
            ->check(CLI::IsMember({"debug", "info", "warn", "error"}));
    };

    const auto add_event_level_option = [&](CLI::App* command) {
        command
            ->add_option("--event-level", event_level,
                         "report event detail: counts (counts and the stub table only) | semantic "
                         "(the semantic types only, no event ledger) | full (unified stream over "
                         "both tiers, builds the ledger)")
            ->check(CLI::IsMember({"counts", "semantic", "full"}));
    };

    int unpack_exit_code = 0;
    unpack_command->callback([&] {
        apply_log_level();
        std::optional<StopGoal> stop;
        if (unpack_stop_option->count() != 0) {
            stop = parse_stop_goal(unpack_stop_goal);
        }
        if (unpack_budget_option->count() == 0) {
            const bool timeout_given = unpack_timeout_option->count() != 0;
            if (!timeout_given) {
                unpack_timeout_ms = kUnpackTimeoutWithoutBudgetMs;
            }
            if (unpack_timeout_ms == 0) {
                std::cerr << "sheller unpack: no -b/--budget given and the wall clock is "
                             "unbounded; only guest termination ends the run (pass -b <n>M to "
                             "stop deterministically)\n";
            } else {
                std::cerr << std::format(
                    "sheller unpack: no -b/--budget given; using {} {} ms wall clock, and a "
                    "timeout writes no dump (pass -b <n>M to stop deterministically)\n",
                    timeout_given ? "the requested" : "the default", unpack_timeout_ms);
            }
        }
        unpack_exit_code = run_unpack(
            unpack_sample_path, unpack_out, unpack_keep, unpack_shellcode,
            event_level_of(event_level),
            EngineBounds{.max_instructions = unpack_budget,
                         .timeout_ms = unpack_timeout_ms,
                         .xfer_number = stop.has_value() && stop->xfer_goal ? stop->xfer_number : 0,
                         .esp_stop_goal =
                             stop.has_value() ? stop->esp : sheller::engine::EspStopGoal::kNone},
            unpack_report_path, unpack_save_snapshot, unpack_system_modules_dir,
            unpack_system_modules_fallback);
    });
    add_log_level_option(capture_command);
    add_log_level_option(run_command);
    add_log_level_option(unpack_command);
    add_event_level_option(run_command);
    add_event_level_option(unpack_command);

    CLI11_PARSE(app, argc, argv);

    if (argc == 1) {
        std::cout << version_banner() << '\n';
        return 0;
    }
    if (app.got_subcommand(capture_command)) {
        return capture_exit_code;
    }
    if (app.got_subcommand(run_command)) {
        return run_exit_code;
    }
    if (app.got_subcommand(unpack_command)) {
        return unpack_exit_code;
    }
    return 0;
}
