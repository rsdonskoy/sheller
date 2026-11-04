// Resident cross-process determinism helper (the artifact-chain pin's
// worker). One replay per
// invocation: load the container given on argv, serialize the complete raw
// event stream through the facade's host observer (wire-encoded records
// carrying the full preamble: type, seq, tid, pc, payload), run with an
// exit dump, and repair the dumped image into a .unp through the repair
// library. The gtest side spawns two independent processes over the same
// container and byte-compares the three artifact groups; this helper holds
// no comparison logic of its own.
//
// Bounds follow the determinism-pin discipline: no instruction budget and no
// wall clock - only the run's own deterministic stop (the runner stub's
// ExitProcess) ends the replay, and the stats line records whether that stop
// was reached so the test can refuse to compare a nondeterministic abort.
//
// usage: det_helper <snapshot> <work_dir>
//   <work>/events.bin      raw stream records: the wire codec's
//                          [type u16][len u16][seq u64][tid u32][pc u64][payload]
//   <work>/dump/           the run's exit dump (.bin per dirty region + manifest)
//   <work>/unpacked.unp    the repaired sample image
//   <work>/stats.txt       "terminated=<0|1> exit=0x.. blocks=.. events=.. candidates=..
//                           oep_found=<0|1> oep_rva=0x.."

#include "wiring.h"

#include "../engine/behavior_fact.h"

#include <sheller/events.h>
#include <sheller/syscallrun.h>
#include <sheller/unpack.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

// Same repaired-file spelling as the CLI unpack pipeline (the copy source is
// named after the region base in 16 hex digits).
std::string hex16(const std::uint64_t value)
{
    char buf[17] = {};
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(value));
    return std::string{buf};
}

// Buffered raw-stream writer: the observer runs per event, so bytes land in
// a flush-at-8MB buffer ahead of the file. A failed write drops the tail
// silently - the byte compare against the twin process is the real guard.
// Records ride the wire codec's encode_event: [type u16][len u16] plus the
// FULL preamble (seq, tid, pc) - a record missing the tid would let a
// cross-process thread-attribution drift pass the pin.
class StreamSink {
  public:
    explicit StreamSink(const fs::path& path) : out_(path, std::ios::binary | std::ios::trunc)
    {
        buffer_.reserve(kFlushBytes + 1024);
    }

    void record(const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                const std::span<const std::uint8_t> payload)
    {
        std::array<std::uint8_t, 1024> record{};
        const auto encoded = sheller::encode_event(record, type, preamble, payload);
        if (!encoded.has_value()) {
            return; // oversized payload: skip, both processes skip alike
        }
        append(record.data(), *encoded);
        if (buffer_.size() >= kFlushBytes) {
            flush();
        }
    }

    void flush()
    {
        out_.write(reinterpret_cast<const char*>(buffer_.data()),
                   static_cast<std::streamsize>(buffer_.size()));
        buffer_.clear();
    }

    bool good() const
    {
        return static_cast<bool>(out_);
    }

  private:
    static constexpr std::size_t kFlushBytes = 8u * 1024 * 1024;

    void append(const void* data, const std::size_t size)
    {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        buffer_.insert(buffer_.end(), bytes, bytes + size);
    }

    std::ofstream out_;
    std::vector<std::uint8_t> buffer_;
};

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: det_helper <snapshot> <work_dir>\n");
        return 2;
    }
    const fs::path snapshot_path = argv[1];
    const fs::path work = argv[2];
    std::error_code ec;
    fs::create_directories(work, ec);
    const auto dump_dir = work / "dump";
    const auto out_dir = work / "out";
    fs::create_directories(dump_dir, ec);
    fs::create_directories(out_dir, ec);

    std::ifstream in(snapshot_path, std::ios::binary);
    std::vector<std::uint8_t> container{std::istreambuf_iterator<char>(in),
                                        std::istreambuf_iterator<char>()};
    if (container.empty()) {
        std::fprintf(stderr, "det_helper: cannot read %s\n", snapshot_path.string().c_str());
        return 2;
    }

    const auto wiring = sheller::api::detail::wire_behavior(container);
    auto names = sheller::api::detail::build_timeline_names(wiring);
    sheller::api::detail::SemanticCollector collector(names);
    sheller::behavior::EventTally tally;

    StreamSink sink{work / "events.bin"};
    std::vector<std::uint64_t> oep_candidates;
    std::uint64_t event_count = 0;
    auto observer = [&](const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                        const std::span<const std::uint8_t> payload) {
        sink.record(type, preamble, payload);
        ++event_count;
        if (type == sheller::EventTypeId::kOepCandidate &&
            payload.size() >= sizeof(std::uint64_t)) {
            oep_candidates.push_back(*reinterpret_cast<const std::uint64_t*>(payload.data()));
        }
    };
    sheller::api::detail::EventStream stream(wiring.rules.get(), tally, collector, nullptr,
                                             observer, ~std::uint64_t{0});

    sheller::engine::SyscallRunOptions run;
    run.max_instructions = 0; // the deterministic stop ends the run
    run.timeout_ms = 0;       // determinism pins carry no wall clock
    run.dump_directory = dump_dir;
    const sheller::engine::FactChannel facts =
        sheller::api::detail::install_behavior_sinks(run, stream, &names);

    const auto result =
        sheller::engine::detail::run_snapshot_syscalls_with_facts(container, run, facts);
    sink.flush();

    std::uint64_t blocks = 0;
    bool terminated = false;
    std::uint32_t exit_code = 0;
    if (result.has_value()) {
        terminated = result->terminated;
        exit_code = result->exit_code;
        blocks = result->blocks;
    }
    const bool repair_ready = result.has_value() && fs::exists(dump_dir / "manifest.txt", ec);

    bool oep_found = false;
    std::uint64_t oep_rva = 0;
    if (repair_ready) {
        // Same repair entry the CLI unpack drives; the sample's runtime base
        // (v2 route: the synthesized module) anchors the region selection.
        const auto summary =
            sheller::unpack::repair_dump(container, dump_dir, out_dir, oep_candidates);
        if (summary.has_value()) {
            oep_found = summary->oep_found;
            oep_rva = summary->oep_rva;
            const auto sample_base = result->sample_module_base;
            const auto* best = sheller::api::detail::select_unpack_region(
                summary->regions, sample_base, sample_base != 0);
            if (best != nullptr) {
                const auto repaired =
                    out_dir / (std::string{"repaired_"} + hex16(best->base) + ".exe");
                fs::copy_file(repaired, work / "unpacked.unp", fs::copy_options::overwrite_existing,
                              ec);
            }
        }
    }

    std::ofstream stats(work / "stats.txt", std::ios::binary | std::ios::trunc);
    stats << std::format("terminated={} exit={:#x} blocks={} events={} candidates={}"
                         " oep_found={} oep_rva={:#x}\n",
                         terminated ? 1 : 0, exit_code, blocks, event_count, oep_candidates.size(),
                         oep_found ? 1 : 0, oep_rva);
    stats.flush();
    const bool ok = result.has_value() && terminated && sink.good() && stats.good() &&
                    fs::exists(work / "unpacked.unp", ec);
    return ok ? 0 : 1;
}
