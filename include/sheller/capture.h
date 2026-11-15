// sheller public capture header - the Win32 re-photography entry point
// run() drives the full pipeline: spawn the sample suspended
// under the real Windows loader, patch its entry into an in-place spin, wait
// for the loader to finish, then photograph the whole user-mode state into a
// snapshot container (v3, with the pinned clock policy). Only the surface
// lives here; the pipeline itself is Windows-only and refuses cleanly
// elsewhere.

#ifndef SHELLER_CAPTURE_H
#define SHELLER_CAPTURE_H

#include <sheller/export.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace sheller::capture {

enum class Status {
    kOk = 0,
    kUnsupportedPlatform, // run() called on a non-Windows host
    kSampleNotFound,
    kNotX64Pe,
    kSpawnFailed,
    kPatchFailed,
    kEntryTimeout,
    kQueryFailed,
    kCaptureFailed,
    kWriteFailed,
};

struct Options {
    std::filesystem::path sample_path{};
    std::filesystem::path output_path{};
    bool disable_aslr{false};
    std::chrono::milliseconds entry_timeout{10000};
    // Input normalization: true forces the input to be
    // wrapped as a shellcode blob (a leading MZ auto-detects without the
    // flag). The wrapped image rides the standard capture route.
    bool shellcode{false};
    // Appended verbatim to the sample's OS command line after the sample
    // path ("sample.exe <tail>"). Empty keeps the zero-argument behavior;
    // the OS builds the process parameters either way, so the captured
    // ProcessParameters match a real run with those arguments byte for byte.
    std::string sample_args{};
};

struct Result {
    Status status{};
    // Human-readable failure reason; on success a one-line summary (region
    // count, output path).
    std::string detail{};
};

bool capture_available();

SHELLER_API Result run(const Options& options);

// Runs the capture and returns the snapshot bytes instead of writing a
// file - the one-shot unpack flow keeps the snapshot in memory.
Result run_to_buffer(const Options& options, std::vector<std::uint8_t>& snapshot);

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_H
