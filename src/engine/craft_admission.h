// The synthetic admission's entry point, shared with the differential tests.
//
// The Windows route's counterpart is capture::admit_dll_sample
// (src/runtime/capture/dll_admission.h): both answer the same question - what
// must the load-stub runner preload for this DLL sample - and both are pinned
// to produce one plan per corpus. The two implementations are internal to the
// capture/craft paths; this header exists so the differential test can drive
// the synthetic route directly without going through a container.

#ifndef SHELLER_ENGINE_CRAFT_ADMISSION_H
#define SHELLER_ENGINE_CRAFT_ADMISSION_H

#include "../runtime/capture/wrapper.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace sheller::engine {

// Admits `sample_bytes` against the synthetic world. `synth_dir` holds the
// generated <module>.x64.dll set (the only trusted system world when the
// directory-mode arguments are empty); `system_modules_dir` selects directory
// mode over real DLL bytes, with `system_modules_fallback` permitting the
// synthetic directory as the named fallback. A rejection is the dependency's
// name plus the reason, in the synthetic route's own wording.
std::expected<capture::RunnerPlan, std::string>
admit_synth_dll_sample(const std::vector<std::uint8_t>& sample_bytes,
                       const std::string& arrival_name, const std::filesystem::path& synth_dir,
                       const std::filesystem::path& system_modules_dir = {},
                       bool system_modules_fallback = false);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_CRAFT_ADMISSION_H
