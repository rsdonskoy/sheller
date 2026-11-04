# Runtime environment-supply layer: craft/ is the portable construction path
# ; capture/ is the Win32 re-photography pipeline.
target_sources(sheller_engine PRIVATE craft/craft.cpp)

# The capture module is its own static library so it never sees the unicorn
# include path: an accidental unicorn include is a hard compile error, not a
# CI finding. All its sources compile on both platforms (format codec, PE
# header walk); only the pipeline itself is Windows-specific.
add_library(sheller_capture STATIC)
target_include_directories(sheller_capture
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>)
target_sources(sheller_capture PRIVATE
  capture/pe_headers.h
  capture/module_name.h
  capture/admission.h
  capture/admission.cpp
  capture/wrapper.h
  capture/wrapper.cpp
  capture/snapshot_codec.cpp
  capture/pe_headers.cpp)
if(WIN32)
  target_sources(sheller_capture PRIVATE
    capture/capture.cpp
    capture/dll_admission.h
    capture/dll_admission.cpp)
else()
  target_sources(sheller_capture PRIVATE capture/capture_stub.cpp)
endif()
sheller_apply_static_core(sheller_capture)
