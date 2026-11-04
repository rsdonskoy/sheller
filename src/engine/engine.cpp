// Engine module: queries the linked unicorn engine.

#include "engine_detail.h"

#include <unicorn/unicorn.h>

#include <format>
#include <string>
#include <string_view>

namespace sheller::engine::detail {

std::string_view unicorn_version_impl()
{
    // Cached once (magic statics): immutable for the rest of the process lifetime,
    // so returning a string_view borrow is safe.
    static const auto version = [] {
        unsigned int major = 0;
        unsigned int minor = 0;
        uc_version(&major, &minor);
        return std::format("{}.{}", major, minor);
    }();
    return version;
}

} // namespace sheller::engine::detail
