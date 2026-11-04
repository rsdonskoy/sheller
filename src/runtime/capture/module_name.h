// The one module-name spelling rule. Windows DLL names are matched
// case-insensitively; the runner admission, the runner builder and the
// synthetic source all key their module lookups through this fold, so a
// spelling change cannot make one route disagree with another. ASCII-only on
// purpose: the names crossing this boundary are ASCII, and a locale-dependent
// fold would make the answer depend on the host's locale.

#ifndef SHELLER_CAPTURE_MODULE_NAME_H
#define SHELLER_CAPTURE_MODULE_NAME_H

#include <cctype>
#include <string>
#include <string_view>

namespace sheller::capture {

inline std::string fold_module_name(const std::string_view name)
{
    std::string out;
    out.reserve(name.size());
    for (const char c : name) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

inline bool fold_module_name_equals(const std::string_view a, const std::string_view b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_MODULE_NAME_H
