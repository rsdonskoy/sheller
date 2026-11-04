// The shared runner-admission algorithm. See admission.h for the contract.

#include "admission.h"

#include <algorithm>
#include <cctype>
#include <set>

namespace sheller::capture {

std::string fold_module_name(const std::string_view name)
{
    std::string out;
    out.reserve(name.size());
    for (const char c : name) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool fold_module_name_equals(const std::string_view a, const std::string_view b)
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

bool ModuleSource::is_base_module(const std::string_view folded_name) const
{
    return folded_name == "kernel32.dll";
}

} // namespace sheller::capture
