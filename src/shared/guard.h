// The export layer's containment: a callable body plus a mapping strategy, in
// one place, so the product entries can promise that no C++ exception reaches
// the host and that "what comes back instead" is decided per entry rather than
// per catch block.
//
// Why the catch lives here and not behind noexcept on the exports: measured on
// MSVC, an exception that escapes a noexcept function terminates the process,
// while on POSIX that check is not performed at all - the same marker would read
// as a guarantee on one platform and as decoration on the other. The containment
// therefore has to be lexical: the try/catch sits in the body of the exported
// function (see src/shared/api.cpp), and this header is what keeps six copies of
// that shape from drifting apart.
//
// Why a template taking a mapping strategy rather than six hand-written
// try/catch blocks: a C ABI layer is one such consumer, and it needs exactly
// this - run the body, render the message, then map to an error code instead of
// a C++ failure structure. decltype(fn()) carries both the void and the
// string_view returns through the same template, so no specialization is needed
// to cover the odd entries.
//
// Internal header: not installed, not exported, included by the forwarding layer
// alone.

#ifndef SHELLER_SHARED_GUARD_H
#define SHELLER_SHARED_GUARD_H

#include <cstddef>
#include <exception>
#include <string>
#include <string_view>
#include <utility>

namespace sheller::shared::detail {

// The one spelling of "this failure came from inside the library". The prefix is
// prose the host may read; it is deliberately not a contract - the sentence
// after it is whatever the standard library said, so a host that needs to branch
// on this class of failure branches on the status/kind it came back with, not on
// the text.
//
// Fifteen characters on purpose: that is the small-string buffer of the standard
// library on the toolchains this targets, so a message made of the prefix alone
// needs no allocation. The fallback in contained() leans on that - the condition
// being reported is usually an exhausted heap, and a renderer that has to
// allocate in order to say so fails exactly when it is needed.
inline constexpr std::string_view kInternalErrorPrefix = "internal error:";

// What follows the prefix when the exception had nothing translatable to say.
inline constexpr std::string_view kInternalErrorBare = "uncaught exception without a description";

// The message is a diagnostic, and a diagnostic that arrives at 3 AM should not
// be unbounded: the standard library's what() is free to quote a path or a
// description of arbitrary length.
inline constexpr std::size_t kInternalErrorDetailLimit = 512;

// Kept: printable ASCII, plus newline so a multi-line what() stays readable in a
// log. Everything else becomes '?'. The message crosses a library boundary into
// a host that may render it anywhere - control codes (and non-ASCII bytes, which
// have no defined encoding across that boundary) have no business in it.
inline void append_printable(std::string& out, const std::string_view text)
{
    const std::size_t room =
        (text.size() < kInternalErrorDetailLimit) ? text.size() : kInternalErrorDetailLimit;
    for (std::size_t i = 0; i < room; ++i) {
        const unsigned char byte = static_cast<unsigned char>(text[i]);
        const bool printable = (byte >= 0x20U && byte < 0x7FU) || byte == '\n';
        out.push_back(printable ? static_cast<char>(byte) : '?');
    }
    if (text.size() > room) {
        out.append("...[truncated]");
    }
}

// The no-detail form: a foreign exception (not derived from std::exception), or
// one whose what() came back empty. Fixed text, so it carries no locale
// dependency and no address that changes between two runs of the same input.
[[nodiscard]] inline std::string internal_error_message()
{
    std::string message{kInternalErrorPrefix};
    message.push_back(' ');
    message.append(kInternalErrorBare);
    return message;
}

// The detail form: the prefix, then the exception's own words, sanitized to
// printable ASCII and bounded. Nothing here appends an address - whatever the
// standard library chose to put in what() survives only as printable text.
[[nodiscard]] inline std::string internal_error_message(const std::exception& error)
{
    const std::string_view what{error.what()};
    if (what.empty()) {
        return internal_error_message();
    }
    std::string message{kInternalErrorPrefix};
    message.push_back(' ');
    append_printable(message, what);
    return message;
}

// Hand the entry's strategy a rendered message, and keep the containment total:
// rendering allocates, and the heap that just threw is the one likely to refuse.
// When it does, the prefix alone goes out - allocation-free, and still the same
// class of failure - because the alternative is an exception escaping from inside
// the catch block, which is precisely what this layer exists to make impossible.
// The message is a diagnostic, so losing it loses nothing a host can branch on:
// the kind and the status still say "internal".
//
// Rendering is settled before the strategy is called, and the strategy is called
// exactly once. The shape this replaces caught a throw from on_error itself and
// answered it by calling on_error again - which is the same failure asked twice,
// and if the second call throws the exception leaves this function, the guard, and
// the library, from the very code that was meant to stop that. What remains here
// depends on the strategies being total, and they are: each one builds a result
// value and moves a string whose message fits the small-string buffer, so no
// allocation is on the path. A strategy that allocates is the thing to catch in
// review, not a second call to make here.
template <typename OnError, typename Render>
auto contained(OnError&& on_error, Render&& render) -> decltype(on_error(std::string{}))
{
    std::string message{};
    try {
        message = std::forward<Render>(render)();
    } catch (...) {
        message = std::string{kInternalErrorPrefix};
    }
    return std::forward<OnError>(on_error)(std::move(message));
}

// Runs fn(); if it throws, hands the rendered message to on_error and returns
// what on_error decides to return instead. on_error is the per-entry mapping
// strategy: the same caught condition answers as a run-class failure on one
// entry, a capture-class status on another, and "state unchanged" on the log
// sink installer.
//
// void and non-void bodies both fit: decltype(fn()) is the return type, and a
// void on_error is a void expression in a return statement, which is valid.
template <typename Fn, typename OnError> auto guard(Fn&& fn, OnError&& on_error) -> decltype(fn())
{
    try {
        return std::forward<Fn>(fn)();
    } catch (const std::exception& error) {
        return contained(on_error, [&error] { return internal_error_message(error); });
    } catch (...) {
        // Wrapped rather than passed by name: internal_error_message is
        // overloaded, and an overload set does not deduce as a template
        // argument.
        return contained(on_error, [] { return internal_error_message(); });
    }
}

} // namespace sheller::shared::detail

#endif // SHELLER_SHARED_GUARD_H
