// API Set evidence tool: the derivation's honesty contract. A synthetic
// system directory (four hand-built PE64 images) drives the tool and the
// checks pin: a forwarder slot name counts into its host's coverage while a
// forward target name does not; forward reachability is judged against the
// scanned set; duplicate and ambiguous coverage stay named instead of being
// silently resolved; and no reviewed map is written while any contract is
// unconfirmed - schema or recorded review is the only route to a map, and a
// review cannot claim a host that lacks an observed function.
// Portable by design (python + stdlib fixtures, no engine link).

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr const char* kToolScript = APISET_EVIDENCE_SCRIPT;
constexpr const char* kCheckScript = APISET_EVIDENCE_CHECK;
constexpr const char* kPython = APISET_PYTHON;

constexpr std::uint32_t kSectionRva = 0x1000;
constexpr std::uint32_t kSectionRaw = 0x400;

struct ExportDef {
    const char* name;
    const char* forward; // empty: a real body; non-empty: forwarder target
};

struct ImportDef {
    const char* dll;
    std::vector<const char*> functions;
};

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_file(const fs::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary);
    out << text;
}

// Appends into one section blob; an offset o in the blob is RVA
// kSectionRva + o, and the parser maps it back to file offset kSectionRaw + o.
class Blob {
  public:
    std::uint32_t rva() const
    {
        return kSectionRva + static_cast<std::uint32_t>(bytes_.size());
    }

    void advance(std::size_t size)
    {
        bytes_.insert(bytes_.end(), size, 0);
    }

    std::uint32_t advance_and_mark(std::size_t size)
    {
        const auto at = rva();
        advance(size);
        return at;
    }

    // every append aligns first and then takes the address: the returned
    // RVA always points at the first byte of what was appended
    std::uint32_t append_bytes(const void* data, std::size_t size)
    {
        align();
        const auto at = rva();
        const auto* p = static_cast<const std::uint8_t*>(data);
        bytes_.insert(bytes_.end(), p, p + size);
        return at;
    }

    std::uint32_t append_u32(std::uint32_t value)
    {
        return append_bytes(&value, sizeof(value));
    }

    std::uint32_t append_string(const std::string& text)
    {
        return append_bytes(text.c_str(), text.size() + 1);
    }

    std::uint32_t append_hint_name(const std::string& function)
    {
        // hint and name go out as one append: a second align between them
        // would strand padding between the hint word and the name the tool
        // reads at +2
        std::string payload(2, '\0');
        payload += function;
        payload.push_back('\0');
        return append_bytes(payload.data(), payload.size());
    }

    void patch_u32(std::uint32_t rva, std::uint32_t value)
    {
        std::memcpy(bytes_.data() + (rva - kSectionRva), &value, sizeof(value));
    }

    void align()
    {
        while (bytes_.size() % 8 != 0) {
            bytes_.push_back(0);
        }
    }

    const std::vector<std::uint8_t>& bytes() const
    {
        return bytes_;
    }

  private:
    std::vector<std::uint8_t> bytes_;
};

// Minimal PE32+ image: headers + one executable section. Enough for the
// tool's export/import walking; nothing here is ever loaded.
std::vector<std::uint8_t> build_pe(const std::string& dll_name,
                                   const std::vector<ExportDef>& exports,
                                   const std::vector<ImportDef>& imports)
{
    Blob blob;
    // body stubs live outside the export region so the parser reads them as
    // real bodies, never as forwarder strings
    std::vector<std::uint32_t> body_rvas;
    for (const auto& def : exports) {
        if (def.forward[0] == '\0') {
            const std::uint8_t stub[] = {0x48, 0x89, 0x5c, 0x24, 0x08, 0xc3};
            body_rvas.push_back(blob.append_bytes(stub, sizeof(stub)));
        } else {
            body_rvas.push_back(0);
        }
    }

    // export region: directory, arrays, then strings - the strings stay
    // inside [exp_rva, exp_rva + exp_size), which is exactly the tool's
    // forwarder classification range
    const std::uint32_t exp_rva = blob.rva();
    blob.advance(40); // IMAGE_EXPORT_DIRECTORY, fields patched below
    const std::uint32_t names_arr_rva = blob.advance_and_mark(exports.size() * 4);
    const std::uint32_t funcs_arr_rva = blob.advance_and_mark(exports.size() * 4);
    const std::uint32_t ords_arr_rva = blob.advance_and_mark(exports.size() * 2);
    const std::uint32_t dll_name_rva = blob.append_string(dll_name);
    std::vector<std::uint32_t> name_rvas;
    std::vector<std::uint32_t> fwd_rvas;
    for (const auto& def : exports) {
        name_rvas.push_back(blob.append_string(def.name));
        fwd_rvas.push_back(def.forward[0] != '\0' ? blob.append_string(def.forward) : 0);
    }
    const std::uint32_t exp_size = blob.rva() - exp_rva;
    for (std::size_t i = 0; i < exports.size(); ++i) {
        blob.patch_u32(names_arr_rva + static_cast<std::uint32_t>(4 * i), name_rvas[i]);
        const std::uint32_t slot = exports[i].forward[0] != '\0' ? fwd_rvas[i] : body_rvas[i];
        blob.patch_u32(funcs_arr_rva + static_cast<std::uint32_t>(4 * i), slot);
        blob.patch_u32(ords_arr_rva + static_cast<std::uint32_t>(2 * i),
                       static_cast<std::uint32_t>(i));
    }
    blob.patch_u32(exp_rva + 12, dll_name_rva); // Name
    blob.patch_u32(exp_rva + 16, 1);            // Base
    blob.patch_u32(exp_rva + 20, static_cast<std::uint32_t>(exports.size()));
    blob.patch_u32(exp_rva + 24, static_cast<std::uint32_t>(exports.size()));
    blob.patch_u32(exp_rva + 28, funcs_arr_rva); // AddressOfFunctions
    blob.patch_u32(exp_rva + 32, names_arr_rva); // AddressOfNames
    blob.patch_u32(exp_rva + 36, ords_arr_rva);  // AddressOfNameOrdinals

    // import region: descriptor table first, then INT/IAT arrays, then the
    // hint/name entries and dll names
    std::uint32_t import_rva = 0;
    if (!imports.empty()) {
        blob.align();
        import_rva = blob.rva();
        blob.advance(20 * (imports.size() + 1));
        struct Arrays {
            std::uint32_t int_rva = 0;
            std::uint32_t iat_rva = 0;
        };
        std::vector<Arrays> arrays;
        for (const auto& def : imports) {
            const std::size_t slots = def.functions.size() + 1;
            Arrays a;
            a.int_rva = blob.rva();
            blob.advance(8 * slots);
            a.iat_rva = blob.rva();
            blob.advance(8 * slots);
            arrays.push_back(a);
        }
        std::vector<std::vector<std::uint32_t>> entries;
        std::vector<std::uint32_t> dll_name_rvas;
        for (const auto& def : imports) {
            dll_name_rvas.push_back(blob.append_string(def.dll));
            std::vector<std::uint32_t> one;
            for (const char* fn : def.functions) {
                one.push_back(blob.append_hint_name(fn));
            }
            entries.push_back(one);
        }
        for (std::size_t i = 0; i < imports.size(); ++i) {
            const std::uint32_t desc = import_rva + static_cast<std::uint32_t>(20 * i);
            blob.patch_u32(desc, arrays[i].int_rva);      // OriginalFirstThunk
            blob.patch_u32(desc + 12, dll_name_rvas[i]);  // Name
            blob.patch_u32(desc + 16, arrays[i].iat_rva); // FirstThunk
            for (std::size_t j = 0; j < entries[i].size(); ++j) {
                blob.patch_u32(arrays[i].int_rva + static_cast<std::uint32_t>(8 * j),
                               entries[i][j]);
                blob.patch_u32(arrays[i].iat_rva + static_cast<std::uint32_t>(8 * j),
                               entries[i][j]);
            }
        }
    }

    // headers
    std::vector<std::uint8_t> headers(0x400, 0);
    headers[0] = 'M';
    headers[1] = 'Z';
    const std::uint32_t e_lfanew = 0x40;
    std::memcpy(headers.data() + 0x3c, &e_lfanew, sizeof(e_lfanew));
    const char pe_sig[] = {'P', 'E', '\0', '\0'};
    std::memcpy(headers.data() + 0x40, pe_sig, sizeof(pe_sig));
    const std::uint16_t machine = 0x8664;
    std::memcpy(headers.data() + 0x44, &machine, sizeof(machine));
    const std::uint16_t num_sections = 1;
    std::memcpy(headers.data() + 0x46, &num_sections, sizeof(num_sections));
    const std::uint16_t opt_size = 240;
    std::memcpy(headers.data() + 0x54, &opt_size, sizeof(opt_size));
    const std::uint16_t characteristics = 0x0022;
    std::memcpy(headers.data() + 0x56, &characteristics, sizeof(characteristics));
    const std::size_t opt = 0x58;
    const std::uint16_t magic = 0x20B;
    std::memcpy(headers.data() + opt, &magic, sizeof(magic));
    const std::uint32_t section_alignment = 0x1000;
    const std::uint32_t file_alignment = 0x200;
    std::memcpy(headers.data() + opt + 32, &section_alignment, sizeof(section_alignment));
    std::memcpy(headers.data() + opt + 36, &file_alignment, sizeof(file_alignment));
    const std::uint16_t subsystem = 3;
    std::memcpy(headers.data() + opt + 68, &subsystem, sizeof(subsystem));
    const std::uint32_t rva_count = 16;
    std::memcpy(headers.data() + opt + 108, &rva_count, sizeof(rva_count));
    if (!exports.empty()) {
        std::memcpy(headers.data() + opt + 112, &exp_rva, 4);
        std::memcpy(headers.data() + opt + 116, &exp_size, 4);
    }
    if (import_rva != 0) {
        const std::uint32_t import_size = 20 * static_cast<std::uint32_t>(imports.size() + 1);
        std::memcpy(headers.data() + opt + 120, &import_rva, 4);
        std::memcpy(headers.data() + opt + 124, &import_size, 4);
    }
    const std::size_t sec = opt + 240;
    std::memcpy(headers.data() + sec, ".text\0\0\0", 8);
    const std::uint32_t virtual_size = static_cast<std::uint32_t>(blob.bytes().size());
    std::memcpy(headers.data() + sec + 8, &virtual_size, 4);
    std::memcpy(headers.data() + sec + 12, &kSectionRva, 4);
    const std::uint32_t raw_size =
        (virtual_size + file_alignment - 1) / file_alignment * file_alignment;
    std::memcpy(headers.data() + sec + 16, &raw_size, 4);
    std::memcpy(headers.data() + sec + 20, &kSectionRaw, 4);
    const std::uint32_t sec_chars = 0x60000020;
    std::memcpy(headers.data() + sec + 36, &sec_chars, 4);

    std::vector<std::uint8_t> image = headers;
    image.resize(kSectionRaw, 0);
    image.insert(image.end(), blob.bytes().begin(), blob.bytes().end());
    image.resize(kSectionRaw + raw_size, 0);
    return image;
}

void emit_image(const fs::path& path, const std::string& dll_name,
                const std::vector<ExportDef>& exports, const std::vector<ImportDef>& imports)
{
    const auto image = build_pe(dll_name, exports, imports);
    write_file(path, std::string(image.begin(), image.end()));
}

void write_system_dir(const fs::path& dir, const std::vector<ImportDef>& importer_imports)
{
    fs::create_directories(dir);
    emit_image(dir / "ntdll.dll", "ntdll.dll", {}, {});
    emit_image(dir / "kernel32.dll", "kernel32.dll",
               {{"FwdReach", "KERNELBASE.TgtBody"},
                {"FwdBroken", "OTHER.Nowhere"},
                {"Dup", ""},
                {"K32Only", ""}},
               {});
    emit_image(dir / "kernelbase.dll", "kernelbase.dll",
               {{"TgtBody", ""}, {"Dup", ""}, {"OnlyKb", ""}}, {});
    emit_image(dir / "ucrtbase.dll", "ucrtbase.dll", {}, importer_imports);
}

std::string run_capture(const std::string& cmd, int& exit_code)
{
    // std::system + a redirect into a log file: the proven invocation shape
    // here (a piped cmd line trips the shell's quote handling)
    const auto log = fs::temp_directory_path() / "sheller_apiset_ev_last.log";
    const std::string line = cmd + " > \"" + log.string() + "\" 2>&1";
    exit_code = std::system(line.c_str());
    std::ifstream in(log, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

struct ToolRun {
    int exit_code = -1;
    std::string output;
};

// Runs the tool against one fixture dir; the anchor is resolved by letting
// the named mismatch state the real hash (cached per directory).
ToolRun run_tool(const fs::path& dir, const fs::path& evidence, const fs::path* map,
                 const fs::path* resolve, const fs::path* schema = nullptr)
{
    static std::map<std::string, std::string> anchors;
    auto cached = anchors.find(dir.string());
    if (cached == anchors.end()) {
        const std::string probe = std::string(kPython) + " \"" + kToolScript + "\" \"" +
                                  dir.string() + "\" 0x0 --evidence \"" +
                                  (dir / "probe.json").string() + "\"";
        int probe_code = -1;
        const std::string probe_out = run_capture(probe, probe_code);
        const auto pos = probe_out.find("is 0x");
        EXPECT_NE(pos, std::string::npos) << "anchor probe failed: " << probe_out;
        if (pos != std::string::npos) {
            cached = anchors.emplace(dir.string(), probe_out.substr(pos + 3, 18)).first;
        } else {
            cached = anchors.emplace(dir.string(), "0x0").first;
        }
    }
    std::string cmd = std::string(kPython) + " \"" + kToolScript + "\" \"" + dir.string() + "\" " +
                      cached->second + " --evidence \"" + evidence.string() + "\"";
    if (map != nullptr) {
        cmd += " --map \"" + map->string() + "\"";
    }
    if (resolve != nullptr) {
        cmd += " --resolve \"" + resolve->string() + "\"";
    }
    if (schema != nullptr) {
        cmd += " --schema \"" + schema->string() + "\"";
    }
    ToolRun run;
    run.output = run_capture(cmd, run.exit_code);
    return run;
}

ToolRun run_checker(const fs::path& evidence, const fs::path& checks)
{
    const std::string cmd = std::string(kPython) + " \"" + kCheckScript + "\" \"" +
                            evidence.string() + "\" \"" + checks.string() + "\"";
    ToolRun run;
    run.output = run_capture(cmd, run.exit_code);
    return run;
}

void expect_checks(const fs::path& evidence, const std::string& checks_text)
{
    const auto checks = evidence.parent_path() / "checks.json";
    write_file(checks, checks_text);
    const ToolRun check = run_checker(evidence, checks);
    EXPECT_EQ(check.exit_code, 0) << check.output;
}

} // namespace

TEST(ApisetEvidence, ForwardSlotNamesCountAndTargetNamesDoNot)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_ev_fwd";
    fs::remove_all(dir);
    write_system_dir(dir, {{{"api-ms-win-core-fwd-r-l1-1-0.dll", {"fwdreach"}}}});
    const auto evidence = dir / "evidence.json";
    const ToolRun run = run_tool(dir, evidence, nullptr, nullptr);
    ASSERT_EQ(run.exit_code, 0) << run.output;

    // funca's slot makes kernel32 a (unique, unconfirmed) candidate while
    // the forward TARGET name never enters kernel32's coverage: the target
    // module answers it instead
    expect_checks(evidence, R"({
"contracts": {
  "api-ms-win-core-fwd-r-l1-1-0": {
    "status": "unique-candidate-unconfirmed",
    "candidates": ["kernel32.dll"],
    "coverage": {"kernel32.dll": {"fwdreach": "forward"},
                 "kernelbase.dll": {"fwdreach": "absent"}}
  }
},
"forwarders": {
  "kernel32.dll": {"fwdreach": {"target": "kernelbase.tgtbody",
                                "status": "reachable"}}
}})");
}

TEST(ApisetEvidence, UnreachableForwardAndMissingNamesStayNamed)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_ev_broken";
    fs::remove_all(dir);
    write_system_dir(dir, {{{"api-ms-win-core-fwd-b-l1-1-0.dll", {"fwdbroken"}},
                            {"api-ms-win-core-missing-l1-1-0.dll", {"nowhere"}}}});
    const auto evidence = dir / "evidence.json";
    const ToolRun run = run_tool(dir, evidence, nullptr, nullptr);
    ASSERT_EQ(run.exit_code, 0) << run.output;

    // a forward into a module outside the scanned set is not usable
    // coverage, and a name no host exports fails named - neither is guessed
    expect_checks(evidence, R"({
"contracts": {
  "api-ms-win-core-fwd-b-l1-1-0": {
    "status": "zero-candidate",
    "candidates": ["kernel32.dll"],
    "coverage": {"kernel32.dll": {"fwdbroken": "forward"}}
  },
  "api-ms-win-core-missing-l1-1-0": {
    "status": "zero-candidate",
    "candidates": []
  }
},
"forwarders": {
  "kernel32.dll": {"fwdbroken": {"target": "other.nowhere",
                                 "status": "module-not-scanned"}}
}})");
}

TEST(ApisetEvidence, UnconfirmedContractsKeepTheMapWithheld)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_ev_hold";
    fs::remove_all(dir);
    write_system_dir(dir, {{{"api-ms-win-core-dup-l1-1-0.dll", {"dup"}},
                            {"api-ms-win-core-onlykb-l1-1-0.dll", {"onlykb"}}}});
    const auto evidence = dir / "evidence.json";
    const auto map = dir / "map.json";

    // ambiguous and unique-candidate alike: no reviewed map without schema
    // or recorded review
    const ToolRun run = run_tool(dir, evidence, &map, nullptr);
    ASSERT_EQ(run.exit_code, 0) << run.output;
    EXPECT_FALSE(fs::exists(map)) << run.output;
    EXPECT_NE(run.output.find("map NOT written"), std::string::npos) << run.output;
    EXPECT_NE(run.output.find("ambiguous"), std::string::npos) << run.output;
    EXPECT_NE(run.output.find("unique-candidate-unconfirmed"), std::string::npos) << run.output;

    expect_checks(evidence, R"({
"contracts": {
  "api-ms-win-core-dup-l1-1-0": {
    "status": "ambiguous",
    "candidates": ["kernel32.dll", "kernelbase.dll"],
    "coverage": {"kernel32.dll": {"dup": "body"},
                 "kernelbase.dll": {"dup": "body"}}
  },
  "api-ms-win-core-onlykb-l1-1-0": {
    "status": "unique-candidate-unconfirmed",
    "candidates": ["kernelbase.dll"],
    "coverage": {"kernelbase.dll": {"onlykb": "body"}}
  }
}})");
}

TEST(ApisetEvidence, RecordedReviewUnlocksTheMap)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_ev_review";
    fs::remove_all(dir);
    write_system_dir(dir, {{{"api-ms-win-core-dup-l1-1-0.dll", {"dup"}},
                            {"api-ms-win-core-onlykb-l1-1-0.dll", {"onlykb"}}}});
    const auto evidence = dir / "evidence.json";
    const auto map = dir / "map.json";
    const auto resolve = dir / "resolve.json";
    write_file(resolve, R"({
"api-ms-win-core-dup-l1-1-0": {
  "host": "kernelbase.dll",
  "basis": "both bodies are real; kernelbase is the reviewed carrier"
},
"api-ms-win-core-onlykb-l1-1-0": {
  "host": "kernelbase.dll",
  "basis": "sole covering host confirmed by recorded review"
}
})");
    const ToolRun run = run_tool(dir, evidence, &map, &resolve);
    ASSERT_EQ(run.exit_code, 0) << run.output;
    ASSERT_TRUE(fs::exists(map)) << run.output;
    EXPECT_NE(run.output.find("all contracts confirmed"), std::string::npos) << run.output;

    const auto map_bytes = read_file(map);
    const std::string map_text(map_bytes.begin(), map_bytes.end());
    EXPECT_NE(map_text.find("\"host\": \"kernelbase.dll\""), std::string::npos);

    // review cannot claim a host that lacks an observed function: named
    // refusal, no map
    const auto bad_resolve = dir / "bad.json";
    write_file(bad_resolve, R"({
"api-ms-win-core-onlykb-l1-1-0": {
  "host": "kernel32.dll",
  "basis": "claims a function kernel32 does not export"
}
})");
    const auto bad_map = dir / "bad_map.json";
    const ToolRun bad = run_tool(dir, dir / "bad_evidence.json", &bad_map, &bad_resolve);
    EXPECT_NE(bad.exit_code, 0) << bad.output;
    EXPECT_NE(bad.output.find("onlykb"), std::string::npos) << bad.output;
    EXPECT_FALSE(fs::exists(bad_map)) << bad.output;
}

TEST(ApisetEvidence, ReviewCannotRescueAnUncoveredFunction)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_ev_rescue";
    fs::remove_all(dir);
    write_system_dir(dir, {{{"api-ms-win-core-missing-l1-1-0.dll", {"nowhere"}}}});
    const auto resolve = dir / "resolve.json";
    write_file(resolve, R"({
"api-ms-win-core-missing-l1-1-0": {
  "host": "kernelbase.dll",
  "basis": "claims nowhere"
}
})");
    const auto map = dir / "map.json";
    const ToolRun run = run_tool(dir, dir / "evidence.json", &map, &resolve);
    EXPECT_NE(run.exit_code, 0) << run.output;
    EXPECT_NE(run.output.find("nowhere"), std::string::npos) << run.output;
    EXPECT_FALSE(fs::exists(map)) << run.output;
}

TEST(ApisetEvidence, ConfirmationCannotRescueUnreachableForwardChains)
{
    // Both confirmation routes must reject a broken first hop, a broken
    // later hop and a cycle, even though the requested slot exists.
    for (const std::string kind : {"missing", "chain", "cycle", "reachable"}) {
        const auto dir = fs::temp_directory_path() / ("sheller_apiset_ev_confirm_" + kind);
        fs::remove_all(dir);
        write_system_dir(dir, {{"api-ms-win-core-test-l1-1-0.dll", {"fwdreach"}}});
        if (kind == "missing") {
            emit_image(dir / "kernelbase.dll", "kernelbase.dll", {{"Other", ""}}, {});
        } else if (kind == "chain") {
            emit_image(dir / "kernelbase.dll", "kernelbase.dll", {{"TgtBody", "NTDLL.Missing"}},
                       {});
        } else if (kind == "cycle") {
            emit_image(dir / "kernelbase.dll", "kernelbase.dll", {{"TgtBody", "KERNEL32.FwdReach"}},
                       {});
        } else {
            emit_image(dir / "kernelbase.dll", "kernelbase.dll", {{"TgtBody", "KERNEL32.K32Only"}},
                       {});
        }
        const auto schema = dir / "schema.json";
        write_file(schema, R"({"schema":1,"kind":"apiset-schema","contracts":{
"api-ms-win-core-test-l1-1-0":[{"importer":"","host":"kernel32.dll"}]}})");
        const auto resolve = dir / "resolve.json";
        write_file(resolve, R"({"api-ms-win-core-test-l1-1-0":{
"host":"kernel32.dll","basis":"explicit fixture review"}})");
        const auto schema_map = dir / "schema-map.json";
        const auto evidence = dir / "schema-evidence.json";
        const auto schema_run = run_tool(dir, evidence, &schema_map, nullptr, &schema);
        ASSERT_EQ(schema_run.exit_code, 0) << schema_run.output;
        EXPECT_EQ(fs::exists(schema_map), kind == "reachable") << schema_run.output;
        if (kind != "reachable") {
            expect_checks(evidence, R"({"contracts":{
"api-ms-win-core-test-l1-1-0":{"status":"schema-conflict"}}})");
        }
        const auto review_map = dir / "review-map.json";
        const auto review_run = run_tool(dir, dir / "review-evidence.json", &review_map, &resolve);
        EXPECT_EQ(review_run.exit_code == 0, kind == "reachable") << review_run.output;
        EXPECT_EQ(fs::exists(review_map), kind == "reachable") << review_run.output;
        if (kind != "reachable") {
            EXPECT_NE(review_run.output.find("reachable exports"), std::string::npos);
        }
    }
}

TEST(ApisetEvidence, SchemaPreservesDefaultAndUnobservedImporterBranches)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_ev_branches";
    fs::remove_all(dir);
    write_system_dir(dir, {{"api-ms-win-core-dup-l1-1-0.dll", {"dup"}}});
    const auto schema = dir / "schema.json";
    write_file(schema, R"({"schema":1,"kind":"apiset-schema","contracts":{
"api-ms-win-core-dup-l1-1-0":[
{"importer":"","host":"kernel32.dll"},
{"importer":"ucrtbase.dll","host":"kernelbase.dll"},
{"importer":"unobserved.dll","host":"ntdll.dll"}]}})");
    const auto map = dir / "map.json";
    const auto run = run_tool(dir, dir / "evidence.json", &map, nullptr, &schema);
    ASSERT_EQ(run.exit_code, 0) << run.output;
    ASSERT_TRUE(fs::exists(map)) << run.output;
    expect_checks(map, R"({"entries":[
{"contract":"api-ms-win-core-dup-l1-1-0","host":"kernel32.dll"},
{"contract":"api-ms-win-core-dup-l1-1-0","importer":"ucrtbase.dll","host":"kernelbase.dll"},
{"contract":"api-ms-win-core-dup-l1-1-0","importer":"unobserved.dll","host":"ntdll.dll"}]})");

    // A schema without a default must never gain one from observations.
    write_file(schema, R"({"schema":1,"kind":"apiset-schema","contracts":{
"api-ms-win-core-dup-l1-1-0":[{"importer":"ucrtbase.dll","host":"kernelbase.dll"}]}})");
    const auto scoped_run = run_tool(dir, dir / "scoped-evidence.json", &map, nullptr, &schema);
    ASSERT_EQ(scoped_run.exit_code, 0) << scoped_run.output;
    expect_checks(map, R"({"entries":[
{"contract":"api-ms-win-core-dup-l1-1-0","importer":"ucrtbase.dll","host":"kernelbase.dll"}]})");
}
