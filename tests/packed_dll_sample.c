// Corpus source for tests/packed.dll (UPX-packed) and tests/packed.dll.unp
// (upx -d reference). Rebuild: vcvars64 && cl /nologo /W4 /O1 /MT /LD
// tests\packed_dll_sample.c user32.lib /Fe:<tmp>\packed_orig.dll, then
//   upx -o tests\packed.dll <tmp>\packed_orig.dll
//   upx -d -o tests\packed.dll.unp tests\packed.dll
// x64 /MT, imports kernel32 + user32 (system-dependency admission:
// verified system DLLs preload through the runner's import
// table). One named export keeps LoadLibrary/GetProcAddress usable. Both
// auto-run paths print a distinct marker through kernel32!GetStdHandle +
// WriteFile - the NtWriteFile-on-stdout path the engine forwards under
// --guest-stdout: DllMain prints "hello world from dllmain" (the ATTACH
// mainline a packed DLL's unpack stub rides), the export prints
// "hello world from export".
#include <windows.h>

static volatile DWORD g_state;

static void print_line(const char* msg)
{
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(out, msg, (DWORD)lstrlenA(msg), &written, NULL);
}

__declspec(dllexport) DWORD __cdecl PackedDllTick(DWORD seed)
{
    print_line("hello world from export\n");
    const BOOL alpha = IsCharAlphaA((CHAR)(seed & 0x7F));
    g_state = alpha ? 1u : 0u;
    return g_state;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(instance);
        g_state = (DWORD)(uintptr_t)instance;
        print_line("hello world from dllmain\n");
        break;
    case DLL_PROCESS_DETACH:
        g_state = 0;
        break;
    default:
        break;
    }
    return TRUE;
}
