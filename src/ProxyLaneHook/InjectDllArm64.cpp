#include "InjectDllArm64.h"
#if defined(_M_ARM64) && !defined(_M_ARM64EC)
#include "ProcessArchitecture.h"
#include "../remotecode/arm64/BootstrapBytes.h"
#include <psapi.h>
#include <stddef.h>
#include <vector>
#include <memory>
#include <string.h>

namespace
{
    struct RemoteString
    {
        USHORT length, maximumLength;
        DWORD padding;
        ULONG64 buffer;
    };
    struct Parameters
    {
        ULONG64 loadDll, getProcedureAddress, continueThread, originalPc;
        RemoteString dllName, entryName;
        ULONG64 pipe;
        DWORD state;
        LONG status;
        ULONG64 module, entry;
    };
    static_assert(sizeof(Parameters) == 96, "Bootstrap parameter layout");
    static_assert(offsetof(Parameters, dllName) == 32 && offsetof(Parameters, entryName) == 48 &&
        offsetof(Parameters, pipe) == 64 && offsetof(Parameters, state) == 72 &&
        offsetof(Parameters, status) == 76 && offsetof(Parameters, module) == 80 &&
        offsetof(Parameters, entry) == 88, "Bootstrap parameter offsets");
    static_assert(sizeof(CONTEXT) == 0x390 && offsetof(CONTEXT, X0) == 8 &&
        offsetof(CONTEXT, Sp) == 0x100 && offsetof(CONTEXT, Pc) == 0x108 &&
        offsetof(CONTEXT, V) == 0x110 && offsetof(CONTEXT, Fpcr) == 0x310 &&
        offsetof(CONTEXT, Fpsr) == 0x314 && CONTEXT_FULL == 0x400007,
        "Bootstrap must match Windows ARM64 CONTEXT");

    bool Read(HANDLE process, ULONG_PTR address, void* data, SIZE_T size)
    {
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<void*>(address), data, size, &read)) return false;
        if (read == size) return true;
        SetLastError(ERROR_PARTIAL_COPY);
        return false;
    }

    bool Headers(HANDLE process, ULONG_PTR base, IMAGE_NT_HEADERS64& nt)
    {
        IMAGE_DOS_HEADER dos = {};
        if (!Read(process, base, &dos, sizeof(dos))) return false;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos) || dos.e_lfanew > 0x100000)
        { SetLastError(ERROR_BAD_EXE_FORMAT); return false; }
        if (!Read(process, base + dos.e_lfanew, &nt, sizeof(nt))) return false;
        if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 ||
            nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt.OptionalHeader.SizeOfImage < static_cast<DWORD>(dos.e_lfanew) + sizeof(nt))
        { SetLastError(ERROR_NOT_SUPPORTED); return false; }
        return true;
    }

    bool CompatibleArm64Image(HANDLE process, ULONG_PTR base, const IMAGE_NT_HEADERS64& nt)
    {
        // ARM64X metadata describes the file's dual ABI, not the process's
        // active ABI. cmd.exe and Windows PowerShell can run its native view.
        // Keep the in-memory ARM64 PE check, and require a positive runtime
        // machine query for hybrids instead of rejecting all metadata.
        if (nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) return true;
        const IMAGE_DATA_DIRECTORY& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (!dir.VirtualAddress || !dir.Size) return true;
        const SIZE_T offset = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer);
        if (dir.VirtualAddress > nt.OptionalHeader.SizeOfImage ||
            dir.Size > nt.OptionalHeader.SizeOfImage - dir.VirtualAddress || dir.Size < sizeof(DWORD))
        { SetLastError(ERROR_BAD_EXE_FORMAT); return false; }
        DWORD size = 0;
        if (!Read(process, base + dir.VirtualAddress, &size, sizeof(size))) return false;
        if (size < offset + sizeof(ULONG64)) return true;
        if (dir.Size < offset + sizeof(ULONG64))
        { SetLastError(ERROR_BAD_EXE_FORMAT); return false; }
        ULONG64 chpe = 0;
        if (!Read(process, base + dir.VirtualAddress + offset, &chpe, sizeof(chpe))) return false;
        if (!chpe) return true;
        return ProcessArchitecture::RequireNativeArm64Hybrid(process) != FALSE;
    }

    struct NativeApiPaths
    {
        WCHAR local[32768], image[32768], mapped[32768];
    };
    struct FreeNativeApiPaths
    {
        void operator()(NativeApiPaths* paths) const
        {
            DWORD error = GetLastError();
            HeapFree(GetProcessHeap(), 0, paths);
            SetLastError(error);
        }
    };

    bool ResolveNativeApis(HANDLE process, Parameters& params)
    {
        HMODULE local = GetModuleHandleW(L"ntdll.dll");
        if (!local) return false;
        // This runs on the application's thread when it creates a child.
        // Three long-path buffers would consume 192 KiB of its stack; Firefox
        // can create children on threads with a smaller remaining stack.
        std::unique_ptr<NativeApiPaths, FreeNativeApiPaths> paths(
            static_cast<NativeApiPaths*>(HeapAlloc(GetProcessHeap(), 0, sizeof(NativeApiPaths))));
        if (!paths) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return false; }
        DWORD length = GetMappedFileNameW(GetCurrentProcess(), local, paths->local, _countof(paths->local));
        if (!length) return false;
        if (length >= _countof(paths->local)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return false; }
        DWORD imageLength = _countof(paths->image);
        if (!QueryFullProcessImageNameW(process, PROCESS_NAME_NATIVE, paths->image, &imageLength)) return false;
        IMAGE_NT_HEADERS64 localNt = {};
        if (!Headers(GetCurrentProcess(), reinterpret_cast<ULONG_PTR>(local), localNt)) return false;

        // VirtualQueryEx works before the initial loader has populated PEB.Ldr.
        // Compare full device paths, not just basenames, then validate the images.
        ULONG_PTR address = 0, lastAllocation = 0, remoteNtdll = 0;
        bool mainVerified = false;
        MEMORY_BASIC_INFORMATION memory = {};
        while (VirtualQueryEx(process, reinterpret_cast<void*>(address), &memory, sizeof(memory)))
        {
            ULONG_PTR base = reinterpret_cast<ULONG_PTR>(memory.AllocationBase);
            if (memory.Type == MEM_IMAGE && base != lastAllocation)
            {
                lastAllocation = base;
                length = GetMappedFileNameW(process, memory.AllocationBase, paths->mapped, _countof(paths->mapped));
                if (!length) return false;
                if (length >= _countof(paths->mapped)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return false; }
                if (!_wcsicmp(paths->mapped, paths->image))
                {
                    IMAGE_NT_HEADERS64 nt = {};
                    if (!Headers(process, base, nt) || !CompatibleArm64Image(process, base, nt)) return false;
                    mainVerified = true;
                }
                if (!_wcsicmp(paths->mapped, paths->local))
                {
                    IMAGE_NT_HEADERS64 nt = {};
                    if (!Headers(process, base, nt)) return false;
                    if (nt.FileHeader.TimeDateStamp != localNt.FileHeader.TimeDateStamp ||
                        nt.OptionalHeader.SizeOfImage != localNt.OptionalHeader.SizeOfImage)
                    { SetLastError(ERROR_REVISION_MISMATCH); return false; }
                    remoteNtdll = base;
                }
                if (mainVerified && remoteNtdll) break;
            }
            ULONG_PTR next = reinterpret_cast<ULONG_PTR>(memory.BaseAddress) + memory.RegionSize;
            if (next <= address) break;
            address = next;
        }
        if (!mainVerified || !remoteNtdll) { SetLastError(ERROR_MOD_NOT_FOUND); return false; }
        const char* names[] = { "LdrLoadDll", "LdrGetProcedureAddress", "NtContinue" };
        ULONG64* destinations[] = { &params.loadDll, &params.getProcedureAddress, &params.continueThread };
        for (size_t i = 0; i < _countof(names); ++i)
        {
            ULONG_PTR localAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(local, names[i]));
            ULONG_PTR rva = localAddress - reinterpret_cast<ULONG_PTR>(local);
            if (!localAddress || rva >= localNt.OptionalHeader.SizeOfImage)
            { SetLastError(ERROR_PROC_NOT_FOUND); return false; }
            *destinations[i] = remoteNtdll + rva;
        }
        return true;
    }

    struct RemoteAllocation
    {
        HANDLE process;
        void* data;
        void* code;
        bool published;
        explicit RemoteAllocation(HANDLE p) : process(p), data(NULL), code(NULL), published(false) {}
        ~RemoteAllocation()
        {
            DWORD error = GetLastError();
            if (!published)
            {
                if (code) VirtualFreeEx(process, code, 0, MEM_RELEASE);
                if (data) VirtualFreeEx(process, data, 0, MEM_RELEASE);
            }
            SetLastError(error);
        }
    };
    bool Write(HANDLE process, void* destination, const void* source, SIZE_T size)
    {
        SIZE_T written = 0;
        if (!WriteProcessMemory(process, destination, source, size, &written)) return false;
        if (written == size) return true;
        SetLastError(ERROR_PARTIAL_COPY);
        return false;
    }
}

int InjectDllArm64W(HANDLE process, HANDLE suspendedThread, LPCWSTR dll, LPCSTR pipe)
{
    if (!process || !dll || !pipe || !dll[0] || !pipe[0])
    { SetLastError(ERROR_INVALID_PARAMETER); return -1; }
    if (!ProcessArchitecture::RequireDirectInjection(process)) return -1;
    DWORD pid = GetProcessId(process);
    if (!pid) return -1;
    if (pid == GetCurrentProcessId() || (suspendedThread && GetProcessIdOfThread(suspendedThread) != pid))
    { SetLastError(ERROR_INVALID_PARAMETER); return -1; }
    size_t dllLength = wcsnlen(dll, 32767), pipeLength = strnlen(pipe, MAX_PATH);
    if (!dllLength || dllLength >= 32767 || !pipeLength || pipeLength >= MAX_PATH ||
        !((dllLength >= 3 && dll[1] == L':' && dll[2] == L'\\') ||
          (dllLength >= 3 && dll[0] == L'\\' && dll[1] == L'\\')))
    { SetLastError(ERROR_INVALID_PARAMETER); return -1; }

    Parameters params = {};
    if (!ResolveNativeApis(process, params)) return -1;
    CONTEXT context = {};
    if (suspendedThread)
    {
        context.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(suspendedThread, &context)) return -1;
        if (!context.Pc || (context.Pc & 3) || (context.Sp & 15))
        { SetLastError(ERROR_INVALID_DATA); return -1; }
        params.originalPc = context.Pc;
    }
    const char entry[] = "gp_HookWinsock";
    const size_t dllBytes = (dllLength + 1) * sizeof(WCHAR);
    std::vector<BYTE> payload(sizeof(params) + dllBytes + sizeof(entry) + pipeLength + 1, 0);
    RemoteAllocation remote(process);
    remote.data = VirtualAllocEx(process, NULL, payload.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote.data) return -1;
    remote.code = VirtualAllocEx(process, NULL, sizeof(Arm64Bootstrap::Code), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote.code) return -1;
    ULONG64 base = reinterpret_cast<ULONG64>(remote.data);
    params.dllName.length = static_cast<USHORT>(dllLength * sizeof(WCHAR));
    params.dllName.maximumLength = static_cast<USHORT>(dllBytes);
    params.dllName.buffer = base + sizeof(params);
    params.entryName.length = sizeof(entry) - 1;
    params.entryName.maximumLength = sizeof(entry);
    params.entryName.buffer = params.dllName.buffer + dllBytes;
    params.pipe = params.entryName.buffer + sizeof(entry);
    memcpy(payload.data(), &params, sizeof(params));
    memcpy(payload.data() + sizeof(params), dll, dllBytes);
    memcpy(payload.data() + sizeof(params) + dllBytes, entry, sizeof(entry));
    memcpy(payload.data() + sizeof(params) + dllBytes + sizeof(entry), pipe, pipeLength + 1);
    BYTE code[sizeof(Arm64Bootstrap::Code)];
    memcpy(code, Arm64Bootstrap::Code, sizeof(code));
    memcpy(code + Arm64Bootstrap::ParameterAddressOffset, &base, sizeof(base));
    if (!Write(process, remote.data, payload.data(), payload.size()) ||
        !Write(process, remote.code, code, sizeof(code))) return -1;
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(process, remote.code, sizeof(code), PAGE_EXECUTE_READ, &oldProtect) ||
        !FlushInstructionCache(process, remote.code, sizeof(code))) return -1;

    if (suspendedThread)
    {
        context.ContextFlags = CONTEXT_CONTROL;
        context.Pc = reinterpret_cast<ULONG64>(remote.code) + Arm64Bootstrap::StartupOffset;
        if (!SetThreadContext(suspendedThread, &context)) return -1;
    }
    else
    {
        LPTHREAD_START_ROUTINE entryPoint = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            static_cast<BYTE*>(remote.code) + Arm64Bootstrap::ThreadOffset);
        HANDLE thread = CreateRemoteThread(process, NULL, 0, entryPoint, remote.data, 0, NULL);
        if (!thread) return -1;
        CloseHandle(thread);
    }
    // Async PRC registration reports actual hook startup. Neither this return
    // nor a notification proves the bootstrap has finished executing; keep both
    // allocations until target exit rather than racing remote instruction fetch.
    remote.published = true;
    SetLastError(ERROR_SUCCESS);
    return 1;
}
#endif
