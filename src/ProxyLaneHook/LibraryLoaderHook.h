#pragma once
#include <windows.h>

namespace LibraryLoaderHook
{
    // Loader APIs moved independently of process-creation APIs. Select one
    // provider by export availability, without changing the latter's mapping.
    inline const char* ModuleName(
        decltype(&::GetModuleHandleW) getModule = ::GetModuleHandleW,
        decltype(&::GetProcAddress) getExport = ::GetProcAddress)
    {
        HMODULE kernelBase = getModule(L"KernelBase.dll");
        return kernelBase && getExport(kernelBase, "LoadLibraryExW")
            ? "KernelBase.dll" : "Kernel32.dll";
    }
}
