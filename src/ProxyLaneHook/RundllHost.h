#pragma once
#include "ProcessArchitecture.h"
#include <vector>

// Shared by GUI attachment and child/elevated launch. Resolve Vista/Win11 APIs
// dynamically so the Intel Hook retains its XP loader compatibility.
namespace RundllHost
{
    typedef BOOL (WINAPI* CreateFn)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
        LPPROCESS_INFORMATION);

    class Attributes
    {
        typedef BOOL (WINAPI* InitializeFn)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
        typedef BOOL (WINAPI* UpdateFn)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
        typedef VOID (WINAPI* DeleteFn)(LPPROC_THREAD_ATTRIBUTE_LIST);
        DeleteFn m_delete;
        std::vector<BYTE> m_storage;
        WORD m_machine;
        Attributes(const Attributes&);
        Attributes& operator=(const Attributes&);
    public:
        HANDLE handles[2];
        LPPROC_THREAD_ATTRIBUTE_LIST list;
        Attributes() : m_delete(NULL), m_machine(0), list(NULL)
        { handles[0] = handles[1] = NULL; }
        ~Attributes()
        {
            DWORD error = GetLastError();
            if (list) m_delete(list);
            if (handles[0]) CloseHandle(handles[0]);
            if (handles[1]) CloseHandle(handles[1]);
            SetLastError(error);
        }
        BOOL Initialize(const ProcessArchitecture::ProcessInfo& target,
            HANDLE process = NULL, HANDLE thread = NULL)
        {
            if (!!process != !!thread) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
            m_machine = ProcessArchitecture::RundllMachine(target);
            if (!process && !m_machine) return TRUE;
            HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
            InitializeFn initialize = reinterpret_cast<InitializeFn>(GetProcAddress(kernel, "InitializeProcThreadAttributeList"));
            UpdateFn update = reinterpret_cast<UpdateFn>(GetProcAddress(kernel, "UpdateProcThreadAttribute"));
            m_delete = reinterpret_cast<DeleteFn>(GetProcAddress(kernel, "DeleteProcThreadAttributeList"));
            if (!initialize || !update || !m_delete)
            {
                if (m_machine) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
                return TRUE; // XP uses the existing PID-based helper protocol.
            }
            if (process)
            {
                HANDLE self = GetCurrentProcess();
                if (!DuplicateHandle(self, process, self, &handles[0], 0, TRUE, DUPLICATE_SAME_ACCESS) ||
                    !DuplicateHandle(self, thread, self, &handles[1], 0, TRUE, DUPLICATE_SAME_ACCESS)) return FALSE;
            }
            const DWORD count = (process ? 1 : 0) + (m_machine ? 1 : 0);
            SIZE_T bytes = 0;
            initialize(NULL, count, 0, &bytes);
            if (!bytes) return FALSE;
            m_storage.resize(bytes);
            LPPROC_THREAD_ATTRIBUTE_LIST candidate = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(&m_storage[0]);
            if (!initialize(candidate, count, 0, &bytes)) return FALSE;
            list = candidate;
            if (process && !update(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles, sizeof(handles), NULL, NULL)) return FALSE;
            // ProcThreadAttributeValue(25, FALSE, TRUE, FALSE), Windows 11.
            return !m_machine || update(list, 0, 0x00020019, &m_machine, sizeof(m_machine), NULL, NULL);
        }
    };

    inline BOOL Create(const ProcessArchitecture::ProcessInfo& target, LPWSTR command,
        Attributes& attributes, PROCESS_INFORMATION& process, CreateFn create = CreateProcessW)
    {
        ZeroMemory(&process, sizeof(process));
        if (!ProcessArchitecture::SystemRundllDirectory(target))
        { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
        STARTUPINFOEXW startup = {};
        startup.StartupInfo.cb = attributes.list ? sizeof(startup) : sizeof(STARTUPINFOW);
        startup.lpAttributeList = attributes.list;
        typedef BOOL (WINAPI* DisableFn)(PVOID*);
        typedef BOOL (WINAPI* RevertFn)(PVOID);
        RevertFn revert = NULL;
        PVOID redirection = NULL;
        if (ProcessArchitecture::CurrentModule() == ProcessArchitecture::X86 &&
            target.process != ProcessArchitecture::X86)
        {
            HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
            DisableFn disable = reinterpret_cast<DisableFn>(GetProcAddress(kernel, "Wow64DisableWow64FsRedirection"));
            revert = reinterpret_cast<RevertFn>(GetProcAddress(kernel, "Wow64RevertWow64FsRedirection"));
            if (!disable || !revert) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
            if (!disable(&redirection)) return FALSE;
        }
        const bool verifyMachine = target.native == ProcessArchitecture::Arm64;
        BOOL result = create(NULL, command, NULL, NULL, attributes.handles[0] != NULL,
            (attributes.list ? EXTENDED_STARTUPINFO_PRESENT : 0) | (verifyMachine ? CREATE_SUSPENDED : 0),
            NULL, NULL, &startup.StartupInfo, &process);
        DWORD error = GetLastError();
        if (revert) revert(redirection);
        SetLastError(error);
        if (!result) return FALSE;
        if (verifyMachine)
        {
            ProcessArchitecture::ProcessInfo actual;
            result = ProcessArchitecture::Query(process.hProcess, actual);
            if (result && (actual.process != target.process || actual.native != target.native))
            { SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH); result = FALSE; }
            if (result) result = ResumeThread(process.hThread) != static_cast<DWORD>(-1);
            if (!result)
            {
                error = GetLastError();
                TerminateProcess(process.hProcess, error);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                ZeroMemory(&process, sizeof(process));
                SetLastError(error);
                return FALSE;
            }
        }
        return TRUE;
    }
}
