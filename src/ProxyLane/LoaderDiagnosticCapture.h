#pragma once

#include <windows.h>
#include <process.h>
#include <sddl.h>
#include <string.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

// Optional, current-session DBWIN listener. Diagnostic messages never change
// injection state. The shared buffer is released before filtering or queuing.
class LoaderDiagnosticCapture
{
public:
    struct Record {
        DWORD processId;
        DWORD error;
        bool hookFailure;
        char stage[64], module[64], api[64];
    };
    LoaderDiagnosticCapture() { InitializeCriticalSection(&m_lock); }
    ~LoaderDiagnosticCapture() { Stop(); DeleteCriticalSection(&m_lock); }

    DWORD Start()
    {
        if (m_thread) return ERROR_SUCCESS;
        PSECURITY_DESCRIPTOR descriptor = NULL;
        HANDLE token = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return GetLastError();
        BYTE tokenUser[256];
        DWORD bytes = 0;
        BOOL gotUser = GetTokenInformation(token, TokenUser, tokenUser, sizeof(tokenUser), &bytes);
        DWORD tokenError = gotUser ? ERROR_SUCCESS : GetLastError();
        CloseHandle(token);
        if (tokenError) return tokenError;
        LPWSTR userSid = NULL;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(tokenUser)->User.Sid, &userSid))
            return GetLastError();
        // Interactive users in this session may produce output. Low integrity
        // is supported on Vista+, without importing a Vista-only entry point.
        const bool integrity = GetProcAddress(GetModuleHandleW(L"advapi32.dll"),
            "AddMandatoryAce") != NULL;
        WCHAR security[512];
        swprintf_s(security, L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)(A;;GRGW;;;IU)%s",
            userSid, integrity ? L"S:(ML;;NW;;;LW)" : L"");
        LocalFree(userSid);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(security,
            SDDL_REVISION_1, &descriptor, NULL)) return GetLastError();
        SECURITY_ATTRIBUTES attributes = { sizeof(attributes), descriptor, FALSE };
        DWORD error = ERROR_SUCCESS;
        // Never adopt another monitor's objects or signal its events.
        m_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &attributes,
            PAGE_READWRITE, 0, sizeof(Buffer), L"DBWIN_BUFFER");
        error = CreationError(m_mapping);
        if (!error) {
            m_ready = CreateEventW(&attributes, FALSE, FALSE, L"DBWIN_BUFFER_READY");
            error = CreationError(m_ready);
        }
        if (!error) {
            m_data = CreateEventW(&attributes, FALSE, FALSE, L"DBWIN_DATA_READY");
            error = CreationError(m_data);
        }
        LocalFree(descriptor);
        if (!error) {
            m_buffer = static_cast<Buffer*>(MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, sizeof(Buffer)));
            if (!m_buffer) error = GetLastError();
        }
        if (!error) {
            m_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!m_stop) error = GetLastError();
        }
        if (!error) {
            m_thread = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, Run, this, 0, NULL));
            if (!m_thread) error = ERROR_NOT_ENOUGH_MEMORY;
        }
        if (error) Stop();
        return error;
    }

    void Stop()
    {
        if (m_thread) {
            SetEvent(m_stop);
            // Worker never calls UI or waits for producers; stop is first in
            // its wait array, including during a flood of unrelated messages.
            WaitForSingleObject(m_thread, INFINITE);
            CloseHandle(m_thread);
            m_thread = NULL;
        }
        if (m_buffer) { UnmapViewOfFile(m_buffer); m_buffer = NULL; }
        Close(m_data); Close(m_ready); Close(m_mapping); Close(m_stop);
        EnterCriticalSection(&m_lock);
        m_head = m_count = m_dropped = 0;
        LeaveCriticalSection(&m_lock);
    }

    unsigned Drain(Record* records, unsigned capacity, unsigned& dropped)
    {
        EnterCriticalSection(&m_lock);
        unsigned count = m_count < capacity ? m_count : capacity;
        for (unsigned i = 0; i < count; ++i) {
            records[i] = m_records[m_head];
            m_head = (m_head + 1) % Capacity;
        }
        m_count -= count;
        dropped = m_dropped;
        m_dropped = 0;
        LeaveCriticalSection(&m_lock);
        return count;
    }

    static bool Parse(const char* text, size_t size, DWORD& error)
    {
        static const char prefix[] = "[ProxyLane.Loader.v1] stage=LoadLibraryW error=";
        const size_t start = sizeof(prefix) - 1;
        if (size < start + 10 || memcmp(text, prefix, start)) return false;
        DWORD value = 0;
        for (size_t i = start; i < start + 8; ++i) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            value = (value << 4) | digit;
        }
        size_t end = start + 8;
        // FormatMessage normalizes line endings to CRLF; raw emitters may use LF.
        if (text[end] == '\r') ++end;
        if (end + 1 >= size || text[end] != '\n' || text[end + 1] != '\0') return false;
        error = value;
        return true;
    }

    static bool ParseHookFailure(const char* text, size_t size, Record& record)
    {
        static const char prefix[] = "[ProxyLane.Hook.v1] ";
        if (size < sizeof(prefix) || !memchr(text, 0, size) ||
            memcmp(text, prefix, sizeof(prefix) - 1)) return false;
        const char* stage = strstr(text + sizeof(prefix) - 1, " | stage=");
        const char* module = stage ? strstr(stage + 9, " | module=") : NULL;
        const char* api = module ? strstr(module + 10, " | API=") : NULL;
        const char* error = api ? strstr(api + 7, " | error=") : NULL;
        if (!stage || !module || !api || !error ||
            !CopyField(record.stage, stage + 9, module) ||
            !CopyField(record.module, module + 10, api) ||
            !CopyField(record.api, api + 7, error)) return false;
        const char* digits = error + 9;
        DWORD value = 0;
        if (*digits < '0' || *digits > '9') return false;
        while (*digits >= '0' && *digits <= '9') {
            DWORD digit = *digits++ - '0';
            if (value > (MAXDWORD - digit) / 10) return false;
            value = value * 10 + digit;
        }
        if (strncmp(digits, " (0x", 4)) return false;
        record.error = value;
        record.hookFailure = true;
        // Do not decode the sender's localized ANSI text: the receiving UI
        // formats the numeric error in Unicode, independently of sender ACP.
        return true;
    }

private:
    struct Buffer { DWORD processId; char text[4096 - sizeof(DWORD)]; };
    enum { Capacity = 128 };
    HANDLE m_mapping = NULL, m_ready = NULL, m_data = NULL;
    HANDLE m_stop = NULL, m_thread = NULL;
    Buffer* m_buffer = NULL;
    CRITICAL_SECTION m_lock;
    Record m_records[Capacity];
    unsigned m_head = 0, m_count = 0, m_dropped = 0;

    LoaderDiagnosticCapture(const LoaderDiagnosticCapture&) = delete;
    LoaderDiagnosticCapture& operator=(const LoaderDiagnosticCapture&) = delete;
    static void Close(HANDLE& handle) { if (handle) CloseHandle(handle); handle = NULL; }
    static bool CopyField(char (&output)[64], const char* begin, const char* end)
    {
        size_t length = static_cast<size_t>(end - begin);
        if (!length || length >= sizeof(output)) return false;
        for (size_t i = 0; i < length; ++i) {
            if (begin[i] < 0x20 || begin[i] > 0x7e) return false;
            output[i] = begin[i];
        }
        output[length] = 0;
        return true;
    }
    static DWORD CreationError(HANDLE handle)
    {
        DWORD error = GetLastError();
        return !handle ? error : (error == ERROR_ALREADY_EXISTS ? error : ERROR_SUCCESS);
    }
    static unsigned __stdcall Run(void* context)
    {
        static_cast<LoaderDiagnosticCapture*>(context)->Receive();
        return 0;
    }
    void Receive()
    {
        HANDLE waits[] = { m_stop, m_data };
        SetEvent(m_ready);
        while (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
            // Hook initialization diagnostics are longer than loader records.
            // Copy the bounded DBWIN payload before releasing its producer.
            char text[sizeof(m_buffer->text)];
            DWORD pid = m_buffer->processId;
            memcpy(text, m_buffer->text, sizeof(text));
            SetEvent(m_ready);
            Record parsed = {};
            parsed.processId = pid;
            if (!Parse(text, sizeof(text), parsed.error) &&
                !ParseHookFailure(text, sizeof(text), parsed)) continue;
            EnterCriticalSection(&m_lock);
            if (m_count < Capacity) {
                Record& record = m_records[(m_head + m_count) % Capacity];
                record = parsed;
                ++m_count;
            } else if (m_dropped != MAXDWORD) ++m_dropped;
            LeaveCriticalSection(&m_lock);
        }
    }
};
