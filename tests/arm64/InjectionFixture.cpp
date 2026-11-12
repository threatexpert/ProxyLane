#include "InjectionFixture.h"
#include <string>

extern "C" __declspec(dllexport) BOOL WINAPI gp_HookWinsock(LPCSTR name)
{
    HANDLE mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!mapping) return FALSE;
    InjectionFixtureState* state = static_cast<InjectionFixtureState*>(
        MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(InjectionFixtureState)));
    BOOL result = FALSE;
    if (state)
    {
        result = state->hookResult;
        InterlockedIncrement(&state->calls);
        HANDLE event = OpenEventA(EVENT_MODIFY_STATE, FALSE, (std::string(name) + "Hook").c_str());
        if (event) { SetEvent(event); CloseHandle(event); }
        UnmapViewOfFile(state);
    }
    CloseHandle(mapping);
    return result;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
