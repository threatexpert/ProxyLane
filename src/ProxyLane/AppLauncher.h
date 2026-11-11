#pragma once
#include <windows.h>
// Returns true only for the private command mode, including malformed invocations.
bool RunInternalAppLauncher(LPCWSTR commandLine, DWORD& exitCode);
