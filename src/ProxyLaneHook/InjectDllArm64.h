#pragma once
#include <windows.h>

#if defined(_M_ARM64) && !defined(_M_ARM64EC)
// A non-null thread must already be suspended by the caller. A null thread
// starts a new remote thread. Success means queued, not hook initialization ACK.
// Once queued, bootstrap allocations belong to the target process lifetime.
int InjectDllArm64W(HANDLE process, HANDLE suspendedThread, LPCWSTR dll, LPCSTR pipe);
#endif
