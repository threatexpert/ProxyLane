// Compile/link evidence only. This is not an ARM64 hook runtime test.
#include "DetourHooks.h"
#include "HookCallGate.h"
#include <detours.h>

#if !defined(_M_ARM64) || defined(_M_ARM64EC)
#error This probe must target native ARM64.
#endif

static_assert(sizeof(void*) == 8, "ARM64 pointers must be 64-bit");

int main()
{
    if (!g_HookCalls.Ready()) return 1;
    if (ApplyDetourHooks(NULL, 0, false) != NO_ERROR) return 2;
    if (DetourTransactionBegin() != NO_ERROR) return 3;
    return DetourTransactionAbort() == NO_ERROR ? 0 : 4;
}
