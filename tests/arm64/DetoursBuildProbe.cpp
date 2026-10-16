// Cross-build evidence on x64; on ARM64 also runs architecture tests.
// This is not an ARM64 hook runtime test.
#include "DetourHooks.h"
#include "ProcessArchitecture.h"

int ProcessArchitectureTestsMain();
#include <detours.h>

#if !defined(_M_ARM64) || defined(_M_ARM64EC)
#error This probe must target native ARM64.
#endif

static_assert(sizeof(void*) == 8, "ARM64 pointers must be 64-bit");

int main()
{
    if (ProcessArchitectureTestsMain() != 0) return 1;
    if (InstallDetourHooks(NULL, 0) != NO_ERROR) return 2;
    if (RemoveDetourHooks(NULL, 0) != NO_ERROR) return 2;
    if (DetourTransactionBegin() != NO_ERROR) return 3;
    return DetourTransactionAbort() == NO_ERROR ? 0 : 4;
}
