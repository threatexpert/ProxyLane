#include "DetourHooks.h"
#include <detours.h>

namespace
{
    struct TransactionLock
    {
        CRITICAL_SECTION value;
        TransactionLock() { InitializeCriticalSection(&value); }
        ~TransactionLock() { DeleteCriticalSection(&value); }
    } transactionLock;

    struct ScopedLock
    {
        ScopedLock() { EnterCriticalSection(&transactionLock.value); }
        ~ScopedLock() { LeaveCriticalSection(&transactionLock.value); }
    };

}

static LONG ApplyDetourHooks(const DetourHookBinding* bindings, size_t count, bool attach)
{
    if (!bindings && count) return ERROR_INVALID_PARAMETER;
    if (!count) return NO_ERROR;
    ScopedLock lock;
    for (size_t i = 0; i < count; ++i)
    {
        if (!bindings[i].original || !*bindings[i].original || !bindings[i].replacement)
            return ERROR_INVALID_PARAMETER;
        for (size_t j = 0; j < i; ++j)
            if (bindings[i].original == bindings[j].original ||
                *bindings[i].original == *bindings[j].original)
                return ERROR_INVALID_PARAMETER;
    }
    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR)
    {
        // Begin can acquire transaction ownership and then fail to make the
        // existing trampoline regions writable. Do not leave that transaction open.
        if (error != ERROR_INVALID_OPERATION) DetourTransactionAbort();
        return error;
    }
    // Deliberately do not suspend host threads. The transaction prepares the
    // entire batch, but publishing entry patches is not atomic to other threads.
    for (size_t i = 0; i < count && error == NO_ERROR; ++i)
        error = attach ? DetourAttach(bindings[i].original, bindings[i].replacement)
                       : DetourDetach(bindings[i].original, bindings[i].replacement);
    if (error != NO_ERROR)
    {
        DetourTransactionAbort();
        return error;
    }
    return DetourTransactionCommit();
}

LONG InstallDetourHooks(const DetourHookBinding* bindings, size_t count)
{
    return ApplyDetourHooks(bindings, count, true);
}

LONG RemoveDetourHooks(const DetourHookBinding* bindings, size_t count)
{
    return ApplyDetourHooks(bindings, count, false);
}
