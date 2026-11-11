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

static LONG ApplyDetourHooks(const DetourHookBinding* bindings, size_t count, bool attach, DetourHookFailure* failure)
{
    DetourHookFailure local = { "validate-bindings", size_t(-1) };
    if (!failure) failure = &local;
    *failure = local;
    if (!bindings && count) return ERROR_INVALID_PARAMETER;
    if (!count) { failure->stage = NULL; return NO_ERROR; }
    ScopedLock lock;
    for (size_t i = 0; i < count; ++i)
    {
        failure->bindingIndex = i;
        if (!bindings[i].original || !*bindings[i].original || !bindings[i].replacement)
            return ERROR_INVALID_PARAMETER;
        for (size_t j = 0; j < i; ++j)
            if (bindings[i].original == bindings[j].original ||
                *bindings[i].original == *bindings[j].original)
                return ERROR_INVALID_PARAMETER;
    }
    failure->stage = "DetourTransactionBegin";
    failure->bindingIndex = size_t(-1);
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
    failure->stage = attach ? "DetourAttach" : "DetourDetach";
    for (size_t i = 0; i < count && error == NO_ERROR; ++i)
    {
        failure->bindingIndex = i;
        error = attach ? DetourAttach(bindings[i].original, bindings[i].replacement)
                       : DetourDetach(bindings[i].original, bindings[i].replacement);
    }
    if (error != NO_ERROR)
    {
        DetourTransactionAbort();
        return error;
    }
    failure->stage = "DetourTransactionCommitEx";
    failure->bindingIndex = size_t(-1);
    PVOID* failedPointer = NULL;
    error = DetourTransactionCommitEx(&failedPointer);
    if (error != NO_ERROR && failedPointer)
        for (size_t i = 0; i < count; ++i)
            if (bindings[i].original == failedPointer) { failure->bindingIndex = i; break; }
    if (error == NO_ERROR) { failure->stage = NULL; failure->bindingIndex = size_t(-1); }
    return error;
}

LONG InstallDetourHooks(const DetourHookBinding* bindings, size_t count, DetourHookFailure* failure)
{
    return ApplyDetourHooks(bindings, count, true, failure);
}

LONG RemoveDetourHooks(const DetourHookBinding* bindings, size_t count, DetourHookFailure* failure)
{
    return ApplyDetourHooks(bindings, count, false, failure);
}
