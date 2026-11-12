#pragma once
#include <windows.h>
#include <stddef.h>

struct DetourHookBinding
{
    PVOID* original;
    PVOID replacement;
};

struct DetourHookFailure
{
    const char* stage;
    size_t bindingIndex; // size_t(-1) when the failure has no individual target.
};

// Prepare all bindings in one transaction, aborting on preparation failure.
// No host thread is suspended: entry patches/pointer updates are not atomic
// to concurrent callers. Initialize callback state before installation and
// retain targets, pointer slots, callbacks and their state while installed.
LONG InstallDetourHooks(const DetourHookBinding* bindings, size_t count, DetourHookFailure* failure = NULL);

// Caller must stop new calls and ensure no thread uses the affected entry
// patches, trampolines or callback state until this transaction has completed.
// This function neither drains callbacks nor suspends threads. Preparation
// failure aborts the batch, retaining installed hooks and pointer slots.
LONG RemoveDetourHooks(const DetourHookBinding* bindings, size_t count, DetourHookFailure* failure = NULL);
