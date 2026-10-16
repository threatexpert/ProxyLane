#pragma once

// Keep the existing handler declarations/call sites while storing typed
// original-function pointers owned by Detours, rather than writable functions.
#define MyDetourProc(returnVal, rettype, calltype, method, args) \
    typedef rettype (calltype* OriginalType_##method) args; \
    static OriginalType_##method Original_##method = NULL; \
    rettype calltype hook_##method args

#define CallTrampoline(method) Original_##method
