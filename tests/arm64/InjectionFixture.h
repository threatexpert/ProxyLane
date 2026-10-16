#pragma once
#include <windows.h>
struct InjectionFixtureState
{
    volatile LONG calls;
    volatile LONG mainEntered;
    LONG hookResult;
    LONG expectedCallsAtMain;
};
