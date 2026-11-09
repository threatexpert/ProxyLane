#include "SshSessionLifetime.h"
#include <stdio.h>

int SshSessionLifetimeTestsMain()
{
    int failures = 0;
    auto check = [&](bool ok, const char* name) {
        if (!ok) { printf("FAIL SSH lifetime: %s\n", name); ++failures; }
    };
    const uint32_t limit = 30u * 60u * 1000u;
    SshSessionLifetime business(SshSessionUse::Business);
    business.Observe(true, 0);
    check(!business.Expired(limit * 2), "an open business connection has no idle deadline");
    business.Observe(false, 100);
    check(!business.Expired(100 + limit - 1), "retain until 30 minutes");
    // Pool polls/keepalives must not restart the idle timer.
    business.Observe(false, 100 + limit - 1);
    check(business.Expired(100 + limit), "expire at 30 minutes despite repeated polling");
    business.Observe(true, 100 + limit);
    check(!business.Expired(100 + limit * 2), "reuse cancels the old idle deadline");
    business.Observe(false, 100 + limit * 2);
    check(!business.Expired(100 + limit * 3 - 1), "new idle period starts after last connection closes");
    check(business.Expired(100 + limit * 3), "new idle period expires");
    SshSessionLifetime wrap(SshSessionUse::Business);
    const uint32_t start = 0xfffffff0u;
    wrap.Observe(false, start);
    check(!wrap.Expired(start + limit - 1), "retain across GetTickCount wrap");
    check(wrap.Expired(start + limit), "expire across GetTickCount wrap");
    SshSessionLifetime test(SshSessionUse::Test);
    test.Observe(true, 0);
    check(!test.Expired(limit), "active test retains transport");
    test.Observe(false, limit);
    check(test.Expired(limit), "completed or cancelled test has no idle retention");
    if (!failures) printf("SSH session lifetime tests: 10 PASS\n");
    return failures ? 1 : 0;
}
