#ifdef NDEBUG
#undef NDEBUG
#endif
#include "UpdateRelease.h"
#include <cassert>
#include <iostream>

int UpdateReleaseTestsMain()
{
    UpdateRelease::VersionParts left, right;
    for (const auto& pair : {std::make_pair("v1.3.6", "1.3.7"),
        std::make_pair("1.3.9", "1.3.10"), std::make_pair("1.9.9", "2.0"),
        std::make_pair("1.3.7", "1.3.7.1")}) {
        assert(UpdateRelease::Version(pair.first, left));
        assert(UpdateRelease::Version(pair.second, right));
        assert(left < right);
    }
    assert(UpdateRelease::Version("V1.3", left));
    assert(UpdateRelease::Version("1.3.0.0", right));
    assert(left == right);
    for (const char* invalid : {"", "v", "1", "1.3.", ".1.3", "1..3", "vv1.3",
        "1.3.7-beta", "1.3.7+build", "1.2.3.4.5", "1.999999", "1.-1", "1.x", " 1.3"})
        assert(!UpdateRelease::Version(invalid, left));

    std::string tag;
    assert(UpdateRelease::Parse(R"({"version":"v1.3.6","publishedAt":"2026-11-01T16:18:41Z","assets":[{"path":"/d/proxylane/698816589"}],"refreshSeconds":600})", tag));
    assert(tag == "v1.3.6");
    for (const char* invalid : {"", "<html>error</html>", "null", "[]", "{}",
        R"({"error":"service unavailable"})", R"({"version":137})",
        R"({"version":"1.3.7\u0000"})", R"({"version":"1.3.7-rc1"})",
        R"({"tag_name":"v1.3.7"})"}) {
        assert(!UpdateRelease::Parse(invalid, tag));
        assert(tag.empty());
    }
    assert(!UpdateRelease::Parse(std::string(UpdateRelease::MaxResponseBytes + 1, ' '), tag));
    std::cout << "Update release tests passed" << std::endl;
    return 0;
}
