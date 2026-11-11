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

    // Installer assets: optional, exact name, fixed-origin path, size and SHA-256.
    const std::string hash(64, 'a');
    UpdateRelease::Installer installer;
    assert(UpdateRelease::Parse(R"({"version":"v1.3.9","assets":[{"name":"ProxyLane-1.3.9-Windows.zip","size":8906430,"path":"/d/proxylane/723481415"}]})", tag, &installer));
    assert(tag == "v1.3.9" && !installer.Available());
    const std::string valid = R"({"version":"v1.4.0","assets":[)"
        R"({"name":"ProxyLane-1.4.0-Windows.zip","size":10,"path":"/d/proxylane/1","sha256":")" + hash + R"("},)"
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":123456,"path":"/d/proxylane/2","digest":"sha256:)" + std::string(64, 'B') + R"("}]})";
    assert(UpdateRelease::Parse(valid, tag, &installer));
    assert(installer.Available() && installer.path == "/d/proxylane/2" && installer.size == 123456);
    assert(installer.sha256 == std::string(64, 'b') && installer.name == "ProxyLane-1.4.0-Setup.exe");
    assert(UpdateRelease::Parse(R"({"version":"1.4.0","assets":[{"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/proxylane/x_1-2","sha256":")" + hash + R"("}]})", tag, &installer));
    assert(installer.Available());
    const std::string rejected[] = {
        // wrong version, absolute URL, traversal, other prefix, query string
        R"({"name":"ProxyLane-1.3.9-Setup.exe","size":1,"path":"/d/proxylane/2","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"https://evil.example/d/proxylane/2","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/proxylane/../x","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/other/2","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/proxylane/2?x=1","sha256":")" + hash + R"("})",
        // missing or bad hash, size
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/proxylane/2"})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/proxylane/2","sha256":"abc"})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":1,"path":"/d/proxylane/2","digest":"md5:)" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","path":"/d/proxylane/2","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":0,"path":"/d/proxylane/2","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":-1,"path":"/d/proxylane/2","sha256":")" + hash + R"("})",
        R"({"name":"ProxyLane-1.4.0-Setup.exe","size":999999999999,"path":"/d/proxylane/2","sha256":")" + hash + R"("})"};
    for (const std::string& asset : rejected) {
        assert(UpdateRelease::Parse(R"({"version":"v1.4.0","assets":[)" + asset + "]}", tag, &installer));
        assert(tag == "v1.4.0" && !installer.Available());
    }
    assert(UpdateRelease::Parse(R"({"version":"v1.4.0","assets":"none"})", tag, &installer) && !installer.Available());
    std::cout << "Update release tests passed" << std::endl;
    return 0;
}
