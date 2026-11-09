#ifdef NDEBUG
#undef NDEBUG
#endif
#include "ProfileShareCodec.h"
#include <cassert>
#include <iostream>

namespace
{
using ProfileShare::Json;
Json Fixture()
{
    return {{"name", u8"办公代理"}, {"type", "SOCKS5"}, {"host", "::1"}, {"port", 1080},
        {"user", "user"}, {"password", "p|a\\ss\"&?#"}, {"transport", "GONC_TLS_PSK"},
        {"psk", u8"共享密钥🔑"}, {"hook_tcp", true}, {"hook_udp", true}, {"block_udp", false},
        {"block_ipv6", true}, {"hook_children", true}, {"dns_mode", 1},
        {"redirect_private_dns", true}, {"redirect_dns", "8.8.8.8"}, {"child_mode", 1},
        {"target_mode", 0}, {"child_rules", Json::array({u8"# 中文规则", "C:\\Apps\\*.exe", "", "a|b", ""})},
        {"target_rules", Json::array({"*.example.org:443", "[::1]:80"})}};
}

void Reject(const std::string& code)
{
    bool rejected = false;
    try { ProfileShare::Decode(code); } catch (const std::exception&) { rejected = true; }
    assert(rejected);
}

void RejectValue(const Json& value)
{
    Reject(std::string(ProfileShare::Prefix) + ProfileShare::Base64Url(value.dump()));
}
}

int ProfileShareCodecTestsMain()
{
    const Json original = Fixture();
    const std::string code = ProfileShare::Encode(original);
    assert(ProfileShare::Decode(code) == original);
    assert(ProfileShare::Decode(" \r\n" + code + "\n\t") == original);
    assert(code.find_first_of(" \r\n\t+=") == std::string::npos);
    assert(ProfileShare::Base64Url("f") == "Zg");
    assert(ProfileShare::Base64Url("fo") == "Zm8");
    assert(ProfileShare::Base64Url("foo") == "Zm9v");
    for (const char* type : {"SOCKS5", "HTTP", "NOPROXY"})
    {
        Json value = original;
        value["type"] = type; value["transport"] = "PLAIN"; value["hook_udp"] = false;
        if (value["type"] == "NOPROXY") { value["host"] = ""; value["port"] = 0; }
        assert(ProfileShare::Decode(ProfileShare::Encode(value)) == value);
    }
    for (const char* type : {"HTTP10", "HTTP11"})
    {
        Json legacyHttp = original;
        legacyHttp["type"] = type; legacyHttp["hook_udp"] = false;
        Json canonicalHttp = legacyHttp;
        canonicalHttp["type"] = "HTTP";
        assert(ProfileShare::Decode(std::string(ProfileShare::Prefix) +
            ProfileShare::Base64Url(legacyHttp.dump())) == canonicalHttp);
        assert(ProfileShare::Encode(legacyHttp) == ProfileShare::Encode(canonicalHttp));
    }
    {
        Json ssh = original;
        ssh["type"] = "SSH"; ssh["port"] = 22; ssh["transport"] = "PLAIN";
        ssh["hook_udp"] = false; ssh["psk"] = "";
        ssh["ssh_host_key"] = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        ssh["user"] = u8"测试用户";
        assert(ProfileShare::Decode(ProfileShare::Encode(ssh)) == ssh);
        Json bad = ssh; bad["ssh_host_key"] = "bad"; RejectValue(bad);
        bad = ssh; bad.erase("ssh_host_key"); RejectValue(bad);
        bad = ssh; bad["hook_udp"] = true; RejectValue(bad);
        bad = ssh; bad["user"] = ""; RejectValue(bad);
        bad = ssh; bad["transport"] = "GONC_TLS_PSK"; RejectValue(bad);
    }
    for (const char* type : {"SOCKS4", "SOCKS4A"})
    {
        Json removed = original;
        removed["type"] = type; removed["transport"] = "PLAIN"; removed["hook_udp"] = false;
        RejectValue(removed);
    }
    // Disabled fields, including credentials, must survive a full-profile share.
    Json value = original;
    value["transport"] = "PLAIN"; value["hook_children"] = false; value["redirect_private_dns"] = false;
    assert(ProfileShare::Decode(ProfileShare::Encode(value)) == value);
    for (auto it = original.begin(); it != original.end(); ++it)
    {
        value = original; value.erase(it.key()); RejectValue(value);
        value = original; value[it.key()] = nullptr; RejectValue(value);
    }
    for (int port : {-1, 0, 65536}) { value = original; value["port"] = port; RejectValue(value); }
    value = original; value["port"] = 1.5; RejectValue(value);
    value = original; value["port"] = UINT64_MAX; RejectValue(value);
    value = original; value["password"] = std::string(128, 'x'); RejectValue(value);
    value = original; value["password"] = std::string("a\0b", 3); RejectValue(value);
    value = original; value["psk"] = ""; RejectValue(value);
    value = original; value["name"] = "bad]\n[options"; RejectValue(value);
    value = original; value["type"] = "UNKNOWN"; RejectValue(value);
    value = original; value["transport"] = "UNKNOWN"; RejectValue(value);
    value = original; value["type"] = "SOCKS4"; RejectValue(value);
    value = original; value["type"] = "HTTP11"; RejectValue(value);
    value = original; value["target_mode"] = 2; RejectValue(value);
    value = original; value["child_rules"] = Json::array({"a\nb"}); RejectValue(value);
    value = original; value["child_rules"] = Json::array({std::string(32768, 'x')}); RejectValue(value);
    Reject(""); Reject("socks5://localhost:1080"); Reject("proxylane://profile/v2/abc");
    Reject(code + "="); Reject(code + "!"); Reject(code.substr(0, code.size() - 4));
    Reject(std::string(ProfileShare::MaxCodeBytes + 1, 'x'));
    Reject(std::string(ProfileShare::Prefix) + "Zh"); // Nonzero unused Base64 bits.
    Reject(std::string(ProfileShare::Prefix) + ProfileShare::Base64Url("{\"name\":\"a\",\"name\":\"b\"}"));
    Reject(std::string(ProfileShare::Prefix) + ProfileShare::Base64Url(std::string(100, '[') + std::string(100, ']')));
    std::cout << "Profile sharing codec tests passed\n";
    return 0;
}
