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

void RejectKeyValue(const Json& value)
{
    Reject(std::string(ProfileShare::KeyPrefix) + ProfileShare::Base64Url(value.dump()));
}

void RejectValue(const Json& value)
{
    Reject(std::string(ProfileShare::Prefix) + ProfileShare::Base64Url(value.dump()));
}

std::string V3(const Json& wire)
{
    return std::string(ProfileShare::ExtensiblePrefix) + ProfileShare::Base64Url(wire.dump());
}

void RejectWith(const std::string& code, const char* key, const std::string& detail = {})
{
    bool rejected = false;
    try { ProfileShare::Decode(code); }
    catch (const ProfileShare::Error& error) {
        rejected = true;
        if (std::string(error.what()) != key || error.detail != detail)
            std::cerr << "Expected " << key << " [" << detail << "], got " << error.what() << " [" << error.detail << "]\n";
        assert(std::string(error.what()) == key);
        assert(error.detail == detail);
    }
    assert(rejected);
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
        ssh["ssh_auth"] = "private_key";
        ssh["ssh_private_key"] = "-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----\n";
        std::string portable = ProfileShare::Encode(ssh);
        assert(portable.find(ProfileShare::KeyPrefix) == 0);
        assert(ProfileShare::Decode(portable) == ssh);
        RejectValue(ssh); // Private-key material in a v1 envelope must never downgrade.
        bad = ssh; bad["ssh_auth"] = "agent"; RejectKeyValue(bad);
        bad = ssh; bad.erase("ssh_private_key"); RejectKeyValue(bad);
        bad = ssh; bad["ssh_private_key"] = std::string(16384, 'x'); RejectKeyValue(bad);
        bad = ssh; bad["ssh_private_key"] = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"; RejectKeyValue(bad);
        bad = ssh; bad["ssh_private_key"] = ssh["ssh_private_key"].get<std::string>() + std::string("\0tail",5); RejectKeyValue(bad);
        bad = ssh; bad["ssh_auth"] = "password"; RejectKeyValue(bad);
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
    value = original; value["dns_mode"] = 2;
    ProfileShare::StoreDohPreferences(value, ProfileShare::LegacyDohUrl, ProfileShare::LegacyDohBootstrap);
    const Json doh = value;
    const Json envelope = {{"required_features", Json::array({"dns.doh.v2"})}, {"profile", doh}};
    assert(ProfileShare::Encode(doh) == V3(envelope));
    assert(ProfileShare::Decode(V3(envelope)) == doh);
    value = envelope; value["required_features"] = Json::array({"dns.doh.v1"});
    assert(ProfileShare::Decode(V3(value)) == doh); // Earlier mode is upgraded on import.
    value["required_features"].push_back("dns.doh.v2");
    RejectWith(V3(value), "share.feature_mismatch");
    assert(ProfileShare::Decode(V3(doh)) == doh); // Development flat v3: read only.
    RejectValue(doh); RejectKeyValue(doh); // Do not relabel new settings as old formats.
    value = envelope; value["profile"].erase("doh_bootstrap");
    RejectWith(V3(value), "share.invalid_fields");
    value = envelope; value["required_features"] = Json::array();
    RejectWith(V3(value), "share.feature_mismatch");
    value = envelope; value["required_features"].push_back("ssh.private-key.v1");
    RejectWith(V3(value), "share.feature_mismatch");
    value = envelope; value["required_features"] = Json::array({"dns.doh.v3"});
    RejectWith(V3(value), "share.unsupported_features", "dns.doh.v3");

    // New senders stay on v3. Unknown capabilities are reported before their
    // unknown settings, and no unrecognized setting can disappear silently.
    value = envelope;
    value["required_features"].push_back("routing.future.v1");
    value["profile"]["future_route"] = "do-not-show-secret-value";
    RejectWith(V3(value), "share.unsupported_features", "routing.future.v1");
    value["required_features"] = Json::array({"dns.doh.v1"});
    RejectWith(V3(value), "share.unknown_fields", "future_route");
    RejectWith(V3(value["profile"]), "share.unknown_fields", "future_route");
    Json oldWithUnknown = original; oldWithUnknown["future_route"] = false;
    RejectWith(std::string(ProfileShare::Prefix) + ProfileShare::Base64Url(oldWithUnknown.dump()),
        "share.unknown_fields", "future_route");
    value = envelope; value["profile"]["dns_mode"] = 99;
    RejectWith(V3(value), "share.invalid_fields");
    value = envelope; value["behavior_override"] = true;
    RejectWith(V3(value), "share.unknown_fields", "behavior_override");

    for (const Json& invalid : {Json(), Json(true), Json("dns.doh.v1"), Json::array({1}),
        Json::array({"dns.doh.v1", "dns.doh.v1"}), Json::array({"bad\nidentifier"}),
        Json::array({std::string(65, 'x')})}) {
        value = envelope; value["required_features"] = invalid;
        RejectWith(V3(value), "share.invalid_fields");
    }
    value = envelope; value["required_features"] = Json::array();
    for (int i = 0; i < 33; ++i) value["required_features"].push_back("future." + std::to_string(i));
    RejectWith(V3(value), "share.invalid_fields");
    value = envelope; value.erase("required_features"); RejectWith(V3(value), "share.invalid_fields");
    value = envelope; value.erase("profile"); RejectWith(V3(value), "share.invalid_fields");
    value = envelope; value["metadata"] = "invalid"; RejectWith(V3(value), "share.invalid_fields");
    value = envelope; value["metadata"] = {{"generator", "future ProxyLane"}, {"new_description", "ignored metadata"}};
    assert(ProfileShare::Decode(V3(value)) == doh);
    RejectWith("proxylane://profile/v4/" + ProfileShare::Base64Url(envelope.dump()), "share.unsupported_version");
    Reject(std::string(ProfileShare::KeyPrefix) + ProfileShare::Base64Url(envelope.dump()));
    RejectWith(std::string(ProfileShare::ExtensiblePrefix) + ProfileShare::Base64Url(
        "{\"profile\":{},\"required_features\":[],\"profile\":{}}"), "share.invalid_fields");

    // V3 is not tied to DoH: ordinary profiles and combined features decode.
    value = {{"required_features", Json::array()}, {"profile", original}};
    assert(ProfileShare::Decode(V3(value)) == original);
    Json combined = doh;
    combined["type"] = "SSH"; combined["port"] = 22; combined["transport"] = "PLAIN";
    combined["hook_udp"] = false; combined["psk"] = ""; combined["ssh_host_key"] = "";
    combined["ssh_auth"] = "private_key";
    combined["ssh_private_key"] = "-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----\n";
    value = {{"required_features", Json::array({"dns.doh.v2", "ssh.private-key.v1"})}, {"profile", combined}};
    assert(ProfileShare::Encode(combined) == V3(value));
    assert(ProfileShare::Decode(V3(value)) == combined);
    assert(ProfileShare::Decode(V3(combined)) == combined);
    value["required_features"] = Json::array({"dns.doh.v1"});
    RejectWith(V3(value), "share.feature_mismatch");

    // Inactive custom preferences still require v3 and survive a round trip.
    value = original;
    ProfileShare::StoreDohPreferences(value, "https://resolver.example/query", "192.0.2.53");
    assert(ProfileShare::Encode(value).find(ProfileShare::ExtensiblePrefix) == 0);
    assert(ProfileShare::Decode(ProfileShare::Encode(value)) == value);
    ProfileShare::StoreDohPreferences(value, ProfileShare::LegacyDohUrl, ProfileShare::LegacyDohBootstrap);
    assert(value == original && ProfileShare::Encode(value) == code);
    // The original v1/v2 export paths remain available without losing settings.
    combined["dns_mode"] = 1;
    ProfileShare::StoreDohPreferences(combined, ProfileShare::LegacyDohUrl, ProfileShare::LegacyDohBootstrap);
    assert(ProfileShare::Encode(combined).find(ProfileShare::KeyPrefix) == 0);
    assert(ProfileShare::Decode(ProfileShare::Encode(combined)) == combined);
    std::cout << "Profile sharing v1/v2/v3 compatibility, feature negotiation and rejection tests passed\n";
    return 0;
}
