#pragma once

#include "../../third_party/nlohmann/json.hpp"
#include <string>
#include <stdexcept>
#include <set>
#include <vector>
#include <utility>
#include "SshPrivateKey.h"

// Portable wire format, independent of MFC, the INI file and running proxies.
namespace ProfileShare
{
using Json = nlohmann::json;
static const size_t MaxCodeBytes = 256 * 1024;
static const size_t MaxJsonBytes = 192 * 1024;
static const char Prefix[] = "proxylane://profile/v1/";
static const char KeyPrefix[] = "proxylane://profile/v2/";
static const char ExtensiblePrefix[] = "proxylane://profile/v3/";
// Frozen interpretation of omitted, inactive DoH preferences in legacy codes.
// Future application presets must not change how an existing code is imported.
static const char LegacyDohUrl[] = "https://dns.google/dns-query";
static const char LegacyDohBootstrap[] = "8.8.8.8, 8.8.4.4";
inline bool UsesPrivateKey(const Json& value) { return value.value("ssh_auth", std::string("password")) == "private_key"; }

struct Error : std::runtime_error
{
    explicit Error(const char* key, std::string context = {}) : std::runtime_error(key), detail(context) {}
    std::string detail; // Identifier names only, never configuration values or secrets.
};

// Frozen legacy vocabulary. Adding a field to KnownFields alone must never
// accidentally export it to readers that silently ignore unknown settings.
inline const std::set<std::string>& LegacyFields()
{
    static const std::set<std::string> fields = {
        "name", "type", "host", "port", "user", "password", "transport", "psk",
        "hook_tcp", "hook_udp", "block_udp", "block_ipv6", "hook_children",
        "dns_mode", "redirect_private_dns", "redirect_dns", "child_mode", "target_mode",
        "child_rules", "target_rules", "ssh_host_key", "ssh_auth", "ssh_private_key"};
    return fields;
}

inline const std::set<std::string>& KnownFields()
{
    static const std::set<std::string> fields = [] {
        auto result = LegacyFields();
        result.insert("doh_url"); result.insert("doh_bootstrap");
        return result;
    }();
    return fields;
}

inline bool IsIdentifier(const std::string& name)
{
    return !name.empty() && name.size() <= 64 &&
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789._-") == std::string::npos;
}

inline std::string IdentifierList(const std::set<std::string>& names)
{
    std::string result;
    for (const auto& name : names) {
        if (!IsIdentifier(name)) throw Error("share.invalid_fields");
        if (!result.empty()) result += ", ";
        if (result.size() + name.size() > 512) { result += "..."; break; }
        result += name;
    }
    return result;
}

inline void CheckFields(const Json& value, const std::set<std::string>& allowed)
{
    if (!value.is_object()) throw Error("share.invalid_fields");
    std::set<std::string> unknown;
    for (auto it = value.begin(); it != value.end(); ++it)
        if (!allowed.count(it.key())) unknown.insert(it.key());
    if (!unknown.empty()) throw Error("share.unknown_fields", IdentifierList(unknown));
}

inline const std::set<std::string>& SupportedFeatures()
{
    static const std::set<std::string> features = {"dns.doh.v1", "dns.doh.v2", "ssh.private-key.v1"};
    return features;
}

// Call only after Validate. A capability also covers retaining its stored
// settings while disabled, not just executing an enabled feature.
inline std::set<std::string> RequiredFeatures(const Json& value)
{
    std::set<std::string> result;
    if (value["dns_mode"] == 2 || value.contains("doh_url") || value.contains("doh_bootstrap"))
        result.insert("dns.doh.v2");
    if (UsesPrivateKey(value)) result.insert("ssh.private-key.v1");
    return result;
}

inline void StoreDohPreferences(Json& value, const std::string& url, const std::string& bootstrap)
{
    if (value.at("dns_mode") == 2 || url != LegacyDohUrl || bootstrap != LegacyDohBootstrap) {
        value["doh_url"] = url; value["doh_bootstrap"] = bootstrap;
    } else {
        value.erase("doh_url"); value.erase("doh_bootstrap");
    }
}

inline std::set<std::string> ReadFeatures(const Json& value)
{
    if (!value.is_array() || value.size() > 32) throw Error("share.invalid_fields");
    std::set<std::string> result, unsupported;
    for (const auto& item : value) {
        if (!item.is_string()) throw Error("share.invalid_fields");
        const std::string name = item.get<std::string>();
        if (!IsIdentifier(name) || !result.insert(name).second) throw Error("share.invalid_fields");
        if (!SupportedFeatures().count(name)) unsupported.insert(name);
    }
    if (!unsupported.empty()) throw Error("share.unsupported_features", IdentifierList(unsupported));
    return result;
}

inline std::string String(const Json& object, const char* key, size_t limit, bool multiline = false)
{
    if (!object.contains(key) || !object.at(key).is_string()) throw Error("share.invalid_fields");
    const std::string value = object.at(key).get<std::string>();
    if (value.size() > limit) throw Error("share.field_too_long");
    for (unsigned char ch : value)
        if (ch == 0 || (!multiline && (ch == '\r' || ch == '\n')))
            throw Error("share.invalid_fields");
    return value;
}

inline void Validate(const Json& value)
{
    CheckFields(value, KnownFields());
    const std::string name = String(value, "name", 512);
    if (name.empty() || name.find_first_of("[]\r\n") != std::string::npos ||
        name.front() == ' ' || name.back() == ' ' || name.find('\t') != std::string::npos)
        throw Error("share.invalid_name");
    const std::string type = String(value, "type", 16);
    if (type != "NOPROXY" && type != "SOCKS5" && type != "HTTP" && type != "HTTP10" && type != "HTTP11" && type != "SSH")
        throw Error("share.invalid_type");
    const std::string auth = value.contains("ssh_auth") ? String(value, "ssh_auth", 16) : "password";
    if (auth != "password" && auth != "private_key") throw Error("share.invalid_fields");
    if (auth == "private_key") {
        if (type != "SSH" || !SshPrivateKey::Supported(String(value, "ssh_private_key", SshPrivateKey::Capacity-1, true)))
            throw Error("ssh.key_format");
    } else if (value.contains("ssh_private_key")) throw Error("share.invalid_fields");
    const std::string host = String(value, "host", 127);
    String(value, "user", 127);
    String(value, "password", 127);
    const std::string psk = String(value, "psk", 255);
    const std::string transport = String(value, "transport", 32);
    if (transport != "PLAIN" && transport != "GONC_TLS_PSK") throw Error("share.invalid_transport");
    if (type == "SSH") {
        const std::string pin = String(value, "ssh_host_key", 50);
        if (String(value, "user", 127).empty() || transport != "PLAIN" || !psk.empty() ||
            (!pin.empty() && (pin.size() != 50 || pin.compare(0,7,"SHA256:") != 0 ||
                pin.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",7) != std::string::npos)))
            throw Error("profile.ssh_invalid");
    }
    if (!value.contains("port") || !value.at("port").is_number_integer() ||
        value.at("port") < 0 || value.at("port") > 65535 ||
        (type != "NOPROXY" && (host.empty() || value.at("port") == 0 ||
            host.find_first_of(" \t") != std::string::npos)))
        throw Error("profile.invalid_endpoint");
    const char* booleans[] = {"hook_tcp", "hook_udp", "block_udp", "block_ipv6",
        "hook_children", "redirect_private_dns"};
    for (const char* key : booleans)
        if (!value.contains(key) || !value.at(key).is_boolean()) throw Error("share.invalid_fields");
    if (!value.contains("dns_mode") || !value["dns_mode"].is_number_integer() || value["dns_mode"] < 0 || value["dns_mode"] > 2)
        throw Error("share.invalid_fields");
    if (value["dns_mode"] == 2 || value.contains("doh_url") || value.contains("doh_bootstrap")) {
        String(value, "doh_url", 1023); String(value, "doh_bootstrap", 511);
    }
    const char* modes[] = {"child_mode", "target_mode"};
    for (const char* key : modes)
        if (!value.contains(key) || !value.at(key).is_number_integer() ||
            (value.at(key) != 0 && value.at(key) != 1)) throw Error("share.invalid_fields");
    String(value, "redirect_dns", 127);
    const char* filters[] = {"child_rules", "target_rules"};
    for (const char* key : filters)
    {
        if (!value.contains(key) || !value.at(key).is_array() || value.at(key).size() > 4096)
            throw Error("share.invalid_rules");
        size_t bytes = 0;
        for (const auto& line : value.at(key))
        {
            Json wrapper = {{"line", line}};
            bytes += String(wrapper, "line", 32767).size() + 2;
            if (bytes > 32767) throw Error("share.invalid_rules");
        }
    }
    if (transport == "GONC_TLS_PSK")
    {
        if (type != "SOCKS5" && type != "HTTP" && type != "HTTP10" && type != "HTTP11")
            throw Error("profile.secure_transport_unsupported");
        if (psk.empty()) throw Error("profile.psk_required");
    }
    if (type != "SOCKS5" && type != "NOPROXY" && value.at("hook_udp") == true)
        throw Error("share.invalid_udp");
}

inline std::string Base64Url(const std::string& input)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    unsigned bits = 0;
    int count = 0;
    for (unsigned char ch : input)
    {
        bits = (bits << 8) | ch;
        count += 8;
        while (count >= 6) { count -= 6; out += alphabet[(bits >> count) & 63]; }
    }
    if (count) out += alphabet[(bits << (6 - count)) & 63];
    return out;
}

inline std::string Encode(const Json& value)
{
    Validate(value);
    Json canonical = value;
    if (canonical["type"] == "HTTP10" || canonical["type"] == "HTTP11") canonical["type"] = "HTTP";
    const auto features = RequiredFeatures(canonical);
    bool extensible = false;
    for (auto it = canonical.begin(); it != canonical.end(); ++it)
        if (!LegacyFields().count(it.key())) extensible = true;
    for (const auto& feature : features)
        if (feature != "ssh.private-key.v1") extensible = true;
    const Json wire = extensible
        ? Json{{"required_features", features}, {"profile", canonical}} : canonical;
    const std::string json = wire.dump(); // Also validates UTF-8.
    if (json.size() > MaxJsonBytes) throw Error("share.too_large");
    std::string result = std::string(extensible ? ExtensiblePrefix : UsesPrivateKey(value) ? KeyPrefix : Prefix) + Base64Url(json);
    if (result.size() > MaxCodeBytes) throw Error("share.too_large");
    return result;
}

inline Json Decode(std::string code)
{
    if (code.size() > MaxCodeBytes) throw Error("share.too_large");
    const size_t first = code.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) throw Error("share.invalid_code");
    code = code.substr(first, code.find_last_not_of(" \t\r\n") - first + 1);
    const bool keyVersion = code.compare(0, sizeof(KeyPrefix)-1, KeyPrefix) == 0;
    const bool extensibleVersion = code.compare(0, sizeof(ExtensiblePrefix)-1, ExtensiblePrefix) == 0;
    const std::string prefix = extensibleVersion ? ExtensiblePrefix : keyVersion ? KeyPrefix : Prefix;
    if (code.compare(0, prefix.size(), prefix) != 0)
    {
        if (code.compare(0, sizeof("proxylane://profile/v") - 1, "proxylane://profile/v") == 0)
            throw Error("share.unsupported_version");
        throw Error("share.invalid_code");
    }
    const std::string encoded = code.substr(prefix.size());
    if (encoded.empty() || encoded.size() % 4 == 1) throw Error("share.invalid_code");
    unsigned bits = 0;
    int count = 0;
    std::string json;
    for (char ch : encoded)
    {
        int n = ch >= 'A' && ch <= 'Z' ? ch - 'A' :
            ch >= 'a' && ch <= 'z' ? ch - 'a' + 26 :
            ch >= '0' && ch <= '9' ? ch - '0' + 52 : ch == '-' ? 62 : ch == '_' ? 63 : -1;
        if (n < 0) throw Error("share.invalid_code");
        bits = (bits << 6) | n;
        count += 6;
        if (count >= 8) { count -= 8; json += static_cast<char>((bits >> count) & 255); }
    }
    if ((count && (bits & ((1u << count) - 1))) || json.size() > MaxJsonBytes)
        throw Error("share.invalid_code");
    // Reject excessive nesting and duplicate keys instead of accepting ambiguous settings.
    std::vector<std::set<std::string>> keys;
    Json value = Json::parse(json, [&keys](int depth, Json::parse_event_t event, Json& parsed) {
        if (depth > 8) throw Error("share.invalid_fields");
        if (event == Json::parse_event_t::object_start) keys.emplace_back();
        if (event == Json::parse_event_t::key &&
            !keys.back().insert(parsed.get<std::string>()).second) throw Error("share.invalid_fields");
        if (event == Json::parse_event_t::object_end) keys.pop_back();
        return true;
    });
    if (extensibleVersion && (value.contains("profile") || value.contains("required_features") || value.contains("metadata"))) {
        CheckFields(value, {"required_features", "profile", "metadata"});
        if (!value.contains("required_features") || !value.contains("profile") ||
            (value.contains("metadata") && !value["metadata"].is_object())) throw Error("share.invalid_fields");
        // Check capabilities before profile fields, so newer senders get a
        // specific unsupported-feature error. Metadata is explicitly non-behavioral.
        auto declared = ReadFeatures(value["required_features"]);
        // v1 profiles acquire the current mode's DNS-packet interception on
        // import. New exports require v2 so older apps cannot silently lose it.
        if (declared.count("dns.doh.v1") && declared.count("dns.doh.v2")) throw Error("share.feature_mismatch");
        if (declared.erase("dns.doh.v1")) declared.insert("dns.doh.v2");
        Json profile = value["profile"];
        Validate(profile);
        if (declared != RequiredFeatures(profile)) throw Error("share.feature_mismatch");
        value = std::move(profile);
    } else {
        if (extensibleVersion) {
            // Read-only migration for the flat v3 emitted by the DoH development
            // build. Freeze its vocabulary; new features must use the envelope.
            auto legacyV3 = LegacyFields();
            legacyV3.insert("doh_url"); legacyV3.insert("doh_bootstrap");
            CheckFields(value, legacyV3);
        } else CheckFields(value, LegacyFields());
        Validate(value);
        if (extensibleVersion ? value["dns_mode"] != 2 :
            (value["dns_mode"] == 2 || UsesPrivateKey(value) != keyVersion))
            throw Error("share.unsupported_version");
    }
    if (value["type"] == "HTTP10" || value["type"] == "HTTP11") value["type"] = "HTTP";
    return value;
}
}
