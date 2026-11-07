#pragma once

#include "../../third_party/nlohmann/json.hpp"
#include <string>
#include <stdexcept>
#include <set>
#include <vector>

// Portable wire format, independent of MFC, the INI file and running proxies.
namespace ProfileShare
{
using Json = nlohmann::json;
static const size_t MaxCodeBytes = 256 * 1024;
static const size_t MaxJsonBytes = 192 * 1024;
static const char Prefix[] = "proxylane://profile/v1/";

struct Error : std::runtime_error
{
    explicit Error(const char* key) : std::runtime_error(key) {}
};

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
    if (!value.is_object()) throw Error("share.invalid_fields");
    const std::string name = String(value, "name", 512);
    if (name.empty() || name.find_first_of("[]\r\n") != std::string::npos ||
        name.front() == ' ' || name.back() == ' ' || name.find('\t') != std::string::npos)
        throw Error("share.invalid_name");
    const std::string type = String(value, "type", 16);
    if (type != "NOPROXY" && type != "SOCKS5" && type != "HTTP" && type != "HTTP10" && type != "HTTP11")
        throw Error("share.invalid_type");
    const std::string host = String(value, "host", 127);
    String(value, "user", 127);
    String(value, "password", 127);
    const std::string psk = String(value, "psk", 255);
    const std::string transport = String(value, "transport", 32);
    if (transport != "PLAIN" && transport != "GONC_TLS_PSK") throw Error("share.invalid_transport");
    if (!value.contains("port") || !value.at("port").is_number_integer() ||
        value.at("port") < 0 || value.at("port") > 65535 ||
        (type != "NOPROXY" && (host.empty() || value.at("port") == 0 ||
            host.find_first_of(" \t") != std::string::npos)))
        throw Error("profile.invalid_endpoint");
    const char* booleans[] = {"hook_tcp", "hook_udp", "block_udp", "block_ipv6",
        "hook_children", "redirect_private_dns"};
    for (const char* key : booleans)
        if (!value.contains(key) || !value.at(key).is_boolean()) throw Error("share.invalid_fields");
    const char* modes[] = {"dns_mode", "child_mode", "target_mode"};
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
    const std::string json = canonical.dump(); // Also validates UTF-8.
    if (json.size() > MaxJsonBytes) throw Error("share.too_large");
    std::string result = Prefix + Base64Url(json);
    if (result.size() > MaxCodeBytes) throw Error("share.too_large");
    return result;
}

inline Json Decode(std::string code)
{
    if (code.size() > MaxCodeBytes) throw Error("share.too_large");
    const size_t first = code.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) throw Error("share.invalid_code");
    code = code.substr(first, code.find_last_not_of(" \t\r\n") - first + 1);
    const std::string prefix = Prefix;
    if (code.compare(0, prefix.size(), prefix) != 0)
    {
        if (code.compare(0, 20, "proxylane://profile/v") == 0) throw Error("share.unsupported_version");
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
    Validate(value);
    if (value["type"] == "HTTP10" || value["type"] == "HTTP11") value["type"] = "HTTP";
    return value;
}
}
