#pragma once
// UI-independent, bounded projection of the Rust protocol query API.
#include "../../third_party/nlohmann/json.hpp"
#include <deque>
#include <functional>
#include <string>
#include <vector>

namespace ProtocolView {
using Json = nlohmann::json;
using Query = std::function<Json(const Json&)>;
constexpr size_t RowLimit = 512;
constexpr size_t MetadataLimit = 8 * 1024 * 1024;
constexpr size_t BodyPreviewLimit = 64 * 1024;
struct Row {
    std::string run, key, process, processPath, protocol, destination, method, target, status;
    uint64_t number = 0;
    int64_t firstSeenSeconds = 0; // First appearance; stable across row updates.
    size_t datagram[2] = {0, 0};
    uint64_t sequence = 0, processStart = 0, cacheId = 0, requestBytes = 0, responseBytes = 0;
    unsigned pid = 0;
    Json record;
    size_t bytes = 0;
    bool websocket = false;
    bool stream = false, udp = false, dns = false, quic = false, connectionRow = false, doh = false;
    std::string endpoint;
    bool hex = false; // View preference belongs to this request, not the page.
};
struct Batch {
    std::string run;
    uint64_t next = 0, lost = 0;
    std::vector<Row> rows;
};
struct Side {
    std::string headers, note, text;
    std::vector<unsigned char> body;
    bool encoded = false;
    bool previewLimited = false;
    std::vector<std::vector<unsigned char>> packets;
    std::vector<std::pair<uint64_t, size_t>> datagrams;
};
struct Detail {
    Side request, response;
    std::string context, note, cacheStamp;
    bool targetCertificateRejected = false;
    // Human-facing banner is localized by the window; diagnostics stay English.
    enum State { Ready, Truncated, Evicted, Unavailable, Pending } state = Ready;
};
std::vector<unsigned char> DisplayBytes(const Side& side);
bool Matches(const Row& row, const std::string& filter, int protocol);
Batch Poll(const Query& query, const std::string& run, uint64_t after, bool baseline);
Detail ReadDetail(const Query& query, const Row& row, size_t previewLimit=BodyPreviewLimit);
std::string CacheStamp(const Query& query, const Row& row);
class History {
public:
    size_t rowLimit=RowLimit, metadataLimit=MetadataLimit;
    void SetLimit(size_t count);
    std::deque<Row> rows;
    size_t bytes = 0;
    uint64_t discarded = 0, nextNumber = 1;
    void Add(Row row);
    void Clear();
};
}
