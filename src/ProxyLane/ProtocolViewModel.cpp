#ifndef PROTOCOL_VIEW_TEST
#include "stdafx.h"
#endif
#include "ProtocolViewModel.h"
#include <chrono>
#include <windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <stdexcept>
#include <cctype>
#pragma comment(lib, "crypt32.lib")

namespace ProtocolView {
static std::string Str(const Json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
}
static const Json& Object(const Json& j, const char* key) {
    static const Json empty = Json::object();
    auto it = j.find(key);
    return it != j.end() && it->is_object() ? *it : empty;
}
static void StripPayload(Json& message) {
    if (!message.is_object()) return;
    message.erase("body_base64"); message.erase("decoded_base64"); message.erase("text");
}
Batch Poll(const Query& query, const std::string& run, uint64_t after, bool baseline) {
    Batch batch;
    auto reply = query(baseline ? Json{{"type", "stats"}} :
        Json{{"type", "poll"}, {"after", after}, {"limit", 32}});
    if (Str(reply, "type") == "inactive") return batch;
    batch.run = Str(reply, "run_id");
    if (batch.run.empty()) throw std::runtime_error("protocol response has no run_id");
    if (baseline) { batch.next = reply.value("last_sequence", uint64_t(0)); return batch; }
    // Sequence/cache IDs restart after stopping the proxy. Never mix runtimes.
    if (batch.run != run && after != 0)
        reply = query(Json{{"type", "poll"}, {"after", 0}, {"limit", 32}});
    batch.run = Str(reply, "run_id");
    batch.next = reply.value("next", uint64_t(0));
    batch.lost = reply.value("lost_before", uint64_t(0));
    for (auto record : reply.at("records")) {
        Row row;
        row.run = batch.run;
        row.sequence = record.at("sequence").get<uint64_t>();
        row.firstSeenSeconds=record.value("observed_unix_ms",uint64_t(0))/1000;
        row.key = row.run + ":" + std::to_string(row.sequence);
        const auto& connection = Object(record, "connection");
        row.pid = connection.value("pid", 0u);
        row.processStart = connection.value("process_start", uint64_t(0));
        row.process = Str(connection, "process_name");
        row.processPath = Str(connection, "process_path");
        row.destination = Str(connection, "destination");
        auto server = Str(connection, "server_name");
        if (!server.empty()) {
            if (server.find(':') != std::string::npos && server.front() != '[') server = "[" + server + "]";
            row.destination = server + ":" + std::to_string(connection.value("server_port", 0u));
        }
        row.endpoint = row.destination;
        row.protocol = Str(record, "protocol") == "h3" ? "HTTP/3" : Str(record, "protocol") == "h2" ? "HTTP/2" :
            Str(record, "protocol") == "http1" ? "HTTP/1.1" : "TLS";
        if (Str(record, "type") == "connection") {
            row.connectionRow = true; row.stream = true;
            row.key = row.run + ":connection:" + Str(connection, "id");
            row.protocol = Str(record,"protocol") == "tcp" ? "TCP" :
                Str(record,"protocol") == "quic" ? "QUIC" : Str(record,"protocol") == "quic_stream" ? "QUIC/Raw" : Str(record,"protocol") == "h3" ? "QUIC/HTTP/3" : Str(record,"protocol") == "h2" ? "TLS/HTTP/2" : Str(record,"protocol") == "http1" ? "TLS/HTTP/1.1" : "TLS";
            row.status = Str(record,"status");
        } else if (Str(record, "type") == "stream") {
            row.stream = true; row.quic = Str(record, "protocol") == "quic";
            row.udp = Str(record, "protocol") == "udp" || Str(record,"protocol")=="quic_datagram" || row.quic;
            row.key = row.run + ":stream:" + Str(connection, "id");
            row.protocol = row.udp ? "UDP" : Str(record, "protocol") == "tls_stream" ? "TLS" :
                Str(record, "protocol") == "tls_encrypted" ? "TLS (encrypted)" : "TCP";
            const auto& stream = Object(record, "stream");
            row.status = !stream.value("finished", false) ? "Active" : stream.value("complete", false) ? "Closed" : "Stopped";
            if (!Str(stream, "problem").empty()) row.status += " *";
            row.requestBytes = stream.value("sent_bytes", uint64_t(0));
            row.responseBytes = stream.value("received_bytes", uint64_t(0));
            row.cacheId = Object(stream, "cache").value("id", uint64_t(0));
            if(Str(record,"protocol")=="quic_stream") {
                const auto id=connection.at("quic_stream_id").get<uint64_t>();
                row.key+=":"+std::to_string(id);row.protocol="QUIC/Raw";
                row.method="Stream "+std::to_string(id);row.target=Str(connection,"quic_alpn");
            }
            if(Str(record,"protocol")=="quic_datagram") {
                row.key+=":datagrams";row.protocol="QUIC/DATAGRAM";
                row.method="DATAGRAM";row.target=Str(connection,"quic_alpn");
            }
            if (row.quic) {
                const auto& quic = Object(record,"quic");
                row.protocol = quic.value("version",uint64_t(0)) == 1 ? "QUIC v1" : "QUIC v2";
                auto name=Str(quic,"sni");
                if (!name.empty()) row.destination=name+":"+std::to_string(connection.value("server_port",0u));
            }
        } else if (Str(record,"type") == "dns") {
            row.dns=true; row.udp=Str(connection,"transport")=="udp";
            const auto& exchange=Object(record,"exchange");
            row.key=row.run+":dns:"+Str(connection,"id")+":"+std::to_string(exchange.value("id",uint64_t(0)));
            row.protocol=row.udp ? "DNS/UDP" : "DNS/TCP";
            row.method=Str(exchange,"kind"); row.target=Str(exchange,"name");
            if (!row.target.empty()) {row.destination=row.target;row.target.clear();}
            row.status=Str(exchange,"status");
            row.requestBytes=exchange.value("sent_bytes",uint64_t(0));
            row.responseBytes=exchange.value("received_bytes",uint64_t(0));
            row.cacheId=Object(exchange,"cache").value("id",uint64_t(0));
        } else if (Str(record, "type") == "exchange") {
            auto& exchange = record.at("exchange");
            // HTTP/3 publishes progress snapshots. A sequence identifies an event,
            // whereas a stream identifies the request throughout its lifetime.
            if (Str(record, "protocol") == "h3")
                row.key = row.run + ":h3:" + Str(connection, "id") + ":" +
                    std::to_string(exchange["id"].is_number_integer()?exchange["id"].get<uint64_t>():0);
            StripPayload(exchange["request"]); StripPayload(exchange["response"]);
            for (auto& info : exchange["informational"]) StripPayload(info);
            const auto& req = Object(exchange, "request");
            const auto& res = Object(exchange, "response");
            if (connection.value("decrypted", false)) row.protocol = (Str(record,"protocol")=="h3" ? "QUIC/" : "TLS/") + row.protocol;
            row.doh = record.contains("doh");
            if (row.doh) row.protocol += " / DoH";
            if(req.value("observed_start_unix_ms",uint64_t(0))) row.firstSeenSeconds=req["observed_start_unix_ms"].get<uint64_t>()/1000;
            row.method = Str(req, "method"); row.target = Str(req, "target");
            std::string authority = Str(Object(Object(record,"summary"),"request"),"authority");
            auto headers = req.find("headers");
            if (headers != req.end()) for (const auto& pair : *headers) {
                auto name = pair.at(0).get<std::string>();
                std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return (char)tolower(c); });
                if (name == ":authority" || (name == "host" && authority.empty())) authority = pair.at(1).get<std::string>();
            }
            if (!authority.empty() && authority.find_first_of(" \t\r\n/@") == std::string::npos) {
                bool hasPort = authority.front() == '[' ? authority.find("]:") != std::string::npos : authority.find(':') != std::string::npos;
                row.destination = authority;
                const auto port = connection.value("server_port", 0u);
                if (!hasPort && port) row.destination += ":" + std::to_string(port);
            }
            row.status = res.contains("status") && res["status"].is_number() ? res["status"].dump() : "Incomplete";
            if (!Str(exchange, "problem").empty()) row.status += " *";
            row.requestBytes = req.value("body_bytes", uint64_t(0));
            row.responseBytes = res.value("body_bytes", uint64_t(0));
            row.cacheId = Object(exchange, "cache").value("id", uint64_t(0));
            if(Str(record,"protocol")=="websocket") {
                row.websocket=true;row.stream=true;
                row.key=row.run+":websocket:"+Str(connection,"id")+":"+std::to_string(exchange.at("id").get<uint64_t>());
                row.protocol=connection.value("decrypted",false)?"TLS/WebSocket":"WebSocket";
                const auto& message=req.empty()?res:req;
                row.method=Str(message,"method");row.target=Str(message,"target");
                row.status=message.value("complete",false)?(req.empty()?"Received":"Sent"):"Incomplete";
                row.firstSeenSeconds=message.value("observed_start_unix_ms",uint64_t(0))/1000;
            }
        } else {
            row.status = "Diagnostic"; row.target = Str(record, "detail");
        }
        // Retained snapshots have a unique cache ID even before an exchange has
        // its complete live-protocol identity (e.g. an interrupted header).
        if(row.run.find("recording:")==0 && record.value("cache_id",uint64_t(0))) {
            row.cacheId=record["cache_id"].get<uint64_t>();row.key=row.run+":cache:"+std::to_string(row.cacheId);
        }
        row.record = std::move(record);
        row.bytes = row.record.dump().size() + row.target.size() + row.destination.size() + row.processPath.size() + 512;
        batch.rows.push_back(std::move(row));
    }
    return batch;
}
void History::Add(Row row) {
    if (row.bytes > metadataLimit) { ++discarded; return; }
    for (auto& existing : rows) {
        const bool sameConnection = existing.run == row.run &&
            Str(Object(existing.record,"connection"),"id") == Str(Object(row.record,"connection"),"id");
        if (sameConnection && row.connectionRow && !existing.connectionRow) return;
        if (sameConnection && existing.connectionRow && row.connectionRow && existing.status == "Failed") return;
    }
    for (auto& existing : rows) if (((row.stream || row.dns ||
        (Str(row.record,"type") == "exchange" && Str(row.record,"protocol") == "h3")) && existing.key == row.key) ||
        (existing.connectionRow && existing.run == row.run &&
        Str(Object(existing.record,"connection"),"id") == Str(Object(row.record,"connection"),"id"))) {
        if (row.sequence <= existing.sequence) return;
        row.hex = existing.hex; row.number = existing.number; row.firstSeenSeconds = existing.firstSeenSeconds;
        row.datagram[0] = existing.datagram[0]; row.datagram[1] = existing.datagram[1];
        bytes -= existing.bytes; bytes += row.bytes; existing = std::move(row);
        while (!rows.empty() && bytes > metadataLimit) { bytes -= rows.front().bytes; rows.pop_front(); ++discarded; }
        return;
    }
    while (!rows.empty() && (rows.size() >= rowLimit || bytes + row.bytes > metadataLimit)) {
        bytes -= rows.front().bytes; rows.pop_front(); ++discarded;
    }
    row.number = nextNumber++;
    if(!row.firstSeenSeconds) row.firstSeenSeconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    bytes += row.bytes; rows.push_back(std::move(row));
}
void History::Clear() { rows.clear(); bytes = 0; discarded = 0; nextNumber = 1; }
void History::SetLimit(size_t count) {
    rowLimit=count;metadataLimit=count*16*1024;
    while(!rows.empty() && (rows.size()>rowLimit || bytes>metadataLimit)) {
        bytes-=rows.front().bytes;rows.pop_front();++discarded;
    }
}
static std::string Headers(const Json& message, bool request, const std::string& protocol) {
    if (message.empty()) return "";
    std::string text = request ? Str(message, "method") + " " + Str(message, "target") + " " + protocol :
        protocol + " " + (message.contains("status") ? message["status"].dump() : "?");
    text += "\r\n";
    for (const auto& pair : message.at("headers"))
        text += pair.at(0).get<std::string>() + ": " + pair.at(1).get<std::string>() + "\r\n";
    auto trailers = message.find("trailers");
    if (trailers != message.end() && !trailers->empty()) {
        text += "\r\n[Trailers]\r\n";
        for (const auto& pair : *trailers)
            text += pair.at(0).get<std::string>() + ": " + pair.at(1).get<std::string>() + "\r\n";
    }
    return text;
}
static std::vector<unsigned char> Base64(const std::string& encoded) {
    if (encoded.empty()) return {};
    DWORD size = 0;
    if (!CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.size(), CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
        throw std::runtime_error("invalid payload base64");
    std::vector<unsigned char> data(size);
    if (!CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.size(), CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr))
        throw std::runtime_error("invalid payload base64");
    data.resize(size); return data;
}
static void ReadSide(const Query& query, const Row& row, const Json& message, bool request, Detail& detail, Side& side, size_t previewLimit) {
    std::string protocol = row.protocol.find("QUIC/") == 0 ? row.protocol.substr(5) : row.protocol.find("TLS/") == 0 ? row.protocol.substr(4) : row.protocol;
    auto suffix = protocol.find(" / DoH"); if (suffix != std::string::npos) protocol.resize(suffix);
    side.headers = Headers(message, request, protocol);
    if (row.doh && request) {
        auto get = Str(Object(row.record,"doh"),"request_get");
        if (!get.empty()) side.text = side.headers + "\r\n" + get;
    }
    if (message.empty()) return;
    if (!message.value("complete", false)) side.note += "Message incomplete.\r\n";
    if (message.value("body_bytes", uint64_t(0)) == 0) { return; }
    if (detail.state == Detail::Evicted || detail.state == Detail::Unavailable) {
        side.note += "Body unavailable. " + detail.note; return;
    }
    Json command{{"type", "cache_decode"}, {"run_id", row.run}, {"cache_id", row.cacheId},
        {"direction", request ? "client" : "server"},{"preview_bytes",previewLimit}};
    // WebSocket messages are already unmasked and inflated by the stream parser.
    // Read only the display prefix, including for messages above the HTTP decode budget.
    if (row.websocket) { command["type"]="cache_read"; command["offset"]=0; command["length"]=previewLimit; }
    try {
            if (row.doh) for (const auto& pair : message.at("headers")) {
        auto name = pair.at(0).get<std::string>(), value = pair.at(1).get<std::string>();
        std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return (char)tolower(c);});
        std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return (char)tolower(c);});
        if (name=="content-type" && value.substr(0,value.find(';'))=="application/dns-message") command["type"] = "doh_read";
    }
        auto reply = query(command);
        auto payload = reply.at("payload");
        auto text = Str(reply,"text");
        if (!text.empty()) side.text = side.headers + "\r\n" + text;
        auto decodeError = Str(reply,"decode_error");
        if (!decodeError.empty()) side.note += "DNS decoding unavailable: " + decodeError + "\r\n";
        side.body = Base64(payload.at("data_base64").get<std::string>());
        auto warning=Str(payload,"warning");
        if(!warning.empty()) {side.note+=warning+"\r\n";detail.state=Detail::Truncated;}
        auto bytes=row.websocket ? message.value("body_bytes",uint64_t(0)) : payload.value("decoded_bytes",uint64_t(side.body.size()));
        side.note += std::string(row.websocket ? "Message payload: " : "Decoded body: ") + std::to_string(bytes) + " bytes.";
        if(bytes>side.body.size()) side.note += " Display limited to the first " + std::to_string(previewLimit/1024) + " KiB; cached payload is unchanged.";
    } catch (const std::exception& error) {
        side.note += std::string("Full body decoding unavailable: ") + error.what() + "\r\n";
        // Partial/compressed bytes must never be presented as decoded text.
        bool compressed = false;
        for (const auto& pair : message.at("headers")) {
            auto name = pair.at(0).get<std::string>();
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return (char)tolower(c); });
            auto value = pair.at(1).get<std::string>();
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)tolower(c); });
            auto begin = value.find_first_not_of(" \t"), end = value.find_last_not_of(" \t");
            value = begin == std::string::npos ? "" : value.substr(begin, end - begin + 1);
            if (name == "content-encoding" && !value.empty() && value != "identity") compressed = true;
        }
        command["type"] = "cache_read"; command["offset"] = 0; command["length"] = previewLimit;
        try {
            side.body = Base64(query(command).at("payload").at("data_base64").get<std::string>());
            side.encoded = compressed;
            side.note += compressed ? "Encoded prefix (HEX); not decoded." : "Available body prefix only.";
            if (detail.state == Detail::Ready) detail.state = Detail::Truncated;
        } catch (const std::exception& error2) {
            side.note += std::string("Body unavailable: ") + error2.what();
            detail.state = Detail::Unavailable;
        }
    }
    if (side.body.size() > previewLimit) {
        side.note += "\r\nDisplay limited to the first " + std::to_string(previewLimit/1024) + " KiB; cached payload is unchanged.";
        side.body.resize(previewLimit);
    }
}
Detail ReadDetail(const Query& query, const Row& row, size_t previewLimit) {
    Detail detail;
    const auto& connection = Object(row.record, "connection");
    detail.context = "PID " + std::to_string(row.pid) + " | " + row.destination + " | " + row.protocol +
        "\r\nConnection " + Str(connection, "id") + " | socket " +
        std::to_string(connection.value("socket", uint64_t(0))) + "/" +
        std::to_string(connection.value("generation", uint64_t(0))) + "\r\n";
    if (row.connectionRow) {
        detail.note = Str(row.record,"detail");
        // rustls diagnostics are prefixed with the TLS endpoint by Session::feed.
        // A client rejecting our CA or a transport failure must not suggest bypassing the target check.
        detail.targetCertificateRejected = row.status == "Failed" &&
            !row.record.value("upstream_verification_skipped",false) &&
            (detail.note.find("upstream TLS: invalid peer certificate:") == 0 ||
             (detail.note.find("Upstream QUIC handshake failed:")==0 && detail.note.find("invalid peer certificate:")!=std::string::npos));
        if ((row.protocol.find("TLS") == 0 || row.protocol.find("QUIC")==0) && row.record.value("upstream_verification_skipped",false)) detail.note += " Target certificate verification skipped.";
        return detail;
    }
    const auto& exchange = Object(row.record, row.stream && !row.websocket ? "stream" : "exchange");
    if (exchange.empty()) { detail.note = Str(row.record, "detail"); detail.state = Detail::Unavailable; return detail; }
    if (!row.stream) detail.context += "Request/stream " + std::to_string(exchange.value("id", uint64_t(0))) + "\r\n";
    detail.note = Str(exchange, "problem");
    if(Str(row.record,"protocol")=="quic_datagram")
        detail.note="Connection DATAGRAMs | ALPN: "+Str(connection,"quic_alpn")+(detail.note.empty()?"":" | "+detail.note);
    if(Str(row.record,"protocol")=="quic_stream") {
        const auto id=connection.at("quic_stream_id").get<uint64_t>();
        detail.note="Stream "+std::to_string(id)+(id&2?" | Unidirectional":" | Bidirectional")+
            (id&1?" | Server-initiated":" | Client-initiated")+" | ALPN: "+Str(connection,"quic_alpn")+
            (detail.note.empty()?"":" | "+detail.note);
    }
    if (!Str(exchange,"problem").empty()) detail.state = Detail::Truncated;
    try {
        if (!row.cacheId) throw std::runtime_error("Payload cache unavailable");
        auto status = query(Json{{"type", "cache_status"}, {"run_id", row.run}, {"cache_id", row.cacheId}}).at("cache");
        detail.cacheStamp = status.dump();
        if (status.is_null()) { detail.state = Detail::Evicted; detail.note += "\r\nCache metadata expired."; }
        else if (status.value("evicted", false)) { detail.state = Detail::Evicted; detail.note += "\r\nCached payload evicted."; }
        else if (!Str(status, "reason").empty()) { detail.state = Detail::Truncated; detail.note += "\r\nCache truncated: " + Str(status, "reason"); }
        else if (status.value("pending_chunks", 0u) || !status.value("finished", false)) {
            detail.state = Detail::Pending; detail.note += "\r\nPayload cache is still being written.";
        }
    } catch (const std::exception& error) {
        detail.state = Detail::Unavailable; detail.note += std::string("\r\n") + error.what();
        detail.cacheStamp = std::string("error:") + error.what();
    }
    if (row.dns) {
        for (int i=0;i<2;++i) {
            Side& side=i==0 ? detail.request : detail.response;
            if ((i==0 ? row.requestBytes : row.responseBytes)==0 || detail.state==Detail::Evicted || detail.state==Detail::Unavailable) continue;
            try {
                auto reply=query(Json{{"type","dns_read"},{"run_id",row.run},{"cache_id",row.cacheId},
                    {"direction",i==0 ? "client" : "server"},{"length",65535}});
                side.body=Base64(reply.at("payload").at("data_base64").get<std::string>());
                side.text=Str(reply,"text");
                if(side.body.size()>previewLimit || side.text.size()>previewLimit) {
                    side.body.resize(min(side.body.size(),previewLimit));side.text.resize(min(side.text.size(),previewLimit));
                    side.note="Display limited to the first " + std::to_string(previewLimit/1024) + " KiB; cached payload is unchanged.";
                }
                auto error=Str(reply,"decode_error");
                if (!error.empty()) { detail.state=Detail::Truncated;detail.note+="\r\n"+error; }
            } catch (const std::exception& error) {detail.state=Detail::Unavailable;detail.note+="\r\n"+std::string(error.what());}
        }
        return detail;
    }
    if(row.websocket) {
        detail.note="WebSocket message " + std::to_string(exchange.value("id",uint64_t(0)))+" | "+row.method+
            (detail.note.empty()?"":" | "+detail.note);
        ReadSide(query,row,Object(exchange,"request"),true,detail,detail.request,previewLimit);
        ReadSide(query,row,Object(exchange,"response"),false,detail,detail.response,previewLimit);
        detail.request.headers.clear();detail.response.headers.clear();
        return detail;
    }
    if (row.stream) {
        detail.context += row.protocol == "TLS (encrypted)" ? "Encrypted TLS records; plaintext is unavailable.\r\n" :
            "Bidirectional byte stream; no application message boundaries.\r\n";
        for (int i = 0; i < 2; ++i) {
            Side& side = i == 0 ? detail.request : detail.response;
            if (row.quic) {
                const auto& q=Object(row.record,"quic");
                side.text="Protocol: "+row.protocol+"\r\nAuthenticated packet type: Initial\r\nApplication payload: encrypted\r\n";
                side.text+="ClientHello SNI: "+Str(q,"sni")+"\r\nClient-offered ALPN:";
                if (q.contains("offered_alpn")) for (const auto& value:q["offered_alpn"]) side.text+=" "+value.get<std::string>();
                side.text+="\r\nECH extension: "+std::string(q.value("ech",false) ? "present (SNI may be an outer name)" : "not observed")+"\r\n";
                if (q.contains("initial_dcids")) for (const auto& value:q["initial_dcids"]) side.text+="Initial DCID: "+value.get<std::string>()+"\r\n";
                side.text+="\r\nConnection handshake summary. HexView shows captured datagrams in this direction.\r\n";
                if (!Str(q,"note").empty()) side.text+=Str(q,"note")+"\r\n";
            }

            if (row.udp) {
                const auto packets = exchange.find("datagrams");
                if (packets != exchange.end() && packets->is_array() && packets->size() == 2) {
                    for (const auto& packet : (*packets)[i]) side.datagrams.emplace_back(packet.at(0).get<uint64_t>(), packet.at(1).get<size_t>());
                }
                if (side.datagrams.empty()) continue;
                if (exchange.contains("packet_counts") && exchange["packet_counts"][i].get<uint64_t>() > side.datagrams.size())
                    detail.note += "\r\nDatagram index limited to the first " + std::to_string(side.datagrams.size()) + " packets in this direction.";
            }
            if (detail.state == Detail::Evicted || detail.state == Detail::Unavailable) continue;
            try {
                auto payload = query(Json{{"type", "cache_read"}, {"run_id", row.run}, {"cache_id", row.cacheId},
                    {"direction", i == 0 ? "client" : "server"}, {"offset", 0}, {"length", previewLimit}}).at("payload");
                side.body = Base64(payload.at("data_base64").get<std::string>());
                if (side.body.size() > previewLimit) side.body.resize(previewLimit);
                if (row.udp) {
                    // One bounded direction prefix shared by Raw and HexView.
                    const auto& prefix=side.body;
                    for (size_t n = 0; n < side.datagrams.size(); ++n) {
                        const auto& packet = side.datagrams[n];
                        if (packet.first > prefix.size() || (packet.second && packet.first == prefix.size())) {
                            side.previewLimited = prefix.size() == previewLimit; break;
                        }
                        const size_t available = prefix.size() - (size_t)packet.first;
                        const size_t count = min(packet.second, available);
                        side.packets.emplace_back(prefix.begin() + (size_t)packet.first,
                            prefix.begin() + (size_t)packet.first + count);
                        if (count < packet.second) {
                            side.previewLimited = prefix.size() == previewLimit;
                            break;
                        }
                    }
                }
                side.encoded = row.protocol == "TLS (encrypted)";
                side.note = "Stream prefix: " + std::to_string(side.body.size()) + " bytes (display limit: " + std::to_string(previewLimit/1024) + " KiB).";
            } catch (const std::exception& error) {
                detail.state = Detail::Unavailable; side.note = error.what();
            }
        }
        return detail;
    }
    ReadSide(query, row, Object(exchange, "request"), true, detail, detail.request, previewLimit);
    ReadSide(query, row, Object(exchange, "response"), false, detail, detail.response, previewLimit);
    auto info = exchange.find("informational");
    std::string informational;
    if (info != exchange.end()) for (const auto& message : *info)
        informational += Headers(message, false, row.protocol.find("QUIC/") == 0 ? row.protocol.substr(5) : row.protocol.find("TLS/") == 0 ? row.protocol.substr(4) : row.protocol) + "\r\n";
    detail.response.headers = informational + detail.response.headers;
    return detail;
}
std::string CacheStamp(const Query& query, const Row& row) {
    try {
        if (!row.cacheId) throw std::runtime_error("Payload cache unavailable");
        return query(Json{{"type", "cache_status"}, {"run_id", row.run}, {"cache_id", row.cacheId}}).at("cache").dump();
    } catch (const std::exception& error) { return std::string("error:") + error.what(); }
}
std::vector<unsigned char> DisplayBytes(const Side& side) {
    std::vector<unsigned char> bytes(side.headers.begin(), side.headers.end());
    if (!bytes.empty()) { bytes.push_back('\r'); bytes.push_back('\n'); }
    bytes.insert(bytes.end(), side.body.begin(), side.body.end());
    return bytes;
}
bool Matches(const Row& row, const std::string& filter, int protocol) {
    if (protocol == 1 && row.protocol.find("HTTP/") == std::string::npos) return false;
    if (protocol == 2 && row.protocol != "TCP" && row.protocol != "DNS/TCP") return false;
    if (protocol == 3 && !row.udp && row.protocol!="QUIC" && row.protocol.find("QUIC/")!=0) return false;
    if (protocol == 4 && row.protocol.find("TLS") != 0 && row.protocol!="QUIC" && row.protocol.find("QUIC/")!=0) return false;
    if (protocol == 5 && !row.dns && !row.doh) return false;
    if (protocol == 6 && !row.quic && row.protocol!="QUIC" && row.protocol.find("QUIC/")!=0) return false;
    if (filter.empty()) return true;
    std::string needle = filter;
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) { return (char)tolower(c); });
    if (needle.find_first_not_of("0123456789") == std::string::npos) return std::to_string(row.pid) == needle;
    std::string haystack = row.process + " " + row.destination + " " + row.target;
    std::transform(haystack.begin(), haystack.end(), haystack.begin(), [](unsigned char c) { return (char)tolower(c); });
    return haystack.find(needle) != std::string::npos;
}

}
