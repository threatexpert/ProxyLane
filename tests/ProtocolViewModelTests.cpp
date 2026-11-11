// Build with ProtocolViewModel.cpp /DPROTOCOL_VIEW_TEST; no MFC/UI required.
#include "../src/ProxyLane/ProtocolViewModel.h"
#include <cassert>
#include <iostream>
#include <fstream>
#include <stdexcept>
using namespace ProtocolView;

Json Message(bool request) {
    return Json{{"method", request ? Json("GET") : Json()}, {"target", request ? Json("/test") : Json()},
        {"status", request ? Json() : Json(200)}, {"headers", Json::array({Json::array({"content-type", "text/plain"})})},
        {"trailers", Json::array()}, {"body_bytes", request ? 0 : 5}, {"complete", true},
        {"body_base64", "aGVsbG8="}, {"decoded_base64", "aGVsbG8="}, {"text", "hello"}, {"decoding", "ok"}};
}
Json Record() {
    return Json{{"type", "exchange"}, {"sequence", 1}, {"protocol", "h2"},
        {"connection", {{"id", "9"}, {"pid", 123}, {"process_start", uint64_t(1234567890123)},
            {"socket", 77}, {"generation", 2}, {"destination", "test:443"}}},
        {"exchange", {{"id", 3}, {"cache", {{"id", 1}}}, {"problem", nullptr},
            {"request", Message(true)}, {"response", Message(false)}, {"informational", Json::array()}}}};
}
struct Fixture {
    Json record = Record();
    Json cache = {{"id", 1}, {"request_bytes", 0}, {"response_bytes", 5}, {"finished", true},
        {"pending_chunks", 0}, {"evicted", false}, {"reason", nullptr}};
    std::string run = "run-A", payload = "aGVsbG8=", error;
    int reads = 0;
    Query query() {
        return [this](const Json& command) -> Json {
            auto type = command.at("type").get<std::string>();
            if (type == "stats") return {{"type", "stats"}, {"run_id", run}, {"last_sequence", 1}};
            if (type == "poll") return {{"type", "records"}, {"run_id", run}, {"next", 1}, {"lost_before", 0},
                {"records", command.value("after", 0u) == 0 ? Json::array({record}) : Json::array()}};
            if (command.at("run_id") != run) throw std::runtime_error("stale or missing run_id");
            if (type == "cache_status") return {{"cache", cache}};
            ++reads;
            if (type == "cache_decode" && !error.empty()) throw std::runtime_error(error);
            if (type == "dns_read" || type == "doh_read") return {{"payload",{{"data_base64",payload}}},{"text","[Answer]\r\na.test. 60 IN A 1.2.3.4"}};
            return {{"payload", {{"data_base64", payload}}}};
        };
    }
    Row row() { return Poll(query(), "", 0, false).rows.at(0); }
};
int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--h3-history") {
        std::cout << "Replaying " << argv[2] << std::endl;
        try {
        std::ifstream input(argv[2]); Json results; input >> results;
        for (const auto& browser : results) {
            History history; std::map<std::string, Row> latest; size_t events=0;
            for (const auto& poll : browser.at("polls")) {
                Json reply=poll.at("reply"), records=Json::array();
                if(reply.value("type",std::string())=="inactive") continue;
                for (const auto& record : reply.at("records"))
                    if (record.value("type",std::string())=="exchange" && record.value("protocol",std::string())=="h3")
                        records.push_back(record);
                reply["records"]=records;
                auto batch=Poll([&](const Json&){return reply;},"",0,false);
                for (auto row : batch.rows) {
                    ++events; latest[row.key]=row; history.Add(row);
                    if(history.rows.size()!=latest.size()) throw std::runtime_error("duplicate history row");
                }
            }
            if(latest.empty() || events<=latest.size()) throw std::runtime_error("missing real progress snapshots");
            for (const auto& row : history.rows) {
                assert(row.sequence==latest.at(row.key).sequence);
                assert(row.responseBytes==latest.at(row.key).responseBytes);
            }
            std::cout << "PASS " << browser.at("browser").get<std::string>() << " real HTTP/3 history: "
                << events << " snapshots -> " << latest.size() << " request rows\n";
        }
        return 0;
        } catch(const std::exception& e) {std::cerr << "Replay failed: " << e.what() << std::endl;return 1;}
    }
    if (argc == 2) {
        // Replay actual MITM queries saved by the injected TLS end-to-end host.
        std::ifstream input(argv[1]); std::string line; std::vector<Json> replies;
        while (std::getline(input, line)) if (line.find("PROTOCOL_JSON ") == 0)
            replies.push_back(Json::parse(line.substr(14)));
        Query query = [&](const Json& cmd) -> Json {
            for (const auto& reply : replies) {
                auto type = reply.value("type", std::string());
                if (cmd["type"] == "poll" && type == "records") return reply;
                if (cmd["type"] == "cache_status" && type == "cache_status" &&
                    reply["run_id"] == cmd["run_id"] && reply["cache"].is_object() && reply["cache"]["id"] == cmd["cache_id"]) return reply;
                if (type == "cache_payload" && reply["run_id"] == cmd["run_id"] &&
                    reply["payload"]["cache"]["id"] == cmd["cache_id"] && reply["payload"]["direction"] == cmd["direction"] &&
                    reply["payload"]["decoded"] == (cmd["type"] == "cache_decode")) return reply;
            }
            throw std::runtime_error("reply unavailable in recorded trace");
        };
        auto batch = Poll(query, "", 0, false); assert(!batch.rows.empty());
        unsigned shown = 0;
        for (const auto& row : batch.rows) {
            auto detail = ReadDetail(query, row);
            if (!detail.response.body.empty() && !detail.response.encoded) ++shown;
            assert(row.record.dump().find("body_base64") == std::string::npos);
            assert(detail.response.body.size() <= BodyPreviewLimit);
        }
        assert(shown > 0);
        std::cout << "PASS real MITM trace: " << shown << " decoded response(s)\n"; return 0;
    }
    Fixture f; auto row = f.row();
    assert(row.pid == 123 && row.processStart == 1234567890123 && row.protocol == "HTTP/2");
    assert(row.record.dump().find("body_base64") == std::string::npos);
    f.record["connection"]["process_name"] = "curl.exe";
    f.record["connection"]["server_name"] = "ifconfig.io";
    f.record["connection"]["server_port"] = 443;
    f.record["connection"]["destination"] = "ifconfig.io:443";
    row = f.row();
    assert(row.process == "curl.exe" && row.destination == "ifconfig.io:443");
    f.record["connection"]["server_name"] = "::1";
    assert(f.row().destination == "[::1]:443");
    f.record["connection"].erase("server_name");
    assert(f.row().destination == "ifconfig.io:443");
    f = Fixture(); row = f.row();
    auto detail = ReadDetail(f.query(), row);
    assert(detail.state == Detail::Ready && std::string(detail.response.body.begin(), detail.response.body.end()) == "hello");
    assert(detail.request.headers.find("GET /test") == 0 && detail.response.headers.find("200") != std::string::npos);
    assert(detail.context.find("77/2") != std::string::npos && detail.context.find("Request/stream 3") != std::string::npos);
    assert(CacheStamp(f.query(), row) == detail.cacheStamp);
    f.cache["evicted"] = true; f.reads = 0;
    assert(CacheStamp(f.query(), row) != detail.cacheStamp);
    detail = ReadDetail(f.query(), row);
    assert(detail.state == Detail::Evicted && detail.response.body.empty() && f.reads == 0);
    f.cache = nullptr; assert(ReadDetail(f.query(), row).state == Detail::Evicted);
    f = Fixture(); row = f.row(); f.cache["reason"] = "per-exchange payload limit"; f.error = "cannot decode incomplete cached body";
    detail = ReadDetail(f.query(), row);
    assert(detail.state == Detail::Truncated && detail.note.find("per-exchange payload limit") != std::string::npos);
    assert(!detail.response.encoded && !detail.response.body.empty());
    f.record["exchange"]["response"]["headers"].push_back(Json::array({"content-encoding", "gzip"})); row = f.row();
    detail = ReadDetail(f.query(), row); assert(detail.response.encoded && detail.response.note.find("not decoded") != std::string::npos);
    f.run = "run-B"; detail = ReadDetail(f.query(), row);
    assert(detail.state == Detail::Unavailable && detail.response.body.empty());
    auto reset = Poll(f.query(), "run-A", 99, false); assert(reset.rows.size() == 1 && reset.next == 1 && reset.run == "run-B");
    auto baseline = Poll(f.query(), "run-A", 0, true); assert(baseline.rows.empty() && baseline.next == 1);
    f = Fixture(); f.record["exchange"]["response"]["complete"] = false; f.record["exchange"]["problem"] = "truncated response";
    row = f.row(); detail = ReadDetail(f.query(), row); assert(detail.state == Detail::Truncated && row.status == "200 *");
    f = Fixture(); f.payload = std::string(4 * 40000, 'A');
    detail = ReadDetail(f.query(), f.row());
    assert(detail.response.body.size() == BodyPreviewLimit && detail.response.note.find("Display limited") != std::string::npos);
    History history;
    for (int i = 0; i < 1000; ++i) history.Add(row);
    assert(history.rows.size() == RowLimit && history.discarded == 1000 - RowLimit);
    history.Clear(); row.bytes = MetadataLimit / 3;
    for (int i = 0; i < 10; ++i) history.Add(row);
    assert(history.rows.size() == 3 && history.bytes <= MetadataLimit && history.discarded == 7);
    row.bytes = MetadataLimit + 1; history.Add(row); assert(history.discarded == 8);
    f = Fixture(); f.record.erase("exchange"); f.record["type"] = "stream"; f.record["protocol"] = "tcp";
    f.record["stream"] = {{"sent_bytes", 2}, {"received_bytes", 5}, {"finished", false}, {"cache", {{"id", 7}}}};
    row = f.row(); assert(row.stream && row.protocol == "TCP" && row.status == "Active");
    detail = ReadDetail(f.query(), row);
    assert(detail.request.headers.empty() && !detail.request.body.empty());
    history.Clear(); row.hex = true; history.Add(row);
    row.sequence++; row.hex = false; row.responseBytes = 100; history.Add(row);
    assert(history.rows.size() == 1 && history.rows.front().hex && history.rows.front().responseBytes == 100);
    f.record["protocol"] = "tls_encrypted"; detail = ReadDetail(f.query(), f.row());
    assert(detail.response.encoded && detail.context.find("plaintext is unavailable") != std::string::npos);
    f.cache["evicted"] = true; f.reads = 0; detail = ReadDetail(f.query(), f.row());
    assert(detail.state == Detail::Evicted && detail.response.body.empty() && f.reads == 0);
    f = Fixture(); f.record["connection"]["decrypted"] = true;
    f.record["connection"]["server_name"] = "1.2.3.4"; f.record["connection"]["server_port"] = 443;
    f.record["exchange"]["request"]["headers"].push_back(Json::array({":authority", "domain.test"}));
    row = f.row(); detail = ReadDetail(f.query(),row);
    assert(row.protocol == "TLS/HTTP/2" && row.destination == "domain.test:443");
    assert(detail.request.headers.find("GET /test HTTP/2") == 0 && detail.request.note.find("Empty body") == std::string::npos);
    auto raw = DisplayBytes(detail.request); assert(!raw.empty() && raw[0] == 'G');
    row.process = "Chrome.exe";
    assert(Matches(row,"chrome",0) && Matches(row,"123",0) && !Matches(row,"12",0));
    assert(Matches(row,"domain.test",4) && !Matches(row,"",3));
    history.Clear(); history.Add(row); auto first = history.rows.front().number; row.key += "b"; history.Add(row);
    assert(first == 1 && history.rows.back().number == 2);
    f=Fixture(); f.record["type"]="dns"; f.record["protocol"]="dns";f.record["connection"]["transport"]="udp";
    f.record["exchange"]={{"id",8},{"name","a.test."},{"kind","A"},{"status","Pending"},
        {"sent_bytes",20},{"received_bytes",0},{"cache",{{"id",1}}}};
    row=f.row();assert(row.dns && row.udp && !row.stream && row.protocol=="DNS/UDP");
    assert(Matches(row,"a.test",5) && Matches(row,"",3) && !Matches(row,"",6));
    detail=ReadDetail(f.query(),row);assert(detail.request.text.find("[Answer]")==0 && detail.response.text.empty());
    assert(DisplayBytes(detail.request)==std::vector<unsigned char>({'h','e','l','l','o'}));
    history.Clear();history.Add(row);auto number=history.rows.front().number;row.sequence++;row.status="NOERROR";history.Add(row);
    assert(history.rows.size()==1 && history.rows.front().number==number && history.rows.front().status=="NOERROR");
    f.cache["evicted"]=true;detail=ReadDetail(f.query(),row);assert(detail.request.text.empty() && detail.request.body.empty());
    f=Fixture();f.record["type"]="stream";f.record["protocol"]="udp";
    f.record["stream"]={{"sent_bytes",6},{"received_bytes",3},{"cache",{{"id",1}}},
        {"datagrams",Json::array({Json::array({Json::array({0,3}),Json::array({3,3}),Json::array({6,0})}),
            Json::array({Json::array({0,3})})})}};
    row=f.row(); row.datagram[0]=1;
    Query packets=[&](const Json& command)->Json {
        if(command["type"]!="cache_read") return f.query()(command);
        ++f.reads;
        assert(command["length"].get<size_t>()<=128);
        return {{"payload",{{"data_base64",command["direction"]=="server" ? "UkVQ" :
            command["offset"]==3 ? "VFdP" : command["length"].get<size_t>()==3 ? "T05F" : command["length"].get<size_t>()==4 ? "T05FVA==" : "T05FVFdP"}}}};
    };
    detail=ReadDetail(packets,row,128);
    assert(detail.request.text.empty() && detail.request.packets.size()==3 && detail.request.packets[2].empty());
    assert(detail.request.packets[0]==std::vector<unsigned char>({'O','N','E'}) && detail.request.packets[1]==std::vector<unsigned char>({'T','W','O'}));
    assert(detail.request.body==std::vector<unsigned char>({'O','N','E','T','W','O'}) && f.reads==2);
    assert(detail.response.packets.size()==1 && detail.response.packets[0]==std::vector<unsigned char>({'R','E','P'}));
    detail=ReadDetail(packets,row,4);
    assert(detail.request.previewLimited && detail.request.packets.size()==2 && detail.request.packets[1]==std::vector<unsigned char>({'T'}));
    f.cache["evicted"]=true; f.reads=0; detail=ReadDetail(packets,row,128);
    assert(detail.request.packets.empty() && detail.request.body.empty() && f.reads==0);
    f=Fixture();f.record["type"]="stream";f.record["protocol"]="quic";
    f.record["connection"]["server_port"]=443;
    f.record["quic"]={{"version",1},{"sni","example.com"},{"offered_alpn",Json::array({"h3"})},{"ech",false}};
    f.record["stream"]={{"sent_bytes",1200},{"received_bytes",0},{"cache",{{"id",1}}},
        {"datagrams",Json::array({Json::array({Json::array({0,1200})}),Json::array()})}};
    row=f.row();assert(row.quic && row.udp && row.protocol=="QUIC v1" && row.destination=="example.com:443");
    assert(Matches(row,"",6) && !Matches(row,"",1));detail=ReadDetail(f.query(),row);
    assert(detail.request.text.find("Application payload: encrypted")!=std::string::npos && detail.request.text.find("h3")!=std::string::npos);
    f=Fixture();f.record["type"]="connection";f.record["status"]="TLS handshaking";f.record["protocol"]="tls_stream";
    auto placeholder=f.row();history.Clear();history.Add(placeholder);auto placeholderNumber=history.rows.front().number;
    detail=ReadDetail(f.query(),placeholder);assert(f.reads==0 && detail.request.body.empty() && detail.state==Detail::Ready);
    f.record["status"]="Failed";
    for(const auto& reason : {"UnknownIssuer","certificate expired: verification time 1","certificate not valid for name example.test"}) {
        f.record["detail"]=std::string("upstream TLS: invalid peer certificate: ")+reason;
        assert(ReadDetail(f.query(),f.row()).targetCertificateRejected);
    }
    for(const auto& reason : {"application TLS: invalid peer certificate: UnknownIssuer","TCP connection failed: 10060","upstream TLS: received fatal alert: UnknownCA"}) {
        f.record["detail"]=reason;
        assert(!ReadDetail(f.query(),f.row()).targetCertificateRejected);
    }
    f.record["detail"]="Upstream QUIC handshake failed: invalid peer certificate: UnknownIssuer";
    assert(ReadDetail(f.query(),f.row()).targetCertificateRejected);
    f.record["detail"]="upstream TLS: invalid peer certificate: BadSignature";
    f.record["upstream_verification_skipped"]=true;
    assert(!ReadDetail(f.query(),f.row()).targetCertificateRejected);
    f=Fixture();f.record["sequence"]=2;f.record["connection"]["decrypted"]=true;f.record["doh"]=Json::object();f.record["exchange"]["response"]["headers"]=Json::array({Json::array({"content-type","application/dns-message"})});
    row=f.row();assert(row.protocol=="TLS/HTTP/2 / DoH" && Matches(row,"",5));
    history.Add(row);assert(history.rows.size()==1 && history.rows.front().number==placeholderNumber && !history.rows.front().connectionRow);
    placeholder.sequence=3;placeholder.status="Closed";history.Add(placeholder);assert(history.rows.size()==1 && !history.rows.front().connectionRow);
    detail=ReadDetail(f.query(),row);assert(detail.response.text.find("[Answer]")!=std::string::npos);
    assert(detail.response.headers.find("DoH")==std::string::npos && DisplayBytes(detail.response).size()>5);
    f.cache["evicted"]=true;detail=ReadDetail(f.query(),row);assert(detail.response.text.empty() && detail.response.body.empty());
    f=Fixture();f.record["protocol"]="h3";f.record["connection"]["decrypted"]=true;
    f.record["connection"]["transport"]="udp";f.record["exchange"]["id"]=0;
    row=f.row();assert(row.protocol=="QUIC/HTTP/3" && !row.udp && !row.stream);
    assert(Matches(row,"",1) && Matches(row,"",3) && Matches(row,"",4) && Matches(row,"",6));
    detail=ReadDetail(f.query(),row);assert(detail.request.headers.find("HTTP/3")!=std::string::npos);
    // One HTTP/3 request: headers, progress, end and final cache snapshot must
    // update one row, including stream zero; keep the user's view and row identity.
    history.Clear(); row.hex=true; history.Add(row);
    const auto h3key=history.rows.front().key;
    const auto h3number=history.rows.front().number;
    const auto h3time=history.rows.front().firstSeenSeconds;
    for(uint64_t seq=2;seq<=6;++seq) {
        f.record["sequence"]=seq; f.record["exchange"]["response"]["body_bytes"]=seq*112;
        history.Add(f.row());
        assert(history.rows.size()==1 && history.rows.front().key==h3key);
        assert(history.rows.front().number==h3number && history.rows.front().firstSeenSeconds==h3time);
        assert(history.rows.front().hex && history.rows.front().responseBytes==seq*112);
        assert(history.bytes==history.rows.front().bytes);
    }
    history.Add(row); // Delayed/replayed old snapshot cannot roll back progress.
    assert(history.rows.size()==1 && history.rows.front().responseBytes==672);
    f.record["sequence"]=7; f.record["exchange"]["id"]=4; history.Add(f.row());
    assert(history.rows.size()==2); // Same URL on another stream is a real request.
    f.record["sequence"]=8; f.record["connection"]["id"]="10"; f.record["exchange"]["id"]=0;
    history.Add(f.row()); assert(history.rows.size()==3); // Stream IDs restart per connection.
    f.run="run-B"; history.Add(f.row()); assert(history.rows.size()==4);
    f=Fixture();f.record["type"]="stream";f.record["protocol"]="quic_stream";
    f.record["connection"]["transport"]="udp";f.record["connection"]["quic_stream_id"]=0;
    f.record["connection"]["quic_alpn"]="raw-test/1";
    f.record["stream"]={{"sent_bytes",5},{"received_bytes",5},{"cache",{{"id",1}}},{"finished",true},{"complete",true}};
    row=f.row();assert(row.stream && !row.udp && !row.quic && row.protocol=="QUIC/Raw" && row.method=="Stream 0");
    assert(Matches(row,"",6));detail=ReadDetail(f.query(),row);
    assert(detail.state==Detail::Ready && detail.note.find("ALPN: raw-test/1")!=std::string::npos);
    assert(detail.request.headers.empty() && DisplayBytes(detail.request)==std::vector<unsigned char>({'h','e','l','l','o'}));
    history.Clear();history.Add(row);f.record["sequence"]=2;f.record["connection"]["quic_stream_id"]=4;history.Add(f.row());
    assert(history.rows.size()==2 && history.rows[0].key!=history.rows[1].key);
    f.record["sequence"]=3;f.record["stream"]["sent_bytes"]=8;history.Add(f.row());assert(history.rows.size()==2 && history.rows[1].requestBytes==8);
    f.record["sequence"]=4;f.record["protocol"]="quic_datagram";
    f.record["connection"].erase("quic_stream_id");f.record["connection"]["quic_datagrams"]=true;
    f.record["stream"]["datagrams"]=Json::array({Json::array({Json::array({0,2}),Json::array({2,0}),Json::array({2,3})}),Json::array()});
    f.record["stream"]["packet_counts"]=Json::array({3,0});
    row=f.row();history.Add(row);assert(history.rows.size()==3);
    assert(row.protocol=="QUIC/DATAGRAM" && row.udp && !row.quic && Matches(row,"",6));
    detail=ReadDetail(f.query(),row);
    assert(detail.note.find("Connection DATAGRAMs")!=std::string::npos);
    assert(detail.request.packets.size()==3 && detail.request.packets[1].empty());
    assert(detail.request.packets[0]==std::vector<unsigned char>({'h','e'}));
    assert(detail.request.packets[2]==std::vector<unsigned char>({'l','l','o'}));
    f.record["type"]="connection";f.record["protocol"]="quic";f.record["status"]="Connecting";
    row=f.row();assert(row.connectionRow && row.protocol=="QUIC" && Matches(row,"",6) && Matches(row,"",3));
    f=Fixture();f.record["protocol"]="websocket";f.record["connection"]["decrypted"]=true;
    f.record["exchange"]["request"]=nullptr;f.record["exchange"]["response"]["method"]="TEXT";
    f.record["exchange"]["response"]["observed_start_unix_ms"]=uint64_t(1792500000123);
    row=f.row();assert(row.websocket && row.stream && row.protocol=="TLS/WebSocket" && row.status=="Received");
    assert(row.firstSeenSeconds==1792500000);detail=ReadDetail(f.query(),row);
    assert(detail.response.headers.empty() && DisplayBytes(detail.response)==std::vector<unsigned char>({'h','e','l','l','o'}));
    f.record["exchange"]["response"]["body_bytes"]=uint64_t(8*1024*1024);
    row=f.row();auto wsQuery=f.query();
    Query noWsDecode=[wsQuery](const Json& q) {
        assert(q.value("type","")!="cache_decode"); return wsQuery(q);
    };
    detail=ReadDetail(noWsDecode,row);
    assert(detail.response.note.find("8388608 bytes")!=std::string::npos);
    assert(detail.response.note.find("Full body decoding unavailable")==std::string::npos);
    f=Fixture();row=f.row();
    auto baseQuery=f.query();
    Query warningQuery=[baseQuery](const Json& q) {auto r=baseQuery(q);if(q.value("type","")=="cache_decode") r["payload"]["warning"]="Gzip stream did not finish; integrity unverified.";return r;};
    detail=ReadDetail(warningQuery,row);
    assert(detail.state==Detail::Truncated && !detail.response.encoded && detail.response.note.find("integrity unverified")!=std::string::npos);
    std::cout << "PASS protocol view: HTTP, DNS, QUIC, WebSocket messages, warned gzip preview and bounds\n";
}
