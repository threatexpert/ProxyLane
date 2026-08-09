# ProxyLane end-to-end test tools

These small Go and Python programs provide controlled endpoints for testing the
real injected Windows binaries. They intentionally use TEST-NET-3 addresses
(`203.0.113.0/24`) and `.test` names; the local proxy servers map those targets
to loopback test services.

## Programs

- `socks5_udp_server.go`: SOCKS5 CONNECT and UDP ASSOCIATE server, optional
  username/password authentication and byte-at-a-time handshake replies.
- `socks5_udp_server.py`: UDP ASSOCIATE reference server with malformed-packet
  and forged-relay-source fault injection.
- `udp_soak.go`: concurrent UDP load, latency, loss, socket and association
  lifecycle test.
- `udp_echo.go`: IPv4/IPv6 UDP echo endpoint used by the soak and QUIC route
  tests.
- `ipv6_egress_probe.go`: TCP/TLS and UDP/DNS probes for validating IPv6
  targets through a SOCKS5 server on an IPv4-only local network.
- `udp_writemsg_probe.go`: Windows `WriteToUDP` / `WriteMsgUDP` compatibility
  probe, including IPv4-mapped destinations on dual-stack sockets.
- `udp_connect_probe.go`: connected UDP lifecycle probe. By default it only
  connects and closes without sending; `-write` activates one datagram per
  socket. This verifies that route reservation does not eagerly open SOCKS5
  UDP associations.
- `quic/`: quic-go stream and unreliable-datagram echo test.
- `tcp_e2e.go`: TCP server/client whose response is sent only after the server
  observes EOF. This makes successful completion proof of end-to-end
  half-close propagation.
- `connectex_initial_data.cpp`: native Windows probe that submits the first
  application payload in `ConnectEx`. It covers data queued while the PRC is
  still negotiating SOCKS5/HTTP, including the Windows XP notification path.
- `http_connect_server.go`: HTTP CONNECT proxy that deliberately writes its
  final response header and initial tunnel bytes together to verify surplus
  preservation.

## Build examples

```powershell
go build -o build/qa/go/socks5_e2e_server.exe tests/e2e/socks5_udp_server.go
go build -o build/qa/go/udp_soak.exe tests/e2e/udp_soak.go
go build -o build/qa/go/udp_echo.exe tests/e2e/udp_echo.go
go build -o build/qa/go/ipv6_egress_probe.exe tests/e2e/ipv6_egress_probe.go
go build -o build/qa/go/udp_connect_probe.exe tests/e2e/udp_connect_probe.go
go build -o build/qa/go/tcp_e2e.exe tests/e2e/tcp_e2e.go
go build -o build/qa/go/http_connect_server.exe tests/e2e/http_connect_server.go
Push-Location tests/e2e/quic
go build -o ../../../build/qa/go/quic_e2e.exe .
Pop-Location
```

Build the native Win32 probe from a Visual Studio developer prompt:

```bat
cl /nologo /EHsc /O2 tests\e2e\connectex_initial_data.cpp /Fe:build\qa\connectex_initial_data32.exe
```

Launch the client through ProxyLane's automation interface after creating a
temporary profile that points at the corresponding local proxy:

```powershell
bin/ProxyLane64.exe --auto --profile E2E --run `
  build/qa/go/tcp_e2e.exe -- -mode client `
  -target 203.0.113.10:39003 -connections 8 -iterations 10
```

The servers, temporary profiles and ports are test-owned resources. Do not run
these mappings against production proxy settings.
