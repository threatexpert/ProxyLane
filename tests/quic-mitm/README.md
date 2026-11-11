# QUIC MITM feasibility probe (Windows x64)

This is a separate test program, not an enabled ProxyLane feature. It does not
modify the GUI, shipping dependency graph, application profiles, system trust,
or `bin` contents. The native host reads the existing x64 Hook DLL/import library.

The probe terminates a client QUIC v1 / HTTP/3 connection using a certificate
issued by the **existing ProxyLane CA code**, then creates an independently
verified QUIC / HTTP/3 connection to a controlled origin. An independent Python
aioquic client and origin verify headers, concurrent streams and body integrity.
No HTTP/2 or TCP fallback is accepted as a successful h3 test.

## Observed results (2026-10-18)

Evidence: `build/qa/quic-mitm-548bb72aae1d/results.json` and its adjacent logs.
Quinn 0.11.9 / rustls 0.23.43 / h3 0.0.8 / h3-quinn 0.0.10, aioquic 1.7.0.

| Case | Result |
| --- | --- |
| Direct baseline, NOPROXY, SOCKS5 IP, SOCKS5 remote domain | All passed; each transferred 11 concurrent requests including a 1 MiB POST echo with byte-for-byte integrity |
| Client missing CA; unknown SNI | Rejected |
| Origin CA not trusted by proxy | Rejected with `UnknownIssuer`; no HTTP forwarded |
| Unavailable SOCKS5, otherwise directly reachable origin | Rejected; no origin QUIC handshake/request, no direct fallback |
| Chrome 155.0.8059.80, normal discovery | TCP trusted; QUIC certificate verification failed; 0 h3 requests |
| Chrome, explicit test-origin force-QUIC flag | 2 h3 requests through MITM and SOCKS5; no ignore-certificate-errors flag |
| Edge 155.0.4283.45, normal discovery | TCP trusted; QUIC certificate verification failed; 0 h3 requests |
| Edge, explicit test-origin force-QUIC flag | 2 h3 requests through MITM and SOCKS5; no ignore-certificate-errors flag |
| Firefox 154.0, normal third-party-root policy | TCP fallback; 0 h3 requests |
| Firefox, third-party-root HTTP/3 disable policy set false in test profile | 17 h3 requests through MITM and SOCKS5, following one TCP bootstrap request |

These are local controlled interoperability results, not Internet/site coverage or
production load testing. The normal browser cases are recorded compatibility
limitations, not silently counted as QUIC success. Ordinary browser defaults do
not provide the same private-CA QUIC experience as TCP HTTPS.

## Chrome SSLErrorOverrideAllowed policy experiment (2026-10-19)

Evidence: `build/qa/quic-policy-fcdb10ac9d92/results.json`,
`registry-backup.json`, and per-case `chrome-policy-*/` NetLogs and policy snapshots.
Chrome 155.0.8059.80, existing current-user ProxyLane CA trust, local controlled
origin and the existing Hook -> SOCKS5 domain UDP route:

| HKCU SSLErrorOverrideAllowed | Effective chrome://policy status | H3 requests | TCP requests |
| --- | --- | --- | --- |
| Unset | Unset | 0 | 18 |
| DWORD 0 | false, OK | 0 | 18 |
| DWORD 1 | true, OK | 0 | 18 |
| DWORD 1 + per-origin force-QUIC positive control | true, OK | 2 | 0 |

The three normal cases attempted QUIC and recorded certificate-unknown /
CERTIFICATE_VERIFY_FAILED, then used TCP. Opening the page was not counted as
HTTP/3 success. No ignore-certificate-errors setting was used. The positive
control changes the per-origin QUIC unknown-root exception, not this policy.
The registry value was originally absent and was restored to absence; only
test-owned browser processes were stopped and temporary private keys were removed.

The policy's documented default is true. It controls whether a user may proceed
from an overridable SSL warning page, not whether a private CA is a QUIC known root.
See the [policy definition](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/Miscellaneous/SSLErrorOverrideAllowed.yaml)
and [QUIC certificate check](https://github.com/chromium/chromium/blob/main/net/quic/crypto/proof_verifier_chromium.cc).

Reproduce with `python tests/e2e/quic_ssl_policy_probe.py`. This script temporarily
changes **user-wide** HKCU policy (not just the isolated browser profile). Windows
may require UAC confirmation for its separate, narrowly scoped registry helper;
Chrome itself runs unelevated. The helper restores the original registry value
and type in `finally`, after 90 seconds without a command, or after 300 seconds
total. A machine shutdown/forced helper termination can bypass that cleanup;
`registry-backup.json` retains the original value/type and created-key list.
Use `--baseline-only` to test the unset case without elevation or registry writes.
The helper's elevated process imports only Python standard-library modules.

Use `--current-policy-only` to verify an already installed HKCU DWORD 1 without
writing/restoring the registry or starting an elevated helper. A separate rerun
after the user manually confirmed the installed policy produced the same result:
`build/qa/quic-policy-0684924c5bf1/results.json` (Chrome 155.0.8059.80, policy true
and OK, 0 H3 / 18 TCP requests, QUIC certificate verification failure).
`registry-observation.json` confirms the value remained DWORD 1 before/after.

## Build and run

### Single-Hook QUIC policy probe (current experiment)

This supersedes the CA-specific policy experiment below. The independent
`quic_decryption` boolean defaults to false. Its approved explanatory text is:

> Chromium 内核浏览器可能拒绝 QUIC 使用已受信任的本地或企业 CA。开启后将尝试放宽此限制，以支持 QUIC 解密，仍保留正常证书校验。

The switch and text are in the isolated runner's options JSON, not the shipping
GUI/INI. This remains a controlled MITM/UDP-route prototype, not transparent
capture of arbitrary browser destinations.

`browser_quic_policy_probe.cpp` attaches only
`Job::ShouldAllowUnknownRootForHost`. It neither hooks the completion routine nor
reads any certificate, C++ object layout, hostname or leaf/root identity. When
enabled, a recognized caller may allow any CA accepted by the browser's normal
verification. Original allowances are preserved. Disable restores the original
decision for subsequent checks without unloading code or closing connections.
An owner-process handle and a bounded lease also disable the exception if its
controller disappears or stops renewing it.

`locate_policy_hook.py` uses two independent diagnostic strings, PE unwind
boundaries and a conservative instruction-family rule for the guarded call and
unknown-root error selection. Register choices, RVAs and member displacements
are derived; no version/hash whitelist or fixed function address is supplied.
The recognized result guard, known-root branch and bool-return use must agree.
Missing, ambiguous, inlined or changed instruction shapes are unsupported.
Full control-flow equivalence across arbitrary future compilers is not claimed.

The controller caches discovery; before attachment the DLL verifies exact module
identity, full live bytes of both functions, unwind ranges and the direct call.
Only the identified return address gains the exception; this is a code-site check,
not per-connection authorization. The completion function is read, not detoured.
`check_policy_locator.py` mutates actual binary evidence in memory to check
rejection of missing anchors, a different error and a broken boolean test.

```powershell
./scripts/build-quic-policy-probe.ps1
python tests/e2e/quic_single_hook_probe.py --mode disabled
python tests/e2e/quic_single_hook_probe.py
python tests/e2e/quic_single_hook_probe.py --mode webtransport
python tests/e2e/quic_launch_flag_probe.py
```

The matrix covers both browsers: default-off, enabled, another trusted private
CA, untrusted same-name CA, expired/wrong-host certificates, wrong module/code
digest, and launch-argument controls without the Hook. Positive cases verify a
64 KiB binary echo through the existing Hook/SOCKS UDP route to an independent
origin. Hook-positive cases also check an established connection after disable,
then force a fresh handshake and check rejection. Invalid certificates must have
the expected normal certificate error in the fixture's NetLog verifier job.

Verified on Chrome 155.0.8059.80 and Edge 155.0.4283.62 (Windows x64):
`build/qa/quic-single-hook-1320dc00a115/results.json` passed all 26 cases,
including 16 single-Hook cases and 10 force-QUIC argument controls. Both browsers
accepted the ProxyLane CA and a different trusted private CA when enabled;
untrusted, expired and wrong-host certificates remained rejected. All four
Hook-positive cases preserved the established transfer after disabling the
exception and rejected a subsequent fresh handshake. The adjacent
`locator-negative.json` records three successful fail-closed mutation checks.

`build/qa/quic-single-hook-90348e74ab19/results.json` records two additional
ordinary HTTP/3 controls: `--webtransport-developer-mode` alone did not remove
the QUIC certificate rejection in either browser. These results do not establish
WebTransport/application-protocol forwarding or arbitrary Internet QUIC coverage.

The launch argument `--origin-to-force-quic-on=host:port` relaxes the unknown-root
check but also forces the transport. `*` applies that force broadly. On both
tested browsers, a trusted TCP-only HTTPS fixture loaded normally but failed with
`ERR_QUIC_PROTOCOL_ERROR` under either force variant; see
`build/qa/quic-launch-flags-b63bb3cba436/results.json` (6/6). This is not a suitable
silent default for general browsing. `--webtransport-developer-mode` only feeds
the dedicated WebTransport verifier, not the ordinary HTTP/3 session pool.
`--ignore-certificate-errors-spki-list` bypasses ordinary verification on a
matching key; it does not implement this experiment's policy.

Sources: [QUIC session pool](https://github.com/chromium/chromium/blob/155.0.8059.80/net/quic/quic_session_pool.cc),
[WebTransport verifier](https://github.com/chromium/chromium/blob/155.0.8059.80/net/quic/dedicated_web_transport_http3_client.cc),
[SPKI exception](https://github.com/chromium/chromium/blob/155.0.8059.80/services/network/ignore_errors_cert_verifier.cc).

### Process-level browser CA Hook probe

The current probe is deliberately independent of individual MITM connections.
`browser_trust_probe.cpp` is a separate test-only x64 DLL, installed once in each
owned browser NetworkService process. Its controller supplies only process
identity, the exact ProxyLane CA fingerprint and a process-level enable/epoch/lease.
There is no authorized leaf/hostname/port list, UDP first-packet holding, or route
selection inside this Hook. Hostname and port in decision records are diagnostics.

The two detours wrap `Job::DoVerifyCertComplete` and
`Job::ShouldAllowUnknownRootForHost`. Normal validation must return OK with zero
certificate status, and the final certificate of the verified chain must match
ProxyLane CA by DER SHA-256. Only then can the scoped unknown-root exception apply.
The Hook never changes `is_issued_by_known_root`, ordinary verification results,
or the browser's global unknown-root host list. Hostname, expiry and signature
errors remain browser errors. Different valid leaves under the same authorized CA
are intentionally eligible; other private CAs are not.

Supported module hashes (Windows x64):

| Browser | Version | SHA-256 |
| --- | --- | --- |
| Chrome | 155.0.8059.80 | `7cc644c8a146d804ac175ff59277124cd63a4ccf15ea75f796e90f06e4dadfcd` |
| Edge | 155.0.4283.62 | `1906b766460da798672a9845e2772130674f7d3d866e8c63140ed88a1fe1c88d` |

Full file hashes and function prologues are checked before installation; unknown
builds are rejected. The observed certificate vector ABI is pointer/size/capacity.
The callback does bounded certificate inspection, with no file I/O or synchronous
controller requests. Decision logging is bounded to 128 small records. Detours
enlists existing threads during installation. Hooks stay loaded until process exit;
stopping the process-level exception does not terminate established connections.
TLS tickets, session storage and 0-RTT are disabled in the test server so reconnects
cannot skip the certificate path under test.

`quic_hook_probe.py` tests CA acceptance, disabled authorization, module/root hash
mismatch, another already-trusted private CA, an untrusted same-name CA, expired
and wrong-host leaves. It also tests existing h3 transfer after disabling the
exception, and rejection of a new handshake. The other trusted root is the existing
local mitmproxy CA; neither CA trust nor browser policies are modified. Local CA
keys are never logged; temporary leaf keys and the copied protected CA are removed
in `finally`.

`quic_late_hook_probe.py` starts browser HTTPS traffic before loading the Hook DLL:

1. Two concurrent 4 MiB HTTPS/TCP downloads run while the process-level Hook is
   installed. Their connection IDs must stay unchanged and SHA-256 must match.
2. A fresh local origin then discovers HTTP/3 via normal Alt-Svc and passes a
   64 KiB binary POST echo through Rust MITM -> shipping Hook -> SOCKS5 UDP domain
   route -> independent aioquic origin.
3. The test kills only its owned NetworkService child and waits for a new PID.
   The new process must not contain the Hook DLL. An unhooked control origin must
   produce zero h3 requests, with certificate refusal checked in NetLog.
4. During two new HTTPS downloads, the controller installs the Hook in that new
   process. Another fresh origin must again succeed over h3. This separate port
   avoids Chromium's cached failed Alt-Svc decision without clearing caches.

The deliberate NetworkService restart inherently destroys its old connections;
that is distinct from the no-disruption assertion during Hook installation.
Existing-connection integrity coverage here is HTTPS/TCP. An attempted public
QUIC baseline negotiated only HTTP/2 (or timed out), so this test does not claim
pre-existing public QUIC coverage. Repeated busy-browser runs are bounded functional
checks, not proof of safety for every possible thread interleaving or browser build.

No trust-relaxing, force-QUIC, SPKI exception or sandbox-disabling launch flags are
used. Isolated profiles, headless/CDP, NetLog and local test-name mapping are used
for automation. Edge relaunch ownership is checked by parent PID and exact profile.
Only test-owned processes are terminated. The Hook does not require installation
at browser startup, but installation after a handshake has already verified its
certificate cannot repair that handshake. A new NetworkService needs reinstallation.

```powershell
python -m pip install --target build/quic-probe/python -r tests/quic-mitm/requirements-hook.txt
./scripts/build-quic-probe.ps1
./scripts/build-quic-hook-probe.ps1
python tests/e2e/quic_hook_probe.py
python tests/e2e/quic_late_hook_probe.py --rounds 3
```

All binaries are under `build/quic-probe`; evidence and isolated profiles are under
`build/qa/quic-hook-*` and `build/qa/quic-late-hook-*`. No GUI, shipping dependency,
production routing or `bin` modifications are made. Automatic browser classification,
process restart watching and production process-level control IPC remain integration
work; tests explicitly drive those events. Future classification should use process
identity and the exact module build, not UDP port 443 as proof of a browser.

Historical evidence `build/qa/quic-hook-68ecc44ca82c/results.json` (18/18) belongs
to the earlier per-leaf/host/port prototype. Those connection-specific restrictions
were subsequently removed at the user's request; they are not current behavior.

Current process-only results (2026-10-19):

* `build/qa/quic-late-hook-cdf5e4b163cc/results.json`: Chrome and Edge each passed
  three rounds, with twelve installations in running NetworkService processes.
  Twenty-four existing 4 MiB HTTPS/TCP downloads (96 MiB total) retained their
  connections and completed with the expected SHA-256. Twelve fresh HTTP/3
  connections passed a 64 KiB binary POST echo through MITM and the UDP route.
* Each NetworkService restart created a process without the test Hook; its fresh
  QUIC handshake failed certificate verification before reinstallation, then
  succeeded after reinstallation. Adjacent `verification.json` independently
  checks those six NetLog failures and confirms temporary keys and test browser
  processes were cleaned up.
* `build/qa/quic-hook-e233b953cda1/results.json`: all sixteen CA/authorization
  cases passed, including stopping authorization while an established h3
  connection continued and a new handshake was rejected.

Existing traffic during installation was HTTPS/TCP, not an existing public QUIC
connection. Public discovery attempts negotiated h2 or timed out, so that latter
case remains unverified. These repeated functional checks are not an exhaustive
thread-scheduling stress test or support for arbitrary browser versions.

Sources: [Chromium QUIC verifier](https://github.com/chromium/chromium/blob/155.0.8059.80/net/quic/crypto/proof_verifier_chromium.cc),
[verified certificate representation](https://github.com/chromium/chromium/blob/155.0.8059.80/net/cert/x509_certificate.h).

### Compatibility research (2026-10-19)

Evidence is under `build/qa/quic-hook-compat-research/`. This is read-only source,
PE and public-symbol research; the exact-build Hook has not been relaxed.

The source samples 120.0.6099.109, 130.0.6723.58, 140.0.7339.80,
150.0.7871.46, 155.0.8059.80 and main all retain both diagnostic anchors and the
unknown-root exception. However, `Job::verify_details_` moved from after the
callback member in 120 to the first member in 155. Function discovery alone does
not establish object-layout compatibility. Source similarity is not binary or
runtime compatibility testing of those older releases.

`locator-audit.json` independently rediscovers the completion candidates in both
installed DLLs using the two strings and PE unwind boundaries, then finds the
direct-call candidate preceding the unknown-root error. These match the earlier
manually audited addresses without feeding those addresses to the locator. The
targets and CRYPTO_BUFFER data/length helpers are not named PE exports. This
experiment does not yet prove complete control/data flow or chain layout and
explicitly reports `install_ready: false`.

Public-symbol HEAD/range requests succeeded for both currently installed builds.
Edge's PDB is 682,487,808 bytes; its TPI and IPI streams are each only 56 bytes
(headers, no type records). It cannot supply the required member layouts through
ordinary PDB type lookup. Chrome's HTTP object is gzip encoded, with stored size
1,072,075,708 bytes; its type coverage was not inspected. Neither full PDB was
downloaded. Symbol existence alone does not prove the required names are present.

Recommended next experiment: local, bounded semantic discovery of the completion
function and its unknown-root call, followed by independent evidence for every
verified-chain access. Diagnostic host/port/leaf parsing should be removed from
the minimal Hook to reduce ABI dependencies. A discovery descriptor must cover
function boundaries, calling convention, control flow and object/container/buffer
layout; a single byte pattern or readable pointer is insufficient. Use symbols
as development-time corroboration, not a required browser-time download.

Cache validated descriptors by exact module identity and revalidate live code
before attachment. The fingerprint identifies cached analysis rather than acting
as a permanently hand-written version whitelist. Keep discovery outside browser
callbacks; retain only bounded CA comparison and process-level enable checks in
the Hook. Unresolved/ambiguous/inlined targets or unknown layouts mean no Hook.
This preserves normal browser behavior but does not provide QUIC decryption.

The remaining hard work is layout derivation and a multi-release binary/runtime
matrix, including negative certificates, concurrent verification, late attachment,
process restart and existing traffic. Supporting recognizable implementation
families is realistic; arbitrary future Chromium internals are not a stable ABI.

References: [Windows debugging symbols](https://www.chromium.org/developers/how-tos/debugging-on-windows/),
[PDB type streams](https://llvm.org/docs/PDB/TpiStream.html),
[Chromium 120 verifier](https://github.com/chromium/chromium/blob/120.0.6099.109/net/quic/crypto/proof_verifier_chromium.cc).

### Original protocol and route probe

Prerequisites: Windows x64, VS 2019 C++ tools, Python 3.11+, existing built
`bin/ProxyLaneHook64.dll` and `bin/x64/Release/ProxyLaneHook.lib`, and an initialized
`%LOCALAPPDATA%/ProxyLane/ca.json`. Browser trust tests require that CA to already
be trusted by the current user. The runner does not install or remove it.

```powershell
# Install this toolchain separately; do not change the shipping build's default.
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc --profile minimal --no-self-update
python -m pip install --target build/quic-probe/python -r tests/quic-mitm/requirements.txt
./scripts/build-quic-probe.ps1
python tests/e2e/quic_mitm_probe.py --browsers
```

Binaries: `build/quic-probe/`. Each run writes logs, isolated browser profiles and
`results.json` below `build/qa/quic-mitm-<random>/`. The test uses a copy of the CA;
the copied protected private key and temporary origin private key are removed in
`finally`. Only test-owned processes are stopped. A forcibly terminated runner can
leave its run directory; do not share leftover private-key files.

## Route coverage

* Direct loopback baseline.
* Actual Hook -> NOPROXY UDP forwarding to a local interface.
* Actual Hook -> CUdpProxyTask -> SOCKS5 UDP with a numeric test address.
* The same route with remote DNS: `origin.quic.test` must appear in the SOCKS5
  domain header. This name is resolved only by the controlled SOCKS fixture.
* Explicitly untrusted client roots and unknown SNI are rejected.
* An untrusted origin must be rejected with an upstream certificate error.
* An unavailable SOCKS proxy must not silently send QUIC directly to the reachable
  local origin.

The native host injects **the test MITM worker**, so these tests prove its upstream
route compatibility. They do not yet implement transparent interception of every
browser's original UDP connection or transfer original browser PID metadata into
the Rust HTTP/3 records. Host logs preserve the injected worker PID, process birth
and socket generation. Production integration still needs explicit PRC route
identity at the Rust boundary.

## Why the UDP adapter exists

Quinn's default Windows I/O uses extended Winsock message APIs. A raw use of that
socket did not enter the shipping Hook's send path in the initial experiment.
Using ordinary datagram sends entered the route, but the return address was the
local PRC peer rather than Quinn's logical remote endpoint.

`route_socket.rs` gives Quinn one connected socket per upstream route. The Hook
redirects the connected socket to its PRC peer; the adapter reports the original
logical remote to Quinn. Connected UDP filters incoming peers. ECN, GSO, GRO,
source-IP selection and migration are deliberately excluded. A production
in-process adapter should use bounded PRC datagram queues instead of injecting
its own worker. Do not silently replace this adapter with direct UDP sockets.

## Browser experiment

The test's TCP HTTPS bootstrap advertises `Alt-Svc: h3` on the same port and runs
repeated fetches. This tests normal h3 discovery with current-user CA trust.
Chrome and Edge are also tested with `--origin-to-force-quic-on` for this single
test origin. Chromium uses this setting in its unknown-root exceptions, so its
success is **not** evidence that a normal browser accepts a private CA for QUIC.
Neither case uses `--ignore-certificate-errors`.

Firefox uses an isolated profile with HTTP/3 enabled and Windows enterprise roots
enabled. The second Firefox case sets
`network.http.http3.disable_when_third_party_roots_found=false` in that profile.
This changes HTTP/3 policy, not certificate verification. See the
[Mozilla explanation](https://bugzilla.mozilla.org/show_bug.cgi?id=1985341) and
[Chromium force-QUIC root exception construction](https://github.com/chromium/chromium/blob/main/net/quic/quic_session_pool.cc).
Test host mapping is profile/command scoped; the system hosts file and
the user's browser profiles are untouched. The bundled Windows curl 8.7.1 does
not advertise HTTP/3 support and is not used as an h3 client.

## Deliberate limits

This is a fixed, explicitly configured test origin with strict SNI, QUIC v1, h3,
no 0-RTT and no connection migration. Bodies are buffered with an 8 MiB cap per
direction, at most eight active body-processing tasks globally, eight connections,
32 bidirectional streams per connection, 16 KiB header sections, transport flow
control and deadlines. It is **not** production streaming or the existing payload
cache. Trailers are rejected; ECH, client certificates, WebTransport, HTTP Datagrams,
DoQ, QUIC v2 and GUI stop-monitoring behavior are outside this experiment.

The independent peer is pinned to aioquic 1.7.0 in an isolated directory. The
previously installed aioquic 1.0.0 did not report request completion when an h3
GREASE frame carried FIN. Using 1.7.0 passed with h3's GREASE enabled; no such
workaround is applied to the production application.
