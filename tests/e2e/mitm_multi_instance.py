"""Called by mitm_e2e.py --multi-instance while its unique CA is installed.

Real injected Schannel curl, without -k/--ssl-no-revoke/best-effort flags.
Only test-owned child processes and this run's exact CRL URL cache are touched.
"""
import concurrent.futures
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


def run(binary_directory, env, work, proxy, origin, authority):
    saved_ca = (work / "pki" / "ca.json").read_bytes()
    preferred = int(env["PROXYLANE_MITM_CRL_PORT"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for label, arch_a, arch_b, occupy in [("64-64", "64", "64", False),
                                           ("32-64-occupied", "32", "64", True)]:
        case = work / ("multi-" + label)
        case.mkdir()
        processes = []
        logs = []
        blocker = None
        try:
            if occupy:
                blocker = socket.socket()
                blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                blocker.bind(("127.0.0.1", preferred)); blocker.listen()
            def start_host(name, arch, gate_name):
                output = case / (name + ".out")
                errors = case / (name + ".err")
                out, err = output.open("wb"), errors.open("wb")
                logs.extend([out, err])
                host = binary_directory / "mitm_host64.exe"
                curl = Path(os.environ["WINDIR"]) / ("SysWOW64" if arch == "32" else "System32") / "curl.exe"
                port = origin.server_address[1]
                child = [str(curl), "--silent", "--show-error", "--verbose", "--noproxy", "*", "--max-time", "20",
                         "--resolve", f"mitm.test:{port}:203.0.113.10", "--write-out", "%{certs}",
                         "--output", str(case / (name + ".body")), f"https://mitm.test:{port}/probe"]
                case_env = dict(env, PROXYLANE_TEST_PROTOCOL="1", PROXYLANE_TEST_NO_MONITOR="1", PROXYLANE_TEST_CRL="1")
                case_env[gate_name] = str(case / (name + ".go"))
                process = subprocess.Popen([str(host), str(proxy.server_address[1]), "SOCKS5", subprocess.list2cmdline(child)],
                                           env=case_env, stdout=out, stderr=err)
                processes.append(process)
                return process, output, errors
            # Start together to exercise preferred-port election by bind itself.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                fa = pool.submit(start_host, "a", arch_a, "PROXYLANE_TEST_HOLD_GATE")
                fb = pool.submit(start_host, "b", arch_b, "PROXYLANE_TEST_REPEAT_GATE")
                a, aout, aerr = fa.result()
                b, bout, berr = fb.result()
            deadline = time.monotonic() + 45
            while not all(b"CRL_TEST_WAITING" in path.read_bytes() for path in (aerr, berr)):
                assert a.poll() is None and b.poll() is None, (a.returncode, b.returncode, aerr.read_text(errors="replace"), berr.read_text(errors="replace"))
                assert time.monotonic() < deadline, "hosts did not complete their first curl requests"
                time.sleep(0.05)
            urls = [re.search(rb"CRL: (http://[^\s]+)", path.read_bytes()).group(1).decode() for path in (aerr, berr)]
            ports = [int(url.split(":")[2].split("/")[0]) for url in urls]
            assert ports[0] != ports[1], ports
            assert (preferred not in ports) if occupy else (preferred in ports)
            # Check the actual client-facing certificates, not just a status string.
            for output, url in zip((aout, bout), urls):
                pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output.read_bytes(), re.S).group(0)
                cert = x509.load_pem_x509_certificate(pem)
                assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
                assert [name.value for point in points for name in point.full_name] == [url]
                authority.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            def check_crl(url):
                with opener.open(url, timeout=5) as response:
                    crl = x509.load_der_x509_crl(response.read())
                authority.public_key().verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm))
                assert crl.issuer == authority.subject and len(crl) == 0
            for url in urls: check_crl(url)
            for name in ("a", "b"): assert (case / (name + ".body")).read_bytes() == b"ProxyLane MITM verified\n"
            # A's monitoring is off and TLS enable has been turned off by the
            # host, yet its CRL stays available until actual process exit.
            (case / "a.go").touch()
            assert a.wait(timeout=15) == 0
            check_crl(urls[1])
            with socket.socket() as probe:
                assert probe.connect_ex(("127.0.0.1", ports[0])) != 0, "exited instance retained its listener"
            # Clear ONLY the test CA's B URL, never the user's global CRL cache.
            subprocess.run(["certutil", "-urlcache", urls[1], "delete"], capture_output=True, timeout=10)
            (case / "b.go").touch()
            assert b.wait(timeout=35) == 0, berr.read_text(errors="replace")
            assert len(re.findall(rb"CHILD pid=", berr.read_bytes())) == 2
            assert len(re.findall(rb"-----BEGIN CERTIFICATE-----", bout.read_bytes())) >= 2
            assert b"CRYPT_E_REVOCATION_OFFLINE" not in berr.read_bytes()
            assert b"SEC_E_UNTRUSTED_ROOT" not in berr.read_bytes()
            assert (work / "pki" / "ca.json").read_bytes() == saved_ca
            assert not list((work / "protocol-cache").glob("run-*"))
            print(f"multi-instance {label} PASS (ports {ports}, curl revocation enabled, survivor reconnects)", flush=True)
        finally:
            # All handles here were created by this test; no user processes.
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=10)
            for log in logs: log.close()
            if blocker: blocker.close()
