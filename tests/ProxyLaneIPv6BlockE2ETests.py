import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time


CLIENT_CODE = r'''
import socket
import sys

def connect_error(address):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        return sock.connect_ex((address, 9))
    finally:
        sock.close()

external = connect_error("2001:db8::1")
loopback = connect_error("::1")
mapped = connect_error("::ffff:127.0.0.1")
result = "PASS" if external == 10047 and loopback != 10047 and mapped != 10047 else (
    f"FAIL external={external} loopback={loopback} mapped={mapped}")
with open(sys.argv[1], "w", encoding="utf-8") as output:
    output.write(result)
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default=os.path.join(
        os.path.dirname(__file__), "..", "bin"))
    args = parser.parse_args()
    binary_dir = os.path.abspath(args.bin)

    with tempfile.TemporaryDirectory(prefix="ProxyLaneIPv6BlockE2E-",
                                     ignore_cleanup_errors=True) as temp:
        for name in ("ProxyLane64.exe", "ProxyLaneHook32.dll",
                     "ProxyLaneHook64.dll"):
            shutil.copy2(os.path.join(binary_dir, name),
                         os.path.join(temp, name))

        profile_text = """[options]
lastselected=IPv6BlockTest
HookLanIP=1
DisableLLMNR=1
DisableMDNS=1
language=en-US

[proxy_IPv6BlockTest]
HookChildProcess=0
HookTCP=0
HookUDP=0
BlockUDP=0
BlockIPv6=1
dnsOpt=0
RedirectPrivateDNS=0
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=0
Type=SOCKS5
Host=127.0.0.1
Port=7799
User=
Pass=
Transport=PLAIN
PSK=
"""
        with open(os.path.join(temp, "ProxyLane.ini"), "w",
                  encoding="utf-8") as profile:
            profile.write(profile_text)

        result_path = os.path.join(temp, "result.txt")
        proxylane = subprocess.Popen([
            os.path.join(temp, "ProxyLane64.exe"),
            "--auto", "--profile", "IPv6BlockTest",
            "--run", sys.executable, "--", "-c", CLIENT_CODE, result_path
        ], cwd=temp)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not os.path.exists(result_path):
                if proxylane.poll() is not None:
                    raise RuntimeError(
                        f"ProxyLane exited early with {proxylane.returncode}")
                time.sleep(0.1)
            if not os.path.exists(result_path):
                raise TimeoutError("IPv6 block probe timed out")
            with open(result_path, encoding="utf-8") as result_file:
                result = result_file.read()
            if result != "PASS":
                raise RuntimeError(result)
            print("PASS: injected IPv6 blocking and loopback exceptions")
        finally:
            proxylane.terminate()
            try:
                proxylane.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxylane.kill()


if __name__ == "__main__":
    main()
