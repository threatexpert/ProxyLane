"""Register a disposable full-trust test package; verify Explorer replacement and real proxy traffic.

Requires Windows 10+ with developer mode already enabled. Does not change developer
mode, install a certificate, or stop existing applications. Removes only its own package.
"""
import argparse
import concurrent.futures
import ctypes
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import threading
import time
import uuid
import zlib

import psutil
from LogonChildE2ETests import serve
from ManagedStartupE2ETests import stop_tree
from ExitWarningE2ETests import USER, CALLBACK, windows, text as window_text, wait_for


def launcher_log(owner):
    main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'launcher GUI')
    edits = []
    @CALLBACK
    def visit(window, _):
        if USER.GetDlgItem(window, 1043):
            edits.append(USER.GetDlgItem(window, 1000))
        return True
    USER.EnumChildWindows(main, visit, 0)
    assert len(edits) == 1 and edits[0], edits
    def completed_log():
        value = window_text(edits[0])
        return value if any(marker in value for marker in ('[Launch]', '[启动]', 'AppsFolder activation:')) else None
    return wait_for(completed_log, 'AppsFolder launch result')


def transact(pipe_name, action, flag=0, payload=b''):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    for name in ('ReadFile', 'WriteFile'):
        getattr(kernel, name).argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    deadline = time.monotonic() + 5
    while True:
        handle = kernel.CreateFileW(pipe_name, 0x80000102, 0, None, 3, 0x100000, None)
        if handle != ctypes.c_void_p(-1).value:
            break
        error = ctypes.get_last_error()
        assert error == 231 and time.monotonic() < deadline, ctypes.WinError(error)
        kernel.WaitNamedPipeW(pipe_name, 100)
    def write(data):
        count = ctypes.c_uint32()
        assert kernel.WriteFile(handle, ctypes.create_string_buffer(data), len(data), ctypes.byref(count), None)
        assert count.value == len(data)
    def read(size):
        data = b''
        while len(data) < size:
            buffer = ctypes.create_string_buffer(size - len(data))
            count = ctypes.c_uint32()
            assert kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None) and count.value
            data += buffer.raw[:count.value]
        return data
    try:
        write(struct.pack('<BBI', action, flag, len(payload)))
        if payload:
            write(payload)
        reply, status, length = struct.unpack('<BBI', read(6))
        assert reply == 0 and status == 1
        return read(length)
    finally:
        kernel.CloseHandle(handle)


def protocol_cases(root, package, family, observations):
    for filename in ('app.started', 'app.go', 'app.done', 'child32.done', 'child64.done', 'app.activations'):
        (package / filename).unlink(missing_ok=True)
    previous = set(os.listdir('\\\\.\\pipe\\'))
    # Keep the host alive with an unpackaged image; the registered app itself
    # could otherwise be reused by ActivateApplication instead of started anew.
    shutil.copy2(package / 'probe64.exe', root / 'hold.exe')
    owner = subprocess.Popen([str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'AppsFolderTest', '--run',
                              str(root / 'hold.exe'), '--', 'hold'], cwd=root,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline = time.monotonic() + 15
        names = []
        while not names and time.monotonic() < deadline:
            names = [name for name in set(os.listdir('\\\\.\\pipe\\')) - previous if name.startswith('PRCPipeName')]
            time.sleep(.05)
        assert len(names) == 1, names
        pipe = '\\\\.\\pipe\\' + names[0]
        startup = transact(pipe, 1, 3)
        version, host_pid, host_time = struct.unpack('<IIQ', startup[-536:-520])
        assert version == 1 and host_pid == owner.pid
        host_path = startup[-520:].decode('utf-16le').split('\0')[0]
        assert Path(host_path) == root / 'ProxyLane64.exe'
        # Old startup layouts remain available to flag 0 and flag 2 clients.
        assert len(transact(pipe, 1, 0)) == len(startup) - 540
        assert len(transact(pipe, 1, 2)) == len(startup) - 536
        def request(aumid, request_id=None):
            request_id = request_id or '{' + str(uuid.uuid4()) + '}'
            return (request_id.encode('utf-16le').ljust(80, b'\0') + aumid.encode('utf-16le').ljust(512, b'\0')
                    + struct.pack('<IQIQQ', host_pid, host_time, os.getpid(), 1,
                                  time.time_ns() // 100 + 116444736000000000))
        before = len(observations)
        payload = request(family + '!App')
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            jobs = [pool.submit(transact, pipe, 19, 0, payload) for _ in range(2)]
            results = [struct.unpack('<III', job.result(timeout=25)) for job in jobs]
        final = struct.unpack('<III', transact(pipe, 19, 0, payload))
        assert final[0] == 0 and final[1] and final[2] == 0, (results, final)
        assert all(result == final or result[0] == 997 for result in results), results
        deadline = time.monotonic() + 10
        while not (package / 'app.started').exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert len((package / 'app.activations').read_text().splitlines()) == 1
        altered = payload[:80] + (family + '!Missing').encode('utf-16le').ljust(512, b'\0') + payload[592:]
        assert struct.unpack('<III', transact(pipe, 19, 0, altered))[0] == 87
        invalid = struct.unpack('<III', transact(pipe, 19, 0, request(family + '!Missing')))
        assert invalid[0] != 0 and invalid[1] == 0, invalid
        for executable in ('ProxyLane.exe', 'ProxyLane64.exe'):
            # Both command modes must terminate without UI or architecture forwarding.
            malformed = subprocess.run([str(root / executable), '--internal-launch-app', 'bad'], timeout=10)
            assert malformed.returncode == 87
            helper = subprocess.run([str(root / executable), '--internal-launch-app', pipe,
                '{' + str(uuid.uuid4()) + '}', family + '!Missing', str(host_pid), str(host_time), str(os.getpid()), '1'], timeout=20)
            assert helper.returncode == invalid[0], (executable, helper.returncode, invalid)
        assert len((package / 'app.activations').read_text().splitlines()) == 1
        (package / 'app.go').write_text('go')
        assert '!Missing' in launcher_log(owner), 'Activation failures must remain in the run log'
        deadline = time.monotonic() + 30
        while not (package / 'app.done').exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert (package / 'app.done').read_text().startswith('PASS')
        assert observations[before:] == [('203.0.113.10', 39093)] * 3
        print('PASS startup layout compatibility, duplicate activation suppression, invalid AUMID, x86/x64 helper exits', flush=True)
    finally:
        stop_tree(owner)


def powershell(script):
    return subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                    "$ErrorActionPreference='Stop';" + script], text=True).strip()


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def png(path, size):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    pixels = (b'\0' + b'\x40\x80\xc0\xff' * size) * size
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
                     + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--language', choices=('en-US', 'zh-CN'), default='en-US')
    parser.add_argument('--case', choices=('shell', 'bare', 'newconsole', 'token'), help='Run one launcher variant on x86 and x64')
    args = parser.parse_args()
    root = Path('build/qa/app-launcher-' + uuid.uuid4().hex[:8]).resolve()
    root.mkdir(parents=True)
    package = root / 'package'
    package.mkdir()
    name = 'ProxyLane.AppLauncherTest.' + uuid.uuid4().hex[:12]
    print('Results:', root, flush=True)
    for filename in ('ProxyLane.exe', 'ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
        shutil.copy2(args.bin / filename, root / filename)
    # Optional transport libraries are kept beside the disposable host.
    for dll in Path('bin').glob('ProxyLane*.dll'):
        if not (root / dll.name).exists():
            shutil.copy2(dll, root / dll.name)
    source = Path(__file__).parent / 'e2e/apps_folder_probe.cs'
    csc = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework/v4.0.30319/csc.exe'
    for bits, platform in ((32, 'x86'), (64, 'x64')):
        subprocess.run([str(csc), '/nologo', '/target:exe', '/platform:' + platform,
                        '/out:' + str(package / ('probe%d.exe' % bits)), str(source.resolve())], check=True)
    png(package / 'logo150.png', 150)
    png(package / 'logo44.png', 44)
    manifest = package / 'AppxManifest.xml'
    manifest.write_text('''<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap rescap">
 <Identity Name="%s" Publisher="CN=ProxyLaneTest" Version="1.0.0.0" ProcessorArchitecture="x64"/>
 <Properties><DisplayName>ProxyLane disposable launch test</DisplayName><PublisherDisplayName>ProxyLaneTest</PublisherDisplayName><Logo>logo44.png</Logo></Properties>
 <Resources><Resource Language="en-us"/></Resources>
 <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19045.0"/></Dependencies>
 <Applications><Application Id="App" Executable="probe64.exe" EntryPoint="Windows.FullTrustApplication">
 <uap:VisualElements DisplayName="ProxyLane disposable launch test" Description="Disposable E2E fixture" BackgroundColor="transparent" Square150x150Logo="logo150.png" Square44x44Logo="logo44.png"/>
 </Application></Applications><Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>''' % name, encoding='utf-8')
    observations = []
    registered = False
    owner = None
    try:
        powershell('Add-AppxPackage -Register ' + literal(manifest))
        registered = True
        family = powershell('(Get-AppxPackage -Name ' + literal(name) + ').PackageFamilyName')
        assert family, 'package family unavailable'
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            threading.Thread(target=serve, args=(listener, observations), daemon=True).start()
            (root / 'portable.flag').touch()
            (root / 'ProxyLane.ini').write_text('''[options]
lastselected=AppsFolderTest
language=%s
[proxy_AppsFolderTest]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=1
dnsOpt=1
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=%d
Transport=PLAIN
''' % (args.language, listener.getsockname()[1]), encoding='utf-8')
            cases = [(32, args.case), (64, args.case)] if args.case else [
                (32, 'suspended'), (64, 'normal'), (64, 'close'),
                (32, 'shell'), (64, 'shell'), (32, 'bare'), (64, 'bare'),
                (32, 'newconsole'), (64, 'newconsole'), (32, 'token'), (64, 'token')]
            for bits, mode in cases:
                for filename in ('app.started', 'app.go', 'app.done', 'child32.done', 'child64.done'):
                    (package / filename).unlink(missing_ok=True)
                report = root / ('installer-%d-%s.txt' % (bits, mode))
                before = len(observations)
                owner = subprocess.Popen([str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'AppsFolderTest',
                    '--run', str(package / ('probe%d.exe' % bits)), '--', 'installer', family + '!App', str(report), mode],
                    cwd=root, creationflags=subprocess.CREATE_NO_WINDOW)
                deadline = time.monotonic() + 65
                while not report.exists() and time.monotonic() < deadline:
                    if owner.poll() is not None:
                        raise RuntimeError('Host exited: %s' % owner.returncode)
                    time.sleep(.1)
                assert report.exists(), 'installer timed out: ' + str(list(package.glob('*.done')))
                text = report.read_text(encoding='utf-8-sig')
                logs = launcher_log(owner)
                (root / ('launcher-%d-%s.log' % (bits, mode))).write_text(logs, encoding='utf-8')
                assert text.startswith('PASS'), text
                marker = '[启动]' if args.language == 'zh-CN' else '[Launch]'
                lines = [line for line in logs.splitlines() if marker in line]
                assert len(lines) == 1 and ('probe%d.exe (' % bits) in lines[0] and 'probe64.exe (' in lines[0], logs
                assert 'AppsFolder helper: created;' not in logs and 'AppsFolder activation:' not in logs, logs
                for filename in ('app.done', 'child32.done', 'child64.done'):
                    assert (package / filename).read_text(encoding='utf-8-sig').startswith('PASS'), filename
                assert observations[before:] == [('203.0.113.10', 39093)] * 3, observations[before:]
                print(text + '; package and x86/x64 children SOCKS PING/PONG PASS', flush=True)
                stop_tree(owner)
                owner = None
                time.sleep(.5)
            if not args.case:
                protocol_cases(root, package, family, observations)
        print('PASS all AppsFolder integration cases', flush=True)
    finally:
        if owner is not None:
            stop_tree(owner)
        # Broker-created package processes need not be descendants of the host.
        for proc in psutil.process_iter(['exe']):
            try:
                if proc.info['exe'] and Path(proc.info['exe']).parent == package:
                    proc.terminate()
                    proc.wait(timeout=5)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if registered:
            powershell('Get-AppxPackage -Name ' + literal(name) + ' | Remove-AppxPackage')


if __name__ == '__main__':
    main()
