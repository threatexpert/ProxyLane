"""Shipping Hook lifecycle: first-injection snapshot, local install, no revocation.
Isolated browser profiles and local origins; no trust-store or browser flags changed.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import tempfile
import psutil
import quic_mitm_probe as probe
from quic_live_route_probe import Host, RUNTIME
from quic_late_hook_probe import SlowHTTPS, eval_async, recording
from quic_hook_probe import BROWSERS, adopt_browser
from quic_hook_control import network_process
from quic_ssl_policy_probe import attach
from aioquic.quic.events import ConnectionTerminated

async def run():
    probe.isolate()
    with tempfile.TemporaryDirectory(dir=RUNTIME) as tmp:
        work=Path(tmp);processes=probe.Processes(work);results=[];servers=[]
        pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane';origin=SlowHTTPS(work,pki)
        ip=next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
        config=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
        config.load_cert_chain(str(origin.cert),str(origin.key))
        negative=work/'untrusted';negative.mkdir();probe.origin_pki(negative)
        badconfig=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
        badconfig.load_cert_chain(str(negative/'origin-cert.pem'),str(negative/'origin-key.pem'))
        class TracedPeer(probe.Peer):
            def quic_event_received(self,event):
                if isinstance(event,ConnectionTerminated):
                    self.events.append({'event':'terminated','error_code':event.error_code,'reason':event.reason_phrase})
                super().quic_event_received(event)
        async def fixture(quic_config=config):
            port=probe.port();events=[]
            async def bootstrap(reader,writer):
                try:
                    head=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
                    download=b'/download' in head.split(b'\r\n')[0]
                    body=b'x'*1048576 if download else b'<html><title>QUIC transparent origin</title></html>'
                    writer.write(f'HTTP/1.1 200 OK\r\nAlt-Svc: h3=":{port}"; ma=60\r\nContent-Length: {len(body)}\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'.encode())
                    for offset in range(0,len(body),16384):
                        writer.write(body[offset:offset+16384]);await writer.drain()
                        if download:await asyncio.sleep(.08)
                except (TimeoutError,ConnectionError):pass
                finally:writer.close()
            udp=await probe.serve('0.0.0.0',port,configuration=quic_config,create_protocol=lambda *a,**k:TracedPeer(*a,origin=True,events=events,**k))
            tcp=await asyncio.start_server(bootstrap,'0.0.0.0',port,ssl=origin.context)
            servers.append((udp,tcp));return port,events
        async def warm(cdp,port,label):
            await asyncio.to_thread(cdp.call,'Page.navigate',{'url':f'https://{probe.NAME}:{port}/'})
            await asyncio.sleep(.7)
            for i in range(6):
                await eval_async(cdp,f"fetch('/{label}?i={i}',{{cache:'no-store'}}).then(r=>r.text())")
                await asyncio.sleep(.4)
        async def installed(work,name,count,pid):
            for _ in range(60):
                text=(work/(name+'.log')).read_bytes()
                if text.count(b'QUIC browser compatibility installed')>=count:return
                if b'QUIC browser compatibility unavailable' in text:raise AssertionError(text.decode(errors='replace'))
                await asyncio.sleep(.5)
            raise AssertionError('local Hook did not install: '+text.decode(errors='replace'))
        try:
            for name,path in BROWSERS.items():
                if os.environ.get("QUIC_TEST_BROWSER") not in (None,name):continue
                host=Host(work,name);second=None;browser=None;cdp=None
                try:
                    debug=probe.port();profile=work/name;netlog=work/(name+'-netlog.json')
                    args=[str(path),'--headless=new','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--no-proxy-server',
                        '--user-data-dir='+str(profile),'--remote-debugging-port='+str(debug),'--host-resolver-rules=MAP quic-probe.test '+ip,'--log-net-log='+str(netlog),'about:blank']
                    assert not any('ignore-certificate' in a or 'force-quic' in a or 'no-sandbox' in a for a in args)
                    browser=processes.start(name+"-browser",args);cdp=recording(await attach(debug));await asyncio.sleep(.5)
                    browser=adopt_browser(browser,profile,processes)
                    port,_=await fixture();await warm(cdp,port,'baseline')
                    network=network_process(browser)
                    assert not (await asyncio.to_thread(host.call,type='quic_injection_policy'))['enabled']
                    result=await asyncio.to_thread(host.call,type='attach',pid=network);assert result['result']==0xff01,result
                    for _ in range(60):
                        if f'HOOK pid={network} error=0'.encode() in (work/(name+'.log')).read_bytes():break
                        await asyncio.sleep(.1)
                    else:raise AssertionError('ordinary Hook initialization incomplete')
                    await asyncio.to_thread(host.call,type='quic_injection_policy',enabled=True)
                    await asyncio.to_thread(host.call,type='monitor_start',decrypt=False,quic=True)
                    # Re-inject/rebind after option changes must not change the snapshot.
                    result=await asyncio.to_thread(host.call,type='attach',pid=network);assert result['result']==0xff01,result
                    port,_=await fixture();start=len(cdp.records);await warm(cdp,port,'snapshot-off')
                    assert not any(r['protocol']=='h3' for r in cdp.records[start:]),cdp.records[start:]
                    assert b'QUIC browser compatibility installed' not in (work/(name+'.log')).read_bytes()
                    print(name,'snapshot-off remains off after toggle/rebind PASS',flush=True)
                    # A new target process takes the now-enabled snapshot, before monitoring.
                    await asyncio.to_thread(host.call,type='monitor_stop')
                    psutil.Process(network).kill();await asyncio.sleep(.8)
                    port,_=await fixture();await asyncio.to_thread(cdp.call,'Page.navigate',{'url':f'https://{probe.NAME}:{port}/'})
                    await asyncio.sleep(.6);network=network_process(browser)
                    await asyncio.to_thread(cdp.call,'Runtime.evaluate',{'expression':"window.download=fetch('/download').then(r=>r.arrayBuffer()).then(b=>b.byteLength)"})
                    await asyncio.sleep(.2)
                    result=await asyncio.to_thread(host.call,type='attach',pid=network);assert result['result']==0xff01,result
                    trigger,_=await fixture()
                    for i in range(3):
                        await eval_async(cdp,f"fetch('https://{probe.NAME}:{trigger}/eligible-udp?i={i}',{{mode:'no-cors',cache:'no-store'}}).then(()=>true)")
                        await asyncio.sleep(.4)
                    await installed(work,name,1,network)
                    assert await eval_async(cdp,'window.download')==1048576
                    # Compatibility was installed even though monitoring was stopped.
                    assert not (await asyncio.to_thread(host.call,type='monitor_status'))['monitoring']
                    await asyncio.to_thread(host.call,type='monitor_start',decrypt=False,quic=True)
                    port,_=await fixture();await warm(cdp,port,'live')
                    value=await eval_async(cdp,"(async()=>{let b=new Uint8Array(65536);for(let i=0;i<b.length;i++)b[i]=i%251;let r=await fetch('/live-binary',{method:'POST',body:b});let a=new Uint8Array(await r.arrayBuffer());return a.length===b.length&&a.every((v,i)=>v===b[i])})()")
                    assert value is True,cdp.records[-5:]
                    records=await asyncio.to_thread(host.call,type='poll',limit=512)
                    exchanges=[r for r in records.get('records',[]) if r.get('protocol')=='h3' and r.get('type')=='exchange']
                    assert exchanges and all(r['connection']['pid']==network for r in exchanges),records
                    assert cdp.records[-1]['protocol']=='h3',cdp.records[-1]
                    await asyncio.to_thread(host.call,type='monitor_stop')
                    await asyncio.to_thread(host.call,type='quic_injection_policy',enabled=False)
                    snapshot=await asyncio.to_thread(host.call,type='poll',limit=512)
                    await eval_async(cdp,"fetch('/after-monitor-stop',{cache:'no-store'}).then(r=>r.text())")
                    assert cdp.records[-1]['protocol']=='h3',cdp.records[-1]
                    await asyncio.sleep(.2)
                    assert (await asyncio.to_thread(host.call,type='poll',limit=512))['next']==snapshot['next']
                    # New non-MITM QUIC with a trusted local CA still works after stop.
                    port,_=await fixture();await warm(cdp,port,'retained')
                    assert cdp.records[-1]['protocol']=='h3',cdp.records[-1]
                    # Ordinary chain validation still rejects an untrusted QUIC CA.
                    badport,badevents=await fixture(badconfig);start=len(cdp.records)
                    await warm(cdp,badport,'untrusted')
                    assert not any(r['protocol']=='h3' for r in cdp.records[start:]),cdp.records[start:]
                    assert not any(e.get('event')=='request' for e in badevents),badevents
                    rejected=[e for e in badevents if e.get('event')=='terminated' and 0x100<=e.get('error_code',0)<0x200]
                    assert rejected,('no client TLS alert from untrusted QUIC origin',badevents)
                    # A second PRC with the option OFF can rebind, but cannot revoke it.
                    second=Host(work,name+'-second')
                    result=await asyncio.to_thread(second.call,type='attach',pid=network);assert result['result']==0xff01,result
                    host.close()
                    port,_=await fixture();await warm(cdp,port,'original-host-exited')
                    assert cdp.records[-1]['protocol']=='h3',cdp.records[-1]
                    # Restarting the target now snapshots OFF from the new PRC.
                    psutil.Process(network).kill();await asyncio.sleep(.8)
                    port,_=await fixture();await asyncio.to_thread(cdp.call,'Page.navigate',{'url':f'https://{probe.NAME}:{port}/'})
                    await asyncio.sleep(.6);replacement=network_process(browser);assert replacement!=network
                    result=await asyncio.to_thread(second.call,type='attach',pid=replacement);assert result['result']==0xff01,result
                    port,_=await fixture();start=len(cdp.records);await warm(cdp,port,'restarted-off')
                    assert not any(r['protocol']=='h3' for r in cdp.records[start:]),cdp.records[start:]
                    results.append(dict(browser=name,version=(await asyncio.to_thread(cdp.call,"Browser.getVersion"))["product"],untrusted_port=badport,untrusted_certificate_errors=rejected,pid=network,http3=True,echo_bytes=65536,snapshot_off_immutable=True,install_while_monitoring_off=True,existing_tcp_download=1048576,stop_preserves_connection=True,stop_preserves_policy=True,untrusted_ca_rejected=True,second_instance_off_does_not_revoke=True,host_exit_preserves_policy=True,restarted_target_reads_off=True,records=records,network=cdp.records))
                    print(name,'PASS',flush=True)
                finally:
                    if cdp:cdp.ws.close()
                    if browser:processes.stop(browser)
                    if second:second.close()
                    host.close()
                    (RUNTIME/(name+'-host.log')).write_bytes((work/(name+'.log')).read_bytes())
                    if netlog.exists():
                        (RUNTIME/(name+'-netlog.json')).write_bytes(netlog.read_bytes())
            (RUNTIME/'browser-results.json').write_text(json.dumps(results,indent=2),encoding='utf8')
        finally:
            processes.close()
            for udp,tcp in servers:udp.close();tcp.close();await tcp.wait_closed()

if __name__=='__main__':asyncio.run(run())
