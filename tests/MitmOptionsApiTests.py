"""Exercise release DLL options and monitor restart, without sockets or CA trust."""
import ctypes as c
import json
import os
import struct
from pathlib import Path
import uuid

root=Path(__file__).resolve().parents[1]
work=root/'build'/'qa'/('mitm-options-'+uuid.uuid4().hex[:12])
work.mkdir(parents=True)
os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=str(work/'cache')
dll=c.CDLL(str(root/'bin'/'ProxyLaneMitm64.dll'))
dll.plm_protocol.argtypes=[c.c_char_p,c.c_void_p,c.c_size_t]
dll.plm_protocol.restype=c.c_int
dll.plm_stream_open.argtypes=[c.c_char_p,c.c_char_p]
dll.plm_stream_open.restype=c.c_void_p
dll.plm_stream_io.argtypes=[c.c_void_p,c.c_uint,c.c_uint,c.c_void_p,c.c_size_t]
dll.plm_stream_io.restype=None

def query(value, fail=False):
    output=c.create_string_buffer(65536)
    n=dll.plm_protocol(json.dumps(value).encode(),output,len(output))
    if n>len(output):
        assert n<=8*1024*1024
        output=c.create_string_buffer(n)
        n=dll.plm_protocol(json.dumps(value).encode(),output,len(output))
    if fail:
        assert n<0,output.value
        return output.value.decode()
    assert 0<n<=len(output),output.value
    return json.loads(output.value)

handles=[]
def open_stream(number):
    metadata=dict(connection_id=number,pid=0,process_create_time=0,socket=number,
                  socket_generation=number,destination='127.0.0.1',port=22)
    h=dll.plm_stream_open(b'test',json.dumps(metadata).encode())
    if h:handles.append(h)
    return h

try:
    assert not open_stream(0), 'monitoring must default to off'
    assert query({'type':'stats'})['type']=='inactive', 'disabled capture must not create a cache'
    original=query({'type':'mitm_options'})['settings']
    # Retain recording settings added to the options schema.
    changed=dict(original,entry_mib=1,total_mib=16,history_rows=1024,preview_kib=128,
                 decode_mib=8,connections=2,pending_requests=16,udp_packets=512,handshake_seconds=30)
    query({'type':'mitm_options','settings':changed,'validate_only':True})
    assert query({'type':'mitm_options'})['settings']==original
    query({'type':'mitm_options','settings':changed})
    assert query({'type':'mitm_options'})['settings']==changed
    for key,value in [('entry_mib',17),('connections',0),('handshake_seconds',999)]:
        invalid=dict(changed);invalid[key]=value
        query({'type':'mitm_options','settings':invalid},fail=True)
        assert query({'type':'mitm_options'})['settings']==changed
    assert not query({'type':'analysis_start'})['reset']
    first=open_stream(1);assert first
    before=query({'type':'stats'})['run_id']
    data=c.create_string_buffer(b'SSH-2.0-test\r\n'+b'x'*(16384-14))
    for n in range(80):
        dll.plm_stream_io(first,0,0,data,len(data.value))
        if n%8==7:query({'type':'stats'})  # Drain queues; exercise the quota, not overload.
    assert query({'type':'stats'})['cache']['used_bytes']==1024*1024, 'saved per-entry quota must apply'
    doh=open_stream(20);assert doh
    rdata=(bytes([100])+b'x'*100)*200
    dns=struct.pack('!6H',1,0x8180,0,1,0,0)+b'\0'+struct.pack('!HHIH',16,1,0,len(rdata))+rdata
    for side,head in [(0,b'POST /dns-query HTTP/1.1\r\nHost: test\r\n'),(1,b'HTTP/1.1 200 OK\r\n')]:
        wire=head+b'Content-Type: application/dns-message\r\nContent-Length: '+str(len(dns)).encode()+b'\r\n\r\n'+dns
        data=c.create_string_buffer(wire);dll.plm_stream_io(doh,0,side,data,len(wire))
    dll.plm_stream_io(doh,2,0,None,0);handles.remove(doh)
    result=query({'type':'poll','after':0,'limit':64})
    exchange=next(r['exchange'] for r in result['records'] if r['type']=='exchange' and r['connection']['id']=='20')
    decoded=query({'type':'doh_read','run_id':before,'cache_id':exchange['cache']['id'],
                   'direction':'server','preview_bytes':16*1024})
    assert not decoded['decode_error'] and 'TXT' in decoded['text'], 'small display limit must not break DNS parsing'
    pending=dict(changed);pending['connections']=1
    query({'type':'mitm_options','settings':pending})
    assert open_stream(2), 'saving options must not interrupt the running analyzer'
    assert not open_stream(3)
    assert query({'type':'stats'})['run_id']==before
    assert query({'type':'analysis_start'})['reset']
    assert open_stream(4)
    assert not open_stream(5), 'new monitor run must use new connection cap'
    assert query({'type':'stats'})['run_id']!=before
    # Old taps remain safe to feed/free after a configuration restart.
    data=c.create_string_buffer(b'SSH-2.0-test\r\n')
    dll.plm_stream_io(first,0,0,data,len(data.value))
    assert not query({'type':'analysis_start'})['reset'], 'unchanged settings preserve the cache'
    query({'type':'analysis_stop'})
    stopped=query({'type':'stats'})
    assert stopped['active_connections']==0
    assert not open_stream(6), 'new connections while stopped must not be captured'
    for h in handles:
        dll.plm_stream_io(h,0,0,data,len(data.value))
        dll.plm_stream_io(h,4,0,None,0)
    assert query({'type':'stats'})==stopped
    query({'type':'analysis_start'})
    for h in handles:dll.plm_stream_io(h,0,0,data,len(data.value))
    assert query({'type':'stats'})==stopped, 'old captures must not resume after a gap'
    assert open_stream(7), 'fresh connections resume capture'
    query({'type':'analysis_stop'})
    assert query({'type':'stats'})['run_id']==stopped['run_id'], 'stop must retain history and payloads'
    query({'type':'shutdown'})
    assert not open_stream(8), 'proxy restart must retain the stopped monitoring mode'
    query({'type':'analysis_start'})
    assert open_stream(9)
    query({'type':'shutdown'})
    assert open_stream(10), 'proxy restart must retain an enabled monitoring mode'
    print('PASS release DLL: options, default-off, stop/drain, retained cache, restart and stale taps',work)
finally:
    for h in handles:dll.plm_stream_io(h,2,0,None,0)
    query({'type':'shutdown'})
    assert not list((work/'cache').glob('run-*')), 'cache must be cleaned'
