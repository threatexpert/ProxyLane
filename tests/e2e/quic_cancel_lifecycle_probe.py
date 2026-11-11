"""Cancel real shipping QUIC handles during handshake; no network or trust changes."""
import ctypes as C
import json
import os
from pathlib import Path
import tempfile
import time
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from quic_live_ffi_probe import Engine, CALLBACK, ROOT
import quic_mitm_probe as probe

def run():
    probe.isolate()
    with tempfile.TemporaryDirectory(dir=ROOT/'build/qa', prefix='quic-cancel-') as temp:
        os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=temp
        engine=Engine()
        engine.query(type='analysis_start')
        callback=CALLBACK(lambda _: None)
        def create(identity):
            config=QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name='cancel.quic.test',supported_versions=[1])
            client=QuicConnection(configuration=config)
            client.connect(('127.0.0.1',443),time.monotonic())
            data=client.datagrams_to_send(time.monotonic())[0][0]
            metadata=dict(connection_id=identity,pid=os.getpid(),process_create_time=1,socket=identity,socket_generation=1,destination='127.0.0.1',port=443,transport='udp')
            handle=C.c_void_p();error=C.create_string_buffer(2048)
            result=engine.dll.plm_quic_open(b'cancel.quic.test',json.dumps(metadata).encode(),data,len(data),None,callback,0,C.byref(handle),error,len(error))
            assert result==1,(result,error.value)
            return handle
        for identity in range(1,33):
            handle=create(identity)
            if identity%2:time.sleep(.005)
            engine.dll.plm_quic_io(handle,3,0,None,0)
        deadline=time.monotonic()+10
        while True:
            rows=engine.query(type='poll',limit=512)['records']
            ended=[r for r in rows if r.get('status')=='Closed']
            if len(ended)==32:break
            assert time.monotonic()<deadline,rows
            time.sleep(.02)
        for identity in range(1,33):
            own=[r for r in rows if r.get('connection',{}).get('id')==str(identity)]
            assert [r['status'] for r in own]==['Connecting','Closed'],own
            assert 'cancelled' in own[-1]['detail'],own
        handle=create(99)
        engine.query(type='analysis_stop')
        engine.query(type='analysis_start')
        last=engine.query(type='poll',limit=512)['next']
        engine.dll.plm_quic_io(handle,3,0,None,0)
        time.sleep(.15)
        assert engine.query(type='poll',limit=512)['next']==last
        engine.query(type='analysis_stop')
        print('PASS 32 real QUIC handle cancellations: one terminal event each; old epoch excluded')

if __name__=='__main__':run()
