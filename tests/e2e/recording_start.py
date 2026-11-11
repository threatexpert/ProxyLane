"""Real host startup/restart recording checks. No target apps, CA or OS trust changes."""
import json, os, time
from pathlib import Path
from quic_live_route_probe import Host, ROOT

def run():
    work=ROOT/'build/recording-validation'/('startup-'+str(time.time_ns()));work.mkdir(parents=True)
    os.environ['LOCALAPPDATA']=str(work/'local')
    host=Host(work)
    try:
        options=host.call(type='mitm_options')['settings']
        assert options['recording']['capacity_mib']==8192,options['recording']
        options['recording']={'enabled':True,'directory':str(work/'recordings'),'capacity_mib':8192,'reserve_mib':16}
        host.call(type='mitm_options',settings=options)
        host.call(type='monitor_start',decrypt=False,quic=False)
        first=host.call(type='recording_status');assert first['enabled'] and not first['ended'],first
        path=Path(first['directory']);assert (path/'manifest.json').exists()
        host.call(type='monitor_stop')
        assert json.loads((path/'manifest.json').read_text())['status']=='completed'
        # Proxy shutdown can clear Rust's runtime while the C++ monitoring flag remains set.
        options['recording']['enabled']=False;host.call(type='mitm_options',settings=options)
        host.call(type='monitor_start',decrypt=False,quic=False);host.call(type='shutdown')
        assert host.call(type='monitor_status')['monitoring']
        options['recording']['enabled']=True;host.call(type='mitm_options',settings=options)
        host.call(type='monitor_start',decrypt=False,quic=False)
        restarted=host.call(type='recording_status');assert restarted.get('enabled') and not restarted['ended'],restarted
        second=Path(restarted['directory']);assert second!=path and (second/'manifest.json').exists() and path.exists()
        # Editing options does not silently change the running capture.
        options['recording']['enabled']=False;host.call(type='mitm_options',settings=options)
        assert host.call(type='recording_status')['enabled']
        host.call(type='monitor_stop');host.call(type='monitor_start',decrypt=False,quic=False)
        assert not host.call(type='recording_status').get('enabled',False)
        host.call(type='monitor_stop')
        blocker=work/'not-a-directory';blocker.write_text('test')
        options['recording']['enabled']=True;options['recording']['directory']=str(blocker)
        host.call(type='mitm_options',settings=options)
        try:host.call(type='monitor_start',decrypt=False,quic=False)
        except RuntimeError:pass
        else:raise AssertionError('invalid recording directory silently accepted')
        assert not host.call(type='monitor_status')['monitoring']
        options['recording']['directory']=str(work/'recordings');host.call(type='mitm_options',settings=options)
        host.call(type='monitor_start',decrypt=False,quic=False);assert host.call(type='recording_status')['enabled'];host.call(type='monitor_stop')
        result={'default_capacity_mib':8192,'cold_start_before_any_traffic':True,'restart_after_runtime_shutdown':True,'options_apply_on_restart':True,'invalid_directory_blocks_start_and_can_be_corrected':True,'retained_directories':[str(path),str(second)]}
        (work/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))
    finally:host.close()

if __name__=='__main__':run()
