"""Mutate actual binary evidence in memory; never install a Hook or modify a DLL."""
import json
from pathlib import Path
import sys
from locate_policy_hook import locate, ANCHORS, pefile

path=Path(sys.argv[1]);output=Path(sys.argv[2]);raw=path.read_bytes()
report={'path':str(path),'cases':[],'passed':False}
baseline=locate(path,data=raw)
pe=pefile.PE(data=raw,fast_load=True)
offset=pe.get_offset_from_rva(baseline['caller_return_rva'])
mutations={
    'missing_anchor':lambda b:b.replace(ANCHORS[0],b'X'*len(ANCHORS[0])),
    'changed_error':lambda b:b[:offset]+b[offset:offset+32].replace(bytes.fromhex('84feffff'),bytes.fromhex('83feffff'))+b[offset+32:],
    # Removing this flag test would make accepting the candidate unsafe.
    'changed_boolean_test':lambda b:b[:offset]+b[offset:offset+16].replace(bytes.fromhex('84c0'),bytes.fromhex('90c0'))+b[offset+16:],
}
for name,mutate in mutations.items():
    changed=mutate(raw);assert changed!=raw
    try:locate(path,data=changed)
    except ValueError as e:report['cases'].append({'case':name,'rejected':True,'reason':str(e)})
    else:raise AssertionError(f'{name} unexpectedly accepted')
    print(name,'rejected',flush=True)
report['passed']=True;output.write_text(json.dumps(report,indent=2));print(output)
