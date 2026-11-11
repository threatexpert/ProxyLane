"""Read-only regression of the shipping Rust locator; never load a browser DLL.

python check_rust_locator.py --dll PATH --output build/qa/results.json MODULE...
Each image is mapped into a private byte buffer. Negative cases mutate that buffer,
not the original file. No injection, CA changes or network activity.
"""
import argparse
import ctypes as c
import json
from pathlib import Path
import time
import pefile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dll', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('modules', type=Path, nargs='+')
    args = parser.parse_args()
    dll = c.CDLL(str(args.dll.resolve()))
    locate = dll.plm_quic_locate_image
    locate.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t]
    locate.restype = c.c_int
    report = {'locator': str(args.dll.resolve()), 'targets': []}
    for path in args.modules:
        start = time.perf_counter()
        pe = pefile.PE(str(path), fast_load=True)
        assert pe.FILE_HEADER.Machine == 0x8664
        # pefile's default mapping omits sections above 256 MiB; modern browser
        # DLLs exceed that. Copy bounded sections directly, as the host does.
        image = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
        headers = pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders)
        image[:len(headers)] = headers
        for section in pe.sections:
            if section.Characteristics & 0x02000000:  # discardable
                continue
            at = section.VirtualAddress
            count = min(section.Misc_VirtualSize, section.SizeOfRawData)
            data = section.get_data()[:count]
            assert at + section.Misc_VirtualSize <= len(image) and len(data) == count
            image[at:at+count] = data
        snapshot_ms = (time.perf_counter()-start)*1000
        buf = (c.c_char*len(image)).from_buffer(image)

        def invoke():
            out = c.create_string_buffer(4096)
            start = time.perf_counter()
            result = locate(buf, len(buf), out, len(out))
            return result, out.value.decode(), (time.perf_counter()-start)*1000

        runs = [invoke() for _ in range(3)]
        entry = {'path': str(path), 'snapshot_ms': snapshot_ms,
                 'locator_ms': [x[2] for x in runs], 'negative_cases': []}
        report['targets'].append(entry)
        if any(n <= 0 for n, _, _ in runs):
            entry['error'] = runs[0][1]
        else:
            descriptors = [json.loads(s) for _, s, _ in runs]
            assert descriptors[0] == descriptors[1] == descriptors[2]
            d = descriptors[0]
            entry['descriptor'] = d
            begin, end = d['complete_rva'], d['complete_rva']+d['complete_size']
            # These are semantic invariants, deliberately not fixed instruction offsets.
            error_at = image.find(bytes.fromhex('84feffff'), begin, end)
            bool_at = image.find(bytes.fromhex('84c0'), d['caller_return_rva'], end)
            anchor_at = image.find(b'Net.QuicSession.CertVerificationResult')
            assert error_at >= 0 and bool_at >= 0 and anchor_at >= 0
            mutations = [('error_code', error_at, b'\x83'),
                         ('return_boolean_test', bool_at, b'\x90\x90'),
                         ('anchor', anchor_at, b'X'),
                         ('call_target', d['caller_return_rva']-4, b'\x00'*4)]
            for name, at, replacement in mutations:
                original = image[at:at+len(replacement)]
                image[at:at+len(replacement)] = replacement
                n, reason, _ = invoke()
                image[at:at+len(replacement)] = original
                assert n < 0, (path, name, reason)
                entry['negative_cases'].append({'case': name, 'rejected': True, 'reason': reason})
            entry['passed'] = True
        print(json.dumps(entry, ensure_ascii=False), flush=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        del buf, image
        pe.close()
    assert all(x.get('passed') for x in report['targets']), 'See regression report for rejected samples'


if __name__ == '__main__':
    main()
