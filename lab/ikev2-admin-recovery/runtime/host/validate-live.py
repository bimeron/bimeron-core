"""Offline freeze validator and local manifest writer; never operates the lab."""
import argparse
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'driver'))
from live_prepare import host_code_paths, load_config
from protected_transport import encode, sha

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--config', type=pathlib.Path)
    group.add_argument('--code-manifest', type=pathlib.Path)
    args=parser.parse_args()
    if args.code_manifest:
        raw=encode(dict(schema='l1-host-code-v1', files={n:sha(p.read_bytes()) for n,p in sorted(host_code_paths().items())}))
        with args.code_manifest.open('xb') as stream: stream.write(raw)
        print('Code manifest written; review still required.')
    else:
        load_config(args.config)
        print('Offline configuration bindings valid; no live action performed.')

if __name__=='__main__': main()
