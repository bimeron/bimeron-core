"""Externally reviewed isolated bootstrap entry; explicit anchored inputs only."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import sys


def main():
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError('Launch the reviewed bootstrap with Python -I -S')
    parser=argparse.ArgumentParser()
    parser.add_argument('--configuration',required=True);parser.add_argument('--sha256',required=True)
    args,_=parser.parse_known_args()
    raw=pathlib.Path(args.configuration).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=args.sha256:raise RuntimeError('Independent configuration anchor')
    config=json.loads(raw);root=pathlib.Path(config['driver'])
    manifest_raw=pathlib.Path(config['driverManifest']['path']).read_bytes()
    if hashlib.sha256(manifest_raw).hexdigest()!=config['driverManifest']['sha256']:
        raise RuntimeError('Independent source anchor')
    manifest=json.loads(manifest_raw)['files']
    if pathlib.Path(__file__).resolve()!=root/'preparation.py' or hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()!=manifest['preparation.py']:
        raise RuntimeError('Bootstrap source binding')
    captured={}
    for name in ('admin_recovery','admin_native','admin_bootstrap','admin_entry'):
        if name in sys.modules:raise RuntimeError('Preloaded bootstrap module')
        path=root/(name+'.py');data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=manifest[path.name]:raise RuntimeError('Bootstrap dependency binding')
        captured[name]=(path,data)
    for name,(path,data) in captured.items():
        spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        exec(compile(data,str(path),'exec'),module.__dict__)
    return sys.modules['admin_entry'].main()


if __name__=='__main__':main()
