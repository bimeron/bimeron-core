"""Isolated child entry for exactly the admitted preparation watcher.

Parent admission pins this file, the manifest and every source before Popen and
retains the pins until positive administrative settlement. No sys.path mutation.
"""
import argparse
import hashlib
import importlib.abc
import importlib.util
import json
import pathlib
import sys


def main():
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError('Watcher requires Python -I -S')
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',required=True);parser.add_argument('--sha256',required=True)
    parser.add_argument('--driver',required=True);parser.add_argument('--config',required=True)
    parser.add_argument('--admission',required=True)
    args=parser.parse_args();raw=pathlib.Path(args.manifest).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=args.sha256:raise RuntimeError('Watcher manifest anchor')
    manifest=json.loads(raw)
    if set(manifest)!={'schema','files'} or manifest['schema']!='fresh-admin-sources-v1':
        raise RuntimeError('Watcher manifest schema')
    root=pathlib.Path(args.driver);captured={}
    for name,digest in manifest['files'].items():
        if pathlib.Path(name).name!=name or ':' in name or '/' in name or '\\' in name:
            raise RuntimeError('Watcher source basename')
        data=(root/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('Watcher source digest')
        captured[name]=data
    if captured.get('pinned_watcher.py')!=pathlib.Path(__file__).read_bytes():
        raise RuntimeError('Watcher loader binding')
    class Loader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if fullname+'.py' in captured:
                return importlib.util.spec_from_loader(fullname,self,origin=str(root/(fullname+'.py')))
            if fullname.split('.')[0] not in sys.stdlib_module_names and fullname not in sys.builtin_module_names:
                raise ImportError('Outside admitted watcher source closure')
            return None
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__=str(root/(module.__name__+'.py'))
            exec(compile(captured[module.__name__+'.py'],module.__file__,'exec'),module.__dict__)
    for name in captured:
        if name.endswith('.py') and name[:-3] in sys.modules:
            raise RuntimeError('Preloaded watcher application module')
    sys.meta_path.insert(0,Loader())
    path=root/'watch-prep.py'
    sys.argv=[str(path),'--config',args.config,'--admission',args.admission]
    exec(compile(captured[path.name],str(path),'exec'),dict(__name__='__main__',__file__=str(path)))


if __name__=='__main__':main()
