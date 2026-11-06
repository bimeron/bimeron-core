"""Pinned source loading and finite private endpoint for the original owner.

Native path/ACL pins are supplied by admission BEFORE calling these functions.
The bootstrap itself must be an explicitly reviewed trust root, not self-approved.
"""
import importlib.util
import importlib.abc
import pathlib
import sys
import time

from admin_recovery import decode, sha, fields, digest, require, encode, Hold


def load_pinned_modules(root, manifest_bytes, expected_hash, admission, names):
    require(sha(manifest_bytes) == expected_hash, 'Independent manifest anchor')
    manifest = decode(manifest_bytes)
    fields(manifest, ('schema', 'files'))
    require(manifest['schema'] == 'fresh-admin-sources-v1', 'Source manifest schema')
    require(type(manifest['files']) is dict and bool(manifest['files']), 'Source closure')
    root = pathlib.Path(root)
    captured = {}
    for name, expected in manifest['files'].items():
        require(type(name) is str and '/' not in name and '\\' not in name and
                ':' not in name and name not in ('.', '..'), 'Source basename')
        digest(expected)
        path = root / name
        admission.pin_source(path)
        raw = path.read_bytes()
        require(sha(raw) == expected, 'Source digest: ' + name)
        captured[name] = raw
    modules={name[:-3] for name in captured if name.endswith('.py')}
    require(set(names)<=modules,'Missing module binding')
    # Check the complete local module closure, not only the requested roots.
    for name in modules:
        if name in sys.modules:
            old = sys.modules[name]
            require(getattr(old, '__admin_source_sha256__', None) == sha(captured[name + '.py'])
                    and getattr(old, '__file__', None) == str(root / (name + '.py')),
                    'Untrusted preloaded module: ' + name)
    class PinnedLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in modules:
                return importlib.util.spec_from_loader(fullname,self,origin=str(root/(fullname+'.py')))
            top=fullname.split('.')[0]
            if top in sys.stdlib_module_names or top in sys.builtin_module_names:
                return None
            # Absent from the closure is an ordinary import miss: stdlib probes
            # such as copy's optional org.python.core must see ImportError. The
            # raise (not None) still keeps every later finder/sys.path untried.
            raise ModuleNotFoundError('Import outside pinned application/stdlib closure: '+fullname,
                                      name=fullname)
        def create_module(self,spec):return None
        def exec_module(self,module):
            name=module.__name__;path=root/(name+'.py')
            admission.revalidate()
            module.__file__=str(path)
            module.__admin_source_sha256__=sha(captured[name+'.py'])
            try:exec(compile(captured[name+'.py'],str(path),'exec'),module.__dict__)
            except BaseException:
                module.__admin_source_sha256__=None
                raise
    finder=PinnedLoader()
    # The original owner retains this finder throughout deferred imports.
    sys.meta_path.insert(0,finder)
    result = {}
    for name in names:
        admission.revalidate()
        path = root / (name + '.py')
        if name not in sys.modules:
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            module.__admin_source_sha256__ = sha(captured[name + '.py'])
            sys.modules[name] = module
            # Execute the already pinned bytes; no pyc loader or sys.path prepend.
            try:
                exec(compile(captured[name + '.py'], str(path), 'exec'), module.__dict__)
            except BaseException:
                # Poison remains registered so it cannot silently be retried.
                module.__admin_source_sha256__ = None
                raise
        result[name] = sys.modules[name]
    admission.revalidate()
    result['__pinned_finder__']=finder
    return result


class Endpoint:
    """A bounded observation slice. Only Owner decides when its caller may exit."""
    def __init__(self, root, admission, proof_reader, collect_original, clock=time.monotonic,
                 pause=time.sleep):
        self.root = pathlib.Path(root)
        self.admission = admission
        self.proof_reader = proof_reader
        self.collect_original = collect_original
        self.clock, self.pause = clock, pause
        self.rejected = {}
        # Per sequence: the exact accepted file name and bytes. A publication
        # retry republishes from this cache and never re-reads a slot file.
        self.accepted = {}

    def __call__(self, owner):
        """Read each request once through a temporary handle; never retain it.

        A pure rejection is published append-only as rejected-N-<sha>.json and
        the slot then accepts only admin-request-N-<sha>.json bound to it.
        """
        deadline = self.clock() + 1
        while self.clock() < deadline:
            self.admission.revalidate()
            # A publication failure retries only the already cached immutable
            # response. It must not strand the original completed action.
            retry=next((seq for seq,entry in owner.requests.items()
                        if entry['response'] is not None and not entry['published']),None)
            if retry is not None and retry in self.accepted:
                _, cached = self.accepted[retry]
                return owner.request(cached, collect=self.collect_original)
            seq = retry or owner.last + 1
            name = 'admin-request-%020d' % seq
            if seq in self.rejected:
                name += '-' + self.rejected[seq]
            path = self.root / (name + '.json')
            if not path.exists():
                self.pause(.05)
                continue
            raw = None
            try:
                try:
                    raw = self.admission.read_once(path, 16384)
                except OSError:
                    # Pending (still being written) and native I/O errors are
                    # transient: retry next tick, never publish a rejection.
                    self.pause(.05)
                    continue
                request = decode(raw)
                require(type(request) is dict, 'Request object')
                # The slot number binds the request: an older request copied
                # into a later slot is rejected, never republished.
                require(request.get('sequence') == seq, 'Request slot sequence')
                verb = request.get('verb')
                proof = self.proof_reader(request.get('proofSHA256')) if verb in ('phase1','settle') else None
                self.accepted[seq] = (path.name, raw)
                return owner.request(raw, phase1=proof if verb=='phase1' else None,
                                     phase2=proof if verb=='settle' else None,
                                     collect=self.collect_original)
            except (Hold, ValueError) as error:
                entry = owner.requests.get(seq)
                if entry is not None and raw is not None and entry['sha256'] == sha(raw):
                    raise
                self.accepted.pop(seq, None)
                if raw is None:
                    # Unreadable slot (bound, hardlink, reparse): bind the
                    # rejection to the refusal itself; a replacement is required.
                    fingerprint = sha(('unreadable:' + name).encode('utf-8'))
                else:
                    fingerprint = sha(raw)
                owner.journal.write('rejected-%020d-%s.json' % (seq, fingerprint), encode(dict(
                    schema='fresh-admin-rejection-v1', binding=owner.bound, sequence=seq,
                    requestSHA256=fingerprint, reason=type(error).__name__ + ': ' + str(error))))
                self.rejected[seq] = fingerprint
                return None
        return None
