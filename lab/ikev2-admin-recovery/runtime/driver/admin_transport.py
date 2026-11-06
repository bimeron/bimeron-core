"""Retained original preparation transports; no retry or timeout termination."""
import threading
import time
import pathlib
from admin_recovery import require, encode, sha
from transport import Transport


RETIREMENT = ('admin-capture-confirm', 'admin-capture-stop', 'admin-sink-stop')


class OriginalTransports:
    def __init__(self, owner, clock=time.monotonic, transport=Transport):
        self.owner, self.clock, self.transport = owner, clock, transport
        self.lock = threading.RLock()
        self.entries = []
        self.pending = None
        self.fixed_requests = {}
        self.attempts = set()

    @staticmethod
    def _fingerprint(argv,data,mutation):
        return sha(encode(dict(argv=list(argv),inputSHA256=sha(data),mutation=mutation)))

    def retire(self,key,argv,data=b''):
        """Shared effect-once ledger for the normal body and the Handoff.

        Returns the original output on first dispatch and None once attempted;
        independent readback then decides the retirement outcome.
        """
        with self.lock:
            require(key in RETIREMENT,'Retirement key')
            if key in self.attempts:
                require(key in self.fixed_requests,'Retirement attempt without fixed record')
                number,original_hash=self.fixed_requests[key]
                require(original_hash==self._fingerprint(argv,data,True),'Original transport command changed')
                if self.entries[number]['state']!='NotDispatched':return None
            else:
                require(self.pending is None,'Original transport outstanding')
                self.attempts.add(key)
            return self.fixed(key,argv,data=data)

    def fixed(self,key,argv,seconds=8,data=b'',mutation=True):
        """Continue only this original fixed command; never submit it twice."""
        with self.lock:
            fingerprint=self._fingerprint(argv,data,mutation)
            if key in self.fixed_requests:
                number,original_hash=self.fixed_requests[key]
                require(original_hash==fingerprint,'Original transport command changed')
                entry=self.entries[number]
                if entry['state']=='NotDispatched':
                    # Known pre-dispatch failure: the same fixed key reserves again.
                    require(self.pending is None,'Original transport outstanding')
                    self.fixed_requests[key]=(len(self.entries),fingerprint)
                    return self(argv,seconds,data,mutation=mutation)
                if entry['state']=='Resolved':return entry['output']
                if entry['state']=='Returned' or (entry['state']=='Collected' and self.pending is not entry):
                    require(entry.get('returncode',0)==0,'Original transport failed')
                    return entry['output']
                require(self.pending is entry,'Original transport disposition missing')
                return self.collect_original()
            require(self.pending is None,'Original transport outstanding')
            self.fixed_requests[key]=(len(self.entries),fingerprint)
            return self(argv,seconds,data,mutation=mutation)

    def permit_retirement_readback(self):
        """Only three fixed administrative effects permit terminal reconciliation.

        Retain their uncertainty while allowing independent readback. This never
        resubmits the effect and never permits detaching a running local child.
        """
        with self.lock:
            if self.pending is None:return
            index=self.entries.index(self.pending)
            names=[key for key,(number,_) in self.fixed_requests.items() if number==index]
            require(len(names)==1 and names[0] in RETIREMENT,
                    'Original non-retirement effect unresolved')
            t=self.pending['transport']
            require(t is not None and len(t.children)==1,'Original retirement child unknown')
            child=t.children[0]
            require(child['handle'] is not None and child['record']['identity'] is not None and
                    type(child['process'].poll()) is int,'Original retirement transport still pending')
            with pathlib.Path(child['record']['files']['stdout']).open('rb') as stream:
                output=stream.read(16*1024*1024+1)
            require(len(output)<=16*1024*1024,'Original retirement output bound')
            self.pending.update(output=output,returncode=child['process'].poll())
            self.pending['state']='TerminalUnresolved'
            self.pending=None

    def resolve_retirement(self,key,proof_hash):
        with self.lock:
            require(key in RETIREMENT,'Retirement key')
            if key not in self.fixed_requests:return
            number,_=self.fixed_requests[key];entry=self.entries[number]
            if entry['state'] in ('Returned','Resolved'):return
            # A known pre-spawn failure sent nothing. When the independent
            # readback already proves the target state, resolve without re-send.
            dispatched=entry['state']!='NotDispatched'
            require(not dispatched or entry['state']=='TerminalUnresolved',
                    'Original retirement transport unresolved')
            from admin_recovery import digest
            digest(proof_hash)
            self.owner.journal.write('transport-resolution-%06d.json'%(number+1),encode(dict(
                binding=self.owner.bound,key=key,proofSHA256=proof_hash,dispatched=dispatched)))
            entry.update(state='Resolved',resolutionSHA256=proof_hash)

    def __call__(self, argv, seconds=8, data=b'', mutation=True):
        with self.lock:
            require(self.pending is None, 'Original transport outstanding')
            number = len(self.entries) + 1
            directory = self.owner.journal.root / ('original-transport-%06d' % number)
            entry = dict(argv=list(argv), inputSHA256=sha(data), transport=None,
                         state='Reserved', output=None,mutation=mutation)
            self.entries.append(entry)
            self.pending = entry
            t = None
            try:
                self.owner.journal.write('transport-%06d.json' % number, encode(dict(
                    binding=self.owner.bound, argv=list(argv), inputSHA256=sha(data))))
                directory.mkdir()
                t = self.transport(directory, self.clock()+seconds+1, clock=self.clock)
                entry['transport'] = t
                result = t.observe(argv, 'original', data=data, timeout=seconds,
                                   before_spawn=self.owner.journal.admission.revalidate,
                                   mutation=mutation)
                entry.update(state='Returned', output=result)
                self.pending = None
                # Original handles survive until the administrative/normal owner
                # verifies semantic completion and positive closure separately.
                return result
            except BaseException as error:
                children = t.children if t is not None else []
                if not children:
                    # Nothing was spawned: known no-dispatch; the consumed number
                    # stays and the pending slot is released.
                    entry.update(state='NotDispatched', error=type(error).__name__)
                    self.pending = None
                elif not mutation and type(children[0]['process'].poll()) is int:
                    # A terminal failed read (e.g. ssh 255) has no effect to dispose.
                    entry.update(state='Failed', returncode=children[0]['process'].poll())
                    self.pending = None
                else:
                    entry['state'] = 'Unknown'
                raise

    def inspect_original(self, resources):
        """No spawn/dispose/submit. Late output remains private and nonauthoritative."""
        observed = []
        for entry in self.entries:
            t = entry['transport']
            children = []
            if t is not None:
                for child in t.children:
                    children.append(dict(identity=child['record']['identity'],
                                         returncode=child['process'].poll()))
            observed.append(dict(state=entry['state'], children=children))
        return observed

    def collect_original(self):
        """Collect one original direct child; never call observe/spawn/close.

        Returned bytes are observation only. Callers must still validate the
        original operation's response and positive remote closure separately.
        """
        with self.lock:
            entry = self.pending
            require(entry is not None, 'No original transport pending')
            t = entry['transport']
            require(t is not None and len(t.children) == 1, 'Original child unknown')
            child = t.children[0]
            require(child['handle'] is not None and child['record']['identity'] is not None,
                    'Original transport identity unavailable')
            code = child['process'].poll()
            require(type(code) is int, 'Original transport still pending')
            if entry['output'] is None:
                path = pathlib.Path(child['record']['files']['stdout'])
                with path.open('rb') as stream:
                    output = stream.read(16 * 1024 * 1024 + 1)
                require(len(output) <= 16 * 1024 * 1024, 'Original output bound')
                entry.update(output=output, returncode=code, state='Collected')
            require(code == entry['returncode'], 'Original terminal state changed')
            number = self.entries.index(entry) + 1
            self.owner.journal.write('transport-late-%06d.json' % number, encode(dict(
                binding=self.owner.bound, identity=child['record']['identity'],
                returncode=code, outputSHA256=sha(entry['output']),
                remoteClosureProven=False)))
            # A failed remote operation remains outstanding for disposition;
            # successful local exit only makes its raw response available.
            if code!=0 and entry['mutation'] is False:
                self.pending=None
            require(code == 0, 'Original transport failed; remote disposition required')
            self.pending = None
            return entry['output']
