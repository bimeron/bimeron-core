"""MailboxClient adapter retaining one original guest owner for this run."""
import base64
import pathlib
import subprocess
import threading
import time
from admin_recovery import encode, decode, sha, require, fields, Hold, reason_text, publish_exclusive
from process_handles import ChildHandle
from stock_controller import _stock_child_environment


class ResidentRPC:
    def __init__(self, owner, driver, *, popen=subprocess.Popen, identity=ChildHandle,
                 clock=time.monotonic, pause=time.sleep, environment=_stock_child_environment):
        self.owner, self.driver = owner, pathlib.Path(driver)
        self.clock, self.pause, self.identity = clock, pause, identity
        self.lock = threading.RLock()
        self.sequence = 0
        self.pending = None
        self.fixed_requests = {}
        self.results = {}
        self.not_dispatched = []
        self.process = self.handle = None
        self.root = owner.journal.admission.create_root(owner.journal.root/'guest-control')
        exe=pathlib.Path('C:/Windows')/'System32/WindowsPowerShell/v1.0/powershell.exe'
        args=[str(exe),'-NoProfile','-NonInteractive','-WindowStyle','Hidden','-ExecutionPolicy','Bypass',
              '-File',str(self.driver/'resident-main.ps1'),'-Root',str(self.root),
              '-Nonce',owner.bound['nonce'],'-ConfigSHA256',owner.bound['configSHA256']]
        env=environment(exe)
        owner.journal.write('resident-start-reserved.json',encode(dict(binding=owner.bound,argv=args)))
        # Capture partial ownership before identity/readiness can fail.
        owner.resources['resident'] = self
        owner.resources.setdefault('operations',{})['resident']=dict(identity=None,submission='Reserved')
        owner.resources.setdefault('operationOwners',{})['resident']=self
        try:
            with (self.root/'resident.stdout').open('xb') as out,(self.root/'resident.stderr').open('xb') as err:
                self.process=popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,
                                   shell=False,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
        except BaseException:
            # No resident process exists: a known no-dispatch, not an owned child.
            owner.resources['operations']['resident']=dict(identity=None,submission='NotDispatched')
            raise
        self.observe_original()
        ready=decode(self._wait('resident-ready.json',30))
        require(ready==dict(schema='fresh-resident-ready-v1',nonce=owner.bound['nonce'],
                           configSHA256=owner.bound['configSHA256']),'Resident readiness binding')

    def observe_original(self):
        require(self.process is not None,'Original resident process unavailable')
        if self.handle is None:self.handle=self.identity(self.process)
        original_identity=dict(pid=self.process.pid,creationFileTime=str(self.handle.creation),
                               imageSHA256=sha(pathlib.Path(self.handle.exe).read_bytes()))
        previous=self.owner.resources['operations']['resident']['identity']
        require(previous is None or previous==original_identity,'Original resident identity changed')
        self.owner.resources['operations']['resident']=dict(identity=original_identity,submission='Submitted')

    def _read_complete(self,path):
        """Complete published JSON bytes, or None while absent/empty/partial."""
        try:
            raw=path.read_bytes()
        except FileNotFoundError:
            return None
        except PermissionError:
            return None  # Writer still holds the file without read sharing.
        if not raw:
            return None
        try:
            decode(raw)
        except (ValueError,Hold):
            return False  # Present but not (yet) a complete JSON document.
        return raw

    def _wait(self,name,seconds):
        require(type(seconds) in (int,float) and 0<seconds<=150,'Resident observation bound')
        end=self.clock()+seconds
        path=self.root/name
        malformed=False
        while self.clock()<end:
            self.owner.journal.admission.revalidate()
            # Missing, zero-length or partially written publications are "not
            # yet". A complete document returns; its binding is validated by
            # the caller, and a validation failure still fails.
            raw=self._read_complete(path)
            if raw:
                return raw
            malformed=raw is False
            if self.process.poll() is not None:
                raw=self._read_complete(path)  # Final publication before exit.
                if raw:
                    return raw
                require(raw is not False,'Original resident exited with malformed publication: '+name)
                require(False,'Original resident exited without receipt')
            self.pause(.05)
        require(not malformed,'Resident publication malformed at deadline; original authority retained: '+name)
        raise Hold('Resident observation timeout; original authority retained')

    def _publish(self,name,raw):
        self.owner.journal.admission.revalidate()
        publish_exclusive(self.root/name,raw,'Resident publication conflict')

    def __call__(self,mode,path):
        raw=pathlib.Path(path).read_bytes();value=decode(raw)
        operation='preflight' if mode=='preflight' else value.get('op')
        return self.submit('submit' if mode=='preflight' else mode,operation,path,raw)

    def submit(self,mode,operation,path,raw,seconds=30):
        with self.lock:
            require(self.pending is None,'Original resident request outstanding')
            require(mode!='fetch' or operation in ('launch','sample','start','cleanup','seal-no-launch'),
                    'Unsafe resident fetch')
            self.sequence+=1
            if operation not in ('restore-session-policy','guest','services','absence'):
                self.owner.resources.setdefault('entryInventory',{})['guestAttempted']=True
            request=dict(schema='fresh-resident-request-v1',nonce=self.owner.bound['nonce'],
                configSHA256=self.owner.bound['configSHA256'],sequence=self.sequence,
                mode=mode,operation=operation,path=str(pathlib.Path(path).absolute()),requestSHA256=sha(raw))
            self.pending=request
            name='resident-request-%020d.json'%self.sequence
            try:
                self._publish(name,encode(request))
            except BaseException:
                if not (self.root/name).exists():
                    # Never visible to the resident host, which admits only the
                    # next contiguous sequence: release and roll the number back.
                    self.not_dispatched.append(request);self.pending=None;self.sequence-=1
                    for key,prior in list(self.fixed_requests.items()):
                        if prior['sequence']==request['sequence']:del self.fixed_requests[key]
                raise
            return self.collect(seconds)

    def collect(self,seconds=30):
        with self.lock:
            require(self.pending is not None,'No original resident request')
            p=self.pending
            response=decode(self._wait('resident-response-%020d.json'%p['sequence'],seconds))
            fields(response,('schema','nonce','configSHA256','sequence','requestSHA256','state','output','error'))
            require(response['schema']=='fresh-resident-response-v1' and all(response[k]==p[k]
                for k in ('nonce','configSHA256','sequence','requestSHA256')),'Resident response binding')
            require(response['state'] in ('Collected','Failed'),'Resident terminal state')
            require(response['error'] is None if response['state']=='Collected' else
                    response['error'] is None or type(response['error']) is str,'Resident error shape')
            self.last_response=response
            self.results[p['sequence']]=response
            self.pending=None
            require(response['state']=='Collected','Original resident operation failed; effects require disposition: '
                    +(reason_text(response['error']) if response['error'] else 'no diagnostic'))
            return base64.b64decode(response['output'],validate=True)

    def fixed(self,key,operation,context,seconds=30):
        """One fixed continuation operation, with late collection on the same ID."""
        with self.lock:
            require(key in ('phase1-policy','phase1-guest','phase1-services','phase1-absence'),
                    'Fixed continuation key')
            expected={'phase1-policy':'restore-session-policy','phase1-guest':'guest',
                      'phase1-services':'services','phase1-absence':'absence'}
            require(operation==expected[key],'Fixed continuation operation')
            path=self.root/(key+'.json')
            if key in self.fixed_requests:
                prior=self.fixed_requests[key]
                require(prior['sha256']==sha(context),'Original continuation context changed')
                response=self.results.get(prior['sequence'])
                if response is None:
                    require(self.pending is not None and self.pending['sequence']==prior['sequence'],
                            'Original continuation outcome unknown')
                    return self.collect(seconds)
                if response['state']=='Collected':
                    return base64.b64decode(response['output'],validate=True)
                # Only the three pure readbacks may be observed again after a
                # terminal Failed; the policy restoration mutation never repeats.
                require(key!='phase1-policy','Original continuation failed')
            require(self.pending is None,'Original resident request outstanding')
            self._publish(path.name,context)
            self.fixed_requests[key]=dict(sequence=self.sequence+1,sha256=sha(context))
            return self.submit('submit',operation,path,context,seconds)

    def helper(self,script,args,seconds):
        values=dict(zip(args[::2],args[1::2]))
        require(values.get('-Nonce')==self.owner.bound['nonce'],'Resident helper nonce')
        if script=='guest-read.ps1':
            require(set(values)=={'-Mode','-Nonce'} and values['-Mode'] in ('integration','ready','clock'),
                    'Resident read allowlist')
            operation=values['-Mode']
        else:
            require(script=='protected-guest.ps1' and values.get('-Operation') in
                    ('principal','challenge','transition'),'Resident helper allowlist')
            operation=values['-Operation']
        path=values.get('-RequestPath')
        if path is None:
            path=self.root/'resident-helper-context.json'
            self._publish(path.name,encode(self.owner.bound))
        return self.submit('submit',operation,path,pathlib.Path(path).read_bytes(),seconds)

    def cached_original(self,request_hash):
        """Already EndInvoke-collected output; no fetch or guest operation."""
        values={base64.b64decode(value['output'],validate=True) for value in self.results.values()
                if value['requestSHA256']==request_hash and value['state']=='Collected'}
        require(len(values)<=1,'Conflicting original resident output')
        return next(iter(values)) if values else None

    def close_session(self):
        require(self.pending is None,'Resident original operation pending')
        self.observe_original()
        self._publish('resident-close-request.json',encode(dict(schema='fresh-resident-close-v1',
            nonce=self.owner.bound['nonce'],configSHA256=self.owner.bound['configSHA256'],lastSequence=self.sequence)))
        raw=self._wait('resident-closed.json',30)
        require(decode(raw)==dict(schema='fresh-resident-closed-v1',
            nonce=self.owner.bound['nonce'],configSHA256=self.owner.bound['configSHA256'],
            sessionState='Closed',pending=0,normalCleanupSucceeded=False),'Original resident closure')
        self.closure=raw
        return raw

    def finish(self,closure):
        require(getattr(self,'closure',None)==closure,'Validated original session closure required')
        self._publish('resident-finish-request.json',encode(dict(schema='fresh-resident-finish-v1',
            nonce=self.owner.bound['nonce'],configSHA256=self.owner.bound['configSHA256'],closureSHA256=sha(closure))))
        receipt=self._wait('resident-finished.json',30)
        require(decode(receipt)==dict(schema='fresh-resident-finish-v1',
            nonce=self.owner.bound['nonce'],configSHA256=self.owner.bound['configSHA256'],
            closureSHA256=sha(closure)),'Original resident finish binding')
        end=self.clock()+30
        while self.clock()<end and self.process.poll() is None:self.pause(.05)
        require(self.process.poll()==0,'Original resident positive exit absent')
        self.finished=receipt
        return receipt

    def administrative_closure(self):
        require(self.pending is None and getattr(self,'closure',None) is not None and
                getattr(self,'finished',None) is not None and self.process.poll()==0,
                'Original resident not positively closed')
        identity=self.owner.resources['operations']['resident']['identity']
        return dict(identity=identity,submission='Submitted',terminal='Collected',
                    sessionState='Closed',pending=False)
