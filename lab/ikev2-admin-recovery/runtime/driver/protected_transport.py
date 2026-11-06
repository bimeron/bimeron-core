"""Immutable host mailbox transport. Importing this module performs no I/O."""
import hashlib
import json
import pathlib
import re
import threading
import time
import subprocess
import os

def _powershell_environment(executable):
    from stock_controller import _stock_child_environment
    return _stock_child_environment(executable)


class PSDirectRPC:
    """File-backed RPC observation; protocol decisions remain in MailboxClient."""
    def __init__(self, script, nonce, runner=None, timeout=30, *, popen=None,
                 identity=None, clock=time.monotonic, sleep=time.sleep,
                 child_environment=None):
        if not re.fullmatch('[a-f0-9]{64}', nonce):
            raise Hold('Invalid nonce')
        if runner is not None and runner is not subprocess.run:
            raise Hold('Legacy run injection forbidden; inject below Popen')
        import math
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 150:
            raise Hold('Invalid RPC observation bound')
        self.script = pathlib.Path(script).resolve()
        self.nonce, self.timeout = nonce, timeout
        self.popen, self.identity = popen, identity
        self.clock, self.sleep = clock, sleep
        self.root = None
        self.sequence = 0
        self.requests = {}
        self.pending = None
        self.active = None
        self.last_evidence = None
        self.lock = threading.RLock()
        self.child_environment = child_environment

    def __call__(self, mode, path):
        with self.lock:
            return self._invoke(mode, path)

    def _invoke(self, mode, path):
        from transport import Transport, retain
        if mode not in ('submit', 'fetch', 'preflight'):
            raise Hold('Invalid RPC mode')
        path = pathlib.Path(path).resolve()
        raw = path.read_bytes()
        value = strict(raw)
        if value.get('nonce') != self.nonce:
            raise Hold('RPC nonce mismatch')
        original_op = 'preflight' if mode == 'preflight' else value.get('op')
        # final is only an argv label. Fetching exit-supervisor used to repeat
        # Complete-OwnerFinal, including DeleteTask. Refuse before close/spawn.
        if mode == 'fetch' and original_op not in (
                'launch', 'sample', 'start', 'cleanup', 'seal-no-launch'):
            raise Hold('Unsafe fetch operation; original authority retained')
        op = original_op
        if op in ('seal-no-launch', 'exit-supervisor'):
            op = 'final'
        if op not in ('preflight', 'launch', 'sample', 'start', 'cleanup', 'final'):
            raise Hold('Invalid guest operation')
        binding = (str(path), sha(raw))
        base = path.parent.parent if path.parent.name == 'commands' else path.parent
        root = base / 'rpc-evidence'
        if self.root is not None and root != self.root:
            raise Hold('RPC mailbox changed')
        if mode == 'fetch':
            if self.requests.get(str(path)) != binding[1]:
                raise Hold('Fetch requires original bound request')
            if self.pending is not None:
                if self.pending != binding:
                    raise Hold('Outstanding RPC requires original request')
                # Only the retained original Popen and verified identity admit fetch.
                try:
                    t = self.active['transport']
                    state = t.children[0]
                    if (len(t.children) != 1 or state['handle'] is None
                            or state['record']['identity'] is None):
                        raise RuntimeError('Identity unavailable')
                    code = state['process'].poll()
                    if code is None:
                        raise RuntimeError('Surviving transport')
                    retain(self.active['directory'] / 'fetch-admission.json',
                           dict(returncode=code,terminationObserved=True,
                                identity=state['record']['identity'],requestSHA256=binding[1]))
                    t.close()
                except Exception:
                    raise Hold('RPC transport exit/identity unproven; no fetch; separately reviewed disposition required') from None
        else:
            if self.pending is not None:
                raise Hold('Outstanding RPC; no submission or automatic replay')
            if str(path) in self.requests:
                raise Hold('RPC submission already attempted')
        executable = pathlib.Path('C:/Windows') / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        if self.child_environment is None:
            child_environment = _powershell_environment(executable)
        else:
            child_environment = self.child_environment(executable)
        args = [str(executable), '-NoProfile', '-NonInteractive', '-WindowStyle',
                'Hidden', '-ExecutionPolicy', 'Bypass', '-File', str(self.script),
                '-Operation', op, '-Nonce', self.nonce, '-RequestPath', str(path),
                '-Mode', 'fetch' if mode == 'fetch' else 'submit']
        self.pending = binding
        self.requests[str(path)] = binding[1]
        self.sequence += 1
        label = '%06d-%s' % (self.sequence, mode)
        attempt = root / label
        self.active = None
        self.last_evidence = dict(attempt=label,directory=str(attempt))
        try:
            if self.root is None:
                # Existing evidence is never adopted by a replacement RPC instance.
                root.mkdir()
                self.root = root
            attempt.mkdir()
            retain(attempt / 'binding.json', dict(nonce=self.nonce,operation=op,
                   requestedOperation=value.get('op'),mode=mode,requestPath=str(path),
                   requestSHA256=binding[1],requestLength=len(raw),argv=args,
                   observationSeconds=self.timeout))
            t = Transport(attempt,self.clock()+self.timeout+1,clock=self.clock,
                          sleep=self.sleep,popen=self.popen,identity=self.identity)
            self.active = dict(transport=t,directory=attempt)
            def before_spawn():
                if path.read_bytes() != raw:
                    raise Hold('RPC request changed before spawn')
            output = t.observe(args,'rpc',timeout=self.timeout,before_spawn=before_spawn,
                               mutation=(mode != 'fetch'),env=child_environment)
            t.close()
            self.pending = None
            return output.rstrip(b'\r\n')
        except Exception:
            # Raw diagnostics remain in private file streams, never exception text.
            raise Hold('PSDirect unresolved; private evidence attempt '+label+
                       '; no replay; surviving transport requires reviewed disposition') from None


class Hold(RuntimeError):
    pass

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Hold('Duplicate JSON key: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise Hold('Nonfinite JSON number')
    return json.loads(raw.decode('utf-8-sig') if isinstance(raw, bytes) else raw, object_pairs_hook=pairs, parse_constant=invalid)

def freeze(path, raw):
    path = pathlib.Path(path)
    # Fail closed with a named refusal instead of a long-path FileNotFoundError.
    if len(os.path.abspath(path)) > 259:
        raise Hold('Path exceeds MAX_PATH budget: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if path.read_bytes() != raw:
            raise Hold('Immutable artifact conflict: ' + str(path))
    return path

def encode(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode('utf-8')

class MailboxClient:
    """RPC accepts (operation, frozen request path); returns exact response bytes.

    A timed-out publication remains outstanding. Only reconcile() may fetch it;
    neither a new sequence nor a repeated relay can hide uncertainty.
    """
    def __init__(self, out, nonce, config_bytes, rpc):
        if not re.fullmatch('[0-9a-f]{64}', nonce):
            raise Hold('Invalid nonce')
        self.out = pathlib.Path(out)
        self.nonce = nonce
        self.config = strict(config_bytes)
        if self.config['nonce'] != nonce:
            raise Hold('Configuration nonce mismatch')
        self.config_hash = sha(config_bytes)
        freeze(self.out / 'config.json', config_bytes)
        self.rpc = rpc
        self.lock = threading.RLock()
        self.seq = 0
        self.pending = None
        self.ownerMayExist = False
        self.sealed = False
        self.attempted = set()
        self.manifest = {}
        self.responses = {}

    def proof(self, name, raw):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*', name):
            raise Hold('Invalid proof basename')
        freeze(self.out / 'proofs' / name, raw)
        ref = dict(name=name, sha256=sha(raw), length=len(raw))
        if name in self.manifest and self.manifest[name] != ref:
            raise Hold('Manifest conflict')
        self.manifest[name] = ref
        return ref

    def command(self, op, body):
        with self.lock:
            if self.pending is not None:
                raise Hold('Outstanding command requires read-only reconciliation')
            if op in ('launch', 'start', 'cleanup', 'seal-no-launch', 'exit-supervisor'):
                if op in self.attempted:
                    raise Hold('One-shot command already attempted')
                if op == 'launch' and self.sealed:
                    raise Hold('Run sealed against launch')
                self.attempted.add(op)
            self.seq += 1
            raw = encode(dict(schema='full300-owner-command-v1', nonce=self.nonce,
                              configSHA256=self.config_hash, seq=self.seq, op=op, body=body))
            path = freeze(self.out / 'commands' / ('%08d.json' % self.seq), raw)
            self.pending = (path, raw, op)
            self.pending_publication = None
            if op == 'launch':
                self.ownerMayExist = True
            before = time.monotonic_ns()
            self.pending_before = before
            response = self.rpc('submit', path)
            return self._receive(response, before)

    def reconcile(self):
        with self.lock:
            if self.pending is None:
                raise Hold('No outstanding command')
            return self._receive(self.rpc('fetch', self.pending[0]), time.monotonic_ns())

    def receive_original(self, raw):
        """Consume late bytes from the same resident operation, never fetch it."""
        with self.lock:
            if self.pending is None:raise Hold('No original mailbox command')
            return self._receive(raw,self.pending_before)

    def once(self, op, body):
        """Reuse an already accepted original command, not a replacement effect."""
        with self.lock:
            if op not in self.attempted:return self.command(op,body)
            if self.pending is not None:raise Hold('Original command still unresolved')
            response=self.responses.get(op)
            if response is None or response['outcome']!='accepted':raise Hold('Original command not accepted')
            command=strict((self.out/'commands'/('%08d.json'%response['seq'])).read_bytes())
            if encode(command['body'])!=encode(body) or command['op']!=op:
                raise Hold('Original command body changed')
            return response

    def _receive(self, raw, before):
        path, command, op = self.pending
        value = strict(raw)
        fields = {'schema','nonce','configSHA256','seq','commandSHA256','outcome','state','owner','refs','error'}
        if set(value) != fields or value['schema'] != 'full300-owner-response-v1':
            raise Hold('Response schema mismatch')
        for key, expected in dict(nonce=self.nonce, configSHA256=self.config_hash,
                                  seq=self.seq, commandSHA256=sha(command)).items():
            if value[key] != expected:
                raise Hold('Response binding mismatch: ' + key)
        if getattr(self,'pending_publication',None) is None:
            self.pending_publication=(raw,encode(dict(commandSHA256=sha(command),
                responseSHA256=sha(raw),beforeNS=str(before),afterNS=str(time.monotonic_ns()))))
        if self.pending_publication[0]!=raw:raise Hold('Original response changed during publication')
        freeze(self.out / 'responses' / path.name, raw)
        freeze(self.out / 'receipts' / path.name,self.pending_publication[1])
        if value['outcome'] not in ('accepted','rejected','hold'):
            raise Hold('Invalid response outcome')
        self.responses[op] = value
        self.pending = None
        if value['outcome'] != 'accepted':
            raise Hold('Supervisor refusal: ' + str(value['error']))
        if op == 'seal-no-launch':
            if value['state'] != 'SEALED_NO_LAUNCH':
                raise Hold('Seal not acknowledged')
            self.sealed = True
        return value

    def freeze_manifest(self):
        return freeze(self.out / 'manifest.json', encode(self.manifest))

class Adapter:
    """Stage integration; injectable RPC, collector, principal and wait boundaries."""
    def __init__(self, here, out, nonce, failure, *, rpc=None, collect=None,
                 principal=None, runner=None, pause=time.sleep, owner_path=None, owned_ps=None,
                 administrative_owner=None):
        self.here, self.out = pathlib.Path(here), pathlib.Path(out)
        self.root = self.out/'owner-transport'
        self.nonce, self.failure = nonce, failure
        self.runner, self.pause = runner or subprocess.run, pause
        self.rpc = rpc or PSDirectRPC(self.here/'protected-guest.ps1', nonce, self.runner)
        self.collector, self.principal = collect, principal
        self.owner_path = pathlib.Path(owner_path) if owner_path else self.here.parent/'native/full300-owner.exe'
        self.client = None
        self.preflight_attempted = False
        self.collections = 0
        self.native_event_prefix = b''
        self.journal_prefix = b''
        self.binding = None
        self.preparation_process = None
        self.owned_ps = owned_ps
        self.administrative_owner = administrative_owner

    def bind_preparation(self, process, command):
        """Bind the original Popen before accepting any early-stage receipt."""
        from cancellation import process_identity
        identity = process_identity(process)
        self.preparation_process = process  # Retain even if identity readback fails.
        if identity['startIdentityStatus'] != 'verified':
            raise Hold('Original preparation handle identity unavailable')
        source = (self.out/'preparation-source.ps1').read_bytes()
        if source != (self.here/'prepare-task.ps1').read_bytes():
            raise Hold('Preparation source changed during startup')
        self.preparation_start = encode(dict(schema='full300-preparation-start-v1', nonce=self.nonce,
            sourceSHA256=sha(source), commandSHA256=sha(encode(command)), pid=identity['pid'],
            creationFileTime=str(identity['startFiletime'])))
        freeze(self.out/'preparation-start.json', self.preparation_start)

    def _early_drain(self):
        # Selection is by positive executed receipt, not missing producer files.
        # No attempted native launch (even an uncertain one) uses this branch.
        if (self.preparation_process is None or self.preparation_process.poll() is not None
                or self.binding is not None or (self.client is not None and
                ('launch' in self.client.attempted or self.client.pending is not None))):
            raise Hold('Early drain requires retained inert preparation and no native launch attempt')
        source = (self.out/'preparation-source.ps1').read_bytes()
        if source != (self.here/'prepare-task.ps1').read_bytes():
            raise Hold('Early preparation source changed')
        return dict(wrapper=encode(dict(schema='full300-early-drain-v1', nonce=self.nonce)), files={},
            early=(self.out/'preparation-early-proof.json').read_bytes(), source=source,
            start=self.preparation_start, admissions=(self.out/'controller-admissions.json').read_bytes(),
            closures=(self.out/'controller-closures.json').read_bytes())

    def verify_preparation_exit(self):
        """Run only after control() observed the retained host exit, before teardown."""
        if not hasattr(self, 'early_drain'): return
        from protected_evidence import check_early_preparation_exit
        bundle = dict(self.early_drain,
            release=(self.out/'preparation-release.json').read_bytes(),
            cleanup=(self.out/'protected-cleanup.json').read_bytes(),
            closed=(self.out/'preparation-session-closed.json').read_bytes())
        if self.preparation_process is None or self.preparation_process.poll() is None:
            raise Hold('Original preparation host exit unproved')
        if check_early_preparation_exit(bundle, self.nonce)['status'] != 'PASS':
            raise Hold('Original preparation session release unproved')
        freeze(self.out/'preparation-host-exit.json', encode(dict(schema='full300-preparation-exit-v1',
            nonce=self.nonce, startSHA256=sha(self.preparation_start),
            sessionClosureSHA256=sha(bundle['closed']), waitResult='signalled',
            exitCode=self.preparation_process.returncode)))

    def _ps(self, script, *args, timeout=30):
        if self.owned_ps is not None:
            return self.owned_ps(script, args, timeout)
        exe = pathlib.Path('C:/Windows')/'System32/WindowsPowerShell/v1.0/powershell.exe'
        r = self.runner([str(exe),'-NoProfile','-NonInteractive','-WindowStyle','Hidden',
                         '-ExecutionPolicy','Bypass','-File',str(self.here/script),*args],
                        capture_output=True,timeout=timeout,check=False,env=_powershell_environment(exe))
        if r.returncode: raise Hold('Guest collection failed')
        return r.stdout.strip().decode('utf-8-sig').encode()

    def preflight(self, nonce, unused_hash=None):
        if nonce != self.nonce: raise Hold('Nonce mismatch')
        for d in ('deployment','proofs','samples','commands','responses','receipts'):
            (self.root/d).mkdir(parents=True, exist_ok=True)
        sid = self.principal() if self.principal else self._ps('protected-guest.ps1','-Operation','principal','-Nonce',nonce).decode().strip()
        if not re.fullmatch(r'S-1-5-21-(?:\d+-){2}\d+-\d+',sid): raise Hold('Invalid approved principal SID')
        sources = {n:(self.here/n).read_bytes() for n in ('owner-supervisor.ps1','owner-bindings.ps1','owner-mailbox.ps1','task-readback.ps1')}
        sources['full300-owner.exe'] = self.owner_path.read_bytes()
        ledger = []
        for n,b in sources.items():
            freeze(self.root/'deployment'/n,b)
            ledger.append(dict(name=n,sha256=sha(b),length=len(b)))
        lb = encode(dict(files=ledger)); freeze(self.root/'deployment.json',lb)
        config = dict(schema='full300-owner-config-v1',nonce=nonce,
            vm='<LAB_VM_ID>',guest='<LAB_GUEST_NAME>',
            principalName='<LAB_GUEST_NAME>\\test',principalSid=sid,
            taskName='BimeronFull300Owner-'+nonce,ownerSHA256=sha(sources['full300-owner.exe']),
            supervisorSHA256=sha(sources['owner-supervisor.ps1']),ledgerSHA256=sha(lb))
        self.client = MailboxClient(self.root,nonce,encode(config),self.rpc)
        self.preflight_attempted = True
        if self.administrative_owner is not None:
            self.administrative_owner.resources['originalRun']['supervisorAttempted']=True
            self.administrative_owner.journal.write('supervisor-attempt-reserved.json',encode(dict(nonce=nonce,configSHA256=self.client.config_hash)))
        once_raw = self.rpc('preflight',self.root/'config.json'); once = strict(once_raw)
        fields={'schema','nonce','configSHA256','instanceId','pid','creationFileTime','principalSid','sessionId','elevated'}
        if set(once)!=fields or once['schema']!='full300-supervisor-once-v1' or once['nonce']!=nonce or once['configSHA256']!=self.client.config_hash or once['principalSid']!=sid or once['elevated'] is not True or type(once['sessionId']) is not int or once['sessionId']<=0:
            raise Hold('Original supervisor attestation mismatch')
        self.client.proof('supervisor-once.json',once_raw)
        self.preflight_value=dict(config,configSHA256=self.client.config_hash,once=once_raw,probeSHA256=sha((self.here/'probe.ps1').read_bytes()))
        return self.preflight_value

    def _collect(self, capture=True, timeout=30):
        import base64
        if self.collector:
            v=self.collector(capture)
        else:
            raw=self._ps('guest-read.ps1','-Mode','integration','-Nonce',self.nonce,timeout=timeout)
            v=strict(raw)
            v['journal']=base64.b64decode(v.pop('probe'),validate=True)
            v['files']={n:base64.b64decode(b,validate=True) for n,b in v['files'].items()}
            v['bfe']=base64.b64decode(v['bfe'],validate=True)
            if capture:
                cfg=strict((self.out/'host-supervisor-config.json').read_bytes())
                args=cfg['query'][:-1]+['sudo cat /var/lib/step8/run-'+self.nonce+'/ingress.pcap']
                if self.administrative_owner is not None:
                    v['pcap']=self.administrative_owner.resources['original_remote_transport'](args,6)
                else:
                    r=self.runner(args,capture_output=True,timeout=6,check=False)
                    if r.returncode: raise Hold('Capture fetch failed')
                    v['pcap']=r.stdout
        if v['nonce']!=self.nonce: raise Hold('Collection nonce mismatch')
        if not v['journal'].startswith(self.journal_prefix): raise Hold('Producer journal prefix rewritten')
        self.journal_prefix=v['journal'][:v['journal'].rfind(b'\n')+1]
        self.collections+=1
        directory=self.out/('integration-%06d'%self.collections);directory.mkdir()
        for n,b in v['files'].items():
            if pathlib.Path(n).name!=n: raise Hold('Collection path')
            freeze(directory/n,b)
        for n in ('journal','pcap','bfe'):
            if n in v: freeze(directory/n,v[n])
        self.latest=v
        return v

    def wait_ready(self, failure):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            if failure.event.is_set(): raise Hold('Admission cancelled')
            try:
                v=self._collect(False)
                if all('reader-'+r+'-ready.json' in v['files'] for r in ('supervisor','collector','barrier')):
                    self.ready=v;return v
            except (FileNotFoundError, Hold):
                pass
            self.pause(.25)
        raise Hold('Reader admission deadline')

    def collect_controls(self):
        from protected_evidence import check_causal_admission
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            v=self._collect(timeout=max(.1,deadline-time.monotonic()));v['pin']=strict(v['files']['original-producer-pin.json'])
            assessment=check_causal_admission(v,self.preflight_value,self.ready,self.nonce)
            if assessment.get('admitted') is True:
                if time.monotonic()>deadline: raise Hold('Controls exceeded 60 seconds')
                break
            if self.failure.event.is_set(): raise Hold('Controls cancelled')
            self.pause(.25)
        else: raise Hold('Causal controls deadline: '+str(assessment['reasons']))
        self.controls=v
        p=self.client.proof
        pins=encode([dict(PID=x['pid'],CreationUTC=x['start'],Path=x['path'],SHA256=x['sha256'].lower()) for x in v['pin']['process']])
        admission=encode(dict(SHA256=self.client.config['ownerSHA256'],VM=self.client.config['vm'],Peer='<LAB_PUBLIC_IP>',Profile='Bimeron Step8',Nonce=self.nonce,ProducerPinSHA256=sha(pins)))
        wrapper=dict(schema='full300-launch-evidence-v1',nonce=self.nonce,configSHA256=self.client.config_hash,
            producerPin=p('original-producer-pin.json',v['files']['original-producer-pin.json']),
            readiness=p('readiness.json',encode(v['readiness'])),
            readerAdmissions=p('reader-admissions.json',encode({r:strict(self.ready['files']['reader-'+r+'-ready.json']) for r in ('supervisor','collector','barrier')})),
            controlsJournal=p('controls.jsonl',v['journal']),controlsCapture=p('controls.pcap',v['pcap']),
            controlsAssessment=p('controls-assessment.json',encode(assessment)),nativePinsSHA256=sha(pins),ownerSHA256=self.client.config['ownerSHA256'])
        self.launch_body=dict(admission=p('admission.json',admission),producerPins=p('producer-pins.json',pins),admissionEvidence=p('admission-evidence.json',encode(wrapper)))
        return v

    def _owner(self,response):
        owner=response['owner']
        if not isinstance(owner,dict) or set(owner)!={'pid','creationFileTime','path','sha256','handleState','exitCode'}:
            raise Hold('Original owner identity missing')
        if type(owner['pid']) is not int or owner['pid']<=0 or not re.fullmatch('[0-9]+',owner['creationFileTime']) or owner['sha256']!=self.client.config['ownerSHA256']:
            raise Hold('Original owner identity invalid')
        identity={k:owner[k] for k in ('pid','creationFileTime','path','sha256')}
        if hasattr(self,'owner_identity') and identity!=self.owner_identity: raise Hold('Original native owner replaced')
        self.owner_identity=identity

    def launch(self):
        if self.administrative_owner is not None:
            self.administrative_owner.resources['nativeLaunchAttempted']=True
        # Controls are already frozen/validated by both adapter and Stage.
        transition=encode(dict(schema='c1pe-transition-v1',nonce=self.nonce))
        path=freeze(self.out/'transition.json',transition)
        receipt=self._ps('protected-guest.ps1','-Operation','transition','-Nonce',self.nonce,'-RequestPath',str(path))
        if strict(receipt)!=dict(nonce=self.nonce,sha256=sha(transition),name='transition.json'): raise Hold('Transition publication mismatch')
        freeze(self.out/'transition-publication.json',receipt)
        response=self.client.command('launch',self.launch_body)
        self._owner(response)
        return response

    def _sample(self):
        r=self.client.command('sample',{})
        self._owner(r)
        files={}
        for ref in r['refs']:
            n=ref['name'];folder='samples' if re.match(r'^\d+-',n) else 'proofs'
            b=(self.root/folder/n).read_bytes()
            if len(b)!=ref['length'] or sha(b)!=ref['sha256']: raise Hold('Sample hash mismatch')
            files[re.sub(r'^\d+-','',n)]=b
        if 'events.jsonl' in files:
            if not files['events.jsonl'].startswith(self.native_event_prefix): raise Hold('Native event prefix rewritten')
            self.native_event_prefix=files['events.jsonl']
        return r,files

    def recover_binding(self):
        # A rejected launch is safe only after the original live supervisor seals
        # itself. A missing response, null owner alone, or timeout is not proof.
        if self.client.pending is not None:
            if self.client.pending[2] != 'launch':
                raise Hold('Unresolved command before binding recovery')
            try:
                self.client.reconcile()
            except Hold:
                if self.client.pending is not None:
                    raise
        rejection = self.client.responses.get('launch')
        if (rejection is not None and rejection['outcome'] == 'rejected'
                and rejection['state'] == 'READY' and rejection['owner'] is None):
            self._seal_no_launch()
            return None
        response,files=self._sample()
        binding=strict(files['gate-request.json'])
        expected=dict(SHA256=self.client.config['ownerSHA256'],Nonce=self.nonce,PolicySHA256=sha((sha(files['rules-bootstrap.json'])+'\n'+sha(files['guids.json'])).encode()))
        if binding!=expected: raise Hold('Partial launch binding mismatch')
        self.binding=binding;self.guids=files['guids.json']
        return binding

    def _seal_no_launch(self):
        if self.client.sealed:
            response = self.client.responses['seal-no-launch']
        else:
            response = self.client.command('seal-no-launch', {})
        raw = (self.root/'proofs/no-launch.json').read_bytes()
        proof = strict(raw)
        fields = {'schema','nonce','configSHA256','supervisorOnceSHA256',
                  'sealCommandSHA256','launchAttempted','sealed'}
        once = (self.root/'proofs/supervisor-once.json').read_bytes()
        expected = dict(schema='full300-no-launch-v1', nonce=self.nonce,
                        configSHA256=self.client.config_hash,
                        supervisorOnceSHA256=sha(once),
                        sealCommandSHA256=response['commandSHA256'],
                        launchAttempted=False, sealed=True)
        ref = dict(name='no-launch.json', sha256=sha(raw), length=len(raw))
        if (set(proof) != fields or proof != expected
                or proof['launchAttempted'] is not False or proof['sealed'] is not True
                or response['state'] != 'SEALED_NO_LAUNCH'
                or response['owner'] is not None or ref not in response['refs']):
            raise Hold('Original supervisor no-launch seal unproven')
        return raw

    def policy(self):
        deadline=time.monotonic()+20
        required=('bfe-bootstrap.xml','rules-bootstrap.json','guids.json','gate-request.json')
        while time.monotonic()<deadline:
            response,files=self._sample()
            if all(n in files for n in required): break
            self.pause(.25)
        else: raise Hold('Native bootstrap incomplete')
        from protected_evidence import check_policy
        assessment=check_policy(files[required[0]],files[required[1]],guids_json=files[required[2]])
        if assessment['status']!='PASS': raise Hold('Policy refused')
        self.binding=strict(files['gate-request.json']);self.guids=files['guids.json']
        p=self.client.proof
        refs={k:p(n,files[src]) for k,n,src in zip(('bfe','rules','guids','gate'),('bfe.xml','rules.json','guids.json','gate.json'),required)}
        wrapper=dict(schema='full300-policy-evidence-v1',nonce=self.nonce,configSHA256=self.client.config_hash,binding=self.binding,**refs,assessment=p('policy-assessment.json',encode(assessment)))
        self.policy_ref=p('policy-evidence.json',encode(wrapper))
        v=self._collect(False)
        return dict(zip(('bfe_path','rules_path','guids_path','gate_request'),[self.root/'proofs'/refs[k]['name'] for k in ('bfe','rules','guids','gate')]),collection=v,response=response)

    def barrier(self, binding):
        if hasattr(self,'start_ack'): return self._challenge_fence(binding)
        from records import snapshot
        v=self._collect(False);pin=self.controls['pin'];log=snapshot(v['journal'],self.nonce,pin['producer'])
        if not log['records'] or log['partialBytes']: raise Hold('Incomplete journal fence')
        raw=encode(dict(nonce=self.nonce,probeSHA256=sha(v['journal']),gateSHA256=sha((self.root/'proofs/gate.json').read_bytes()),sequence=log['records'][-1]['sequence'],round=log['records'][-1]['round']))
        path=freeze(self.out/('barrier-%06d.json'%self.collections),raw)
        jp=freeze(self.out/('barrier-%06d.jsonl'%self.collections),v['journal'])
        if not hasattr(self,'barrier_ref'):
            p=self.client.proof
            wrapper=dict(schema='full300-barrier-evidence-v1',nonce=self.nonce,configSHA256=self.client.config_hash,binding=binding,
                metadata=p('barrier.json',raw),journal=p('barrier-journal.jsonl',v['journal']),producerPin=self.client.manifest['original-producer-pin.json'])
            self.barrier_ref=p('barrier-evidence.json',encode(wrapper))
        if hasattr(self,'start_ack'):
            self.cutoff=dict(sequence=log['records'][-1]['sequence'],round=max(r['round'] for r in log['records']))
            self.fence_prefix=v['journal']
        return dict(path=path,journal_path=jp)

    def _challenge_fence(self, binding):
        from records import snapshot
        from preexisting import validate_fence
        from protected_evidence import check_start_ack
        import secrets, uuid
        if hasattr(self,'challenge_raw'): raise Hold('One-shot challenge already attempted')
        if check_start_ack(self.start_ack,binding)['status']!='PASS': raise Hold('Challenge before acknowledged start')
        # Generated here, only after policy() and acknowledged start(); never launch input.
        measurement=secrets.token_hex(32)
        if measurement==self.nonce: raise Hold('Nonce collision')
        self.ack_raw=encode(dict(response=self.start_ack['response'],relay=self.start_ack['relay'],
            native_status=self.start_ack['native_status'].decode(),native_events=self.start_ack['native_events'].decode()))
        freeze(self.out/'challenge-ack.json',self.ack_raw)
        self.challenge_raw=encode(dict(schema='c1pe-challenge-v1',nonce=self.nonce,measurementNonce=measurement,
            requestId=uuid.uuid4().hex,producerPinSHA256=sha(self.controls['files']['original-producer-pin.json']),
            producer=self.controls['pin']['producer'],owner=self.owner_identity,policySHA256=binding['PolicySHA256'],ackSHA256=sha(self.ack_raw)))
        path=freeze(self.out/'post-arm.json',self.challenge_raw)
        before=time.monotonic_ns();deadline=time.monotonic()+20
        receipt=self._ps('protected-guest.ps1','-Operation','challenge','-Nonce',self.nonce,'-RequestPath',str(path),timeout=max(.1,deadline-time.monotonic()))
        if strict(receipt)!=dict(nonce=self.nonce,sha256=sha(self.challenge_raw),name='post-arm.json'): raise Hold('Challenge publication mismatch')
        freeze(self.out/'challenge-publication.json',receipt)
        while time.monotonic()<deadline:
            v=self._collect(False,timeout=max(.1,deadline-time.monotonic()));log=snapshot(v['journal'],self.nonce,self.controls['pin']['producer'])
            if any(r['kind']=='post-arm-fence' for r in log['records']): break
            self.pause(.1)
        else: raise Hold('Challenge receipt deadline')
        if time.monotonic()>deadline: raise Hold('Challenge publication/receipt exceeded 20 seconds')
        fence=validate_fence(self.challenge_raw,log['records'],self.nonce,self.controls['files']['original-producer-pin.json'],binding['PolicySHA256'],self.ack_raw,self.owner_identity)
        # Freeze exactly through the producer receipt, not a later controller snapshot.
        prefix=b''.join(v['journal'].splitlines(keepends=True)[:fence['sequence']])
        self.fence_prefix=prefix;self.cutoff={k:fence[k] for k in ('sequence','round')}
        raw=encode(dict(nonce=self.nonce,probeSHA256=sha(prefix),gateSHA256=sha((self.root/'proofs/gate.json').read_bytes()),
            **self.cutoff,challengeSHA256=sha(self.challenge_raw),publicationSHA256=sha(receipt),ackSHA256=sha(self.ack_raw),beforeNS=str(before),afterNS=str(time.monotonic_ns())))
        path=freeze(self.out/('barrier-%06d.json'%self.collections),raw)
        jp=freeze(self.out/('barrier-%06d.jsonl'%self.collections),prefix)
        return dict(path=path,journal_path=jp,challenge=self.challenge_raw,ack=self.ack_raw,publication=receipt,owner=self.owner_identity)

    def start(self, request):
        response=self.client.command('start',dict(request=self.client.proof('start-observation.json',encode(request)),policyEvidence=self.policy_ref,barrierEvidence=self.barrier_ref))
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            sample,files=self._sample()
            if 'gate-status.json' in files and strict(files['gate-status.json'])['State']=='OBSERVING':
                self.start_ack=dict(response=sample,native_status=files['gate-status.json'],native_events=files['events.jsonl'],relay=response)
                return self.start_ack
            self.pause(.25)
        raise Hold('Native start acknowledgement absent')

    def observe(self, binding, failure):
        deadline=time.monotonic()+360
        while time.monotonic()<deadline:
            v=self._collect();r,f=self._sample()
            v.update(response=r,native_status=strict(f['gate-status.json']),native_status_bytes=f['gate-status.json'],native_events=f['events.jsonl'],start_ack=self.start_ack)
            yield v
            if v['native_status']['Completed300']: return
            if failure.event.is_set(): return
            self.pause(1)
        raise Hold('Observation watchdog')

    def verify_drain(self, nonce):
        from protected_evidence import check_exact_drain
        if (self.out/'preparation-early-proof.json').is_file():
            bundle = self._early_drain()
            assessment = check_exact_drain(bundle, nonce)
            if assessment['status'] != 'PASS': raise Hold('Executed early preparation drain refused: '+str(assessment['reasons']))
            self.early_drain = self.prelaunch_drain = bundle
            return bundle
        v=self._collect()
        if 'original-producer-pin.json' not in v['files']:
            admissions=(self.out/'controller-admissions.json').read_bytes()
            bundle=dict(wrapper=encode(dict(schema='full300-prelaunch-drain-v1',nonce=nonce)),files=v['files'],admissions=admissions,task=encode(v['task']))
            if check_exact_drain(bundle,nonce)['status']!='PASS': raise Hold('Prelaunch drain refused')
            self.prelaunch_drain=bundle
            return bundle
        if self.client is None:
            self.client=MailboxClient(self.root,self.nonce,encode(dict(nonce=self.nonce)),self.rpc)
        p=self.client.proof
        if self.binding is not None and hasattr(self,'cutoff'):
            from protected_evidence import assess_causal_escape
            response,files=self._sample()
            v.update(response=response,native_status=strict(files['gate-status.json']),native_status_bytes=files['gate-status.json'],native_events=files['events.jsonl'],start_ack=self.start_ack)
            from protected_evidence import check_observation_lifecycle
            if check_observation_lifecycle(v,self.binding,operational=False)['status']!='PASS': raise Hold('Post-drain original owner proof failed')
            self.live_owner_sample = dict(response['owner'])
            freeze(self.out/'post-drain-sample.json',encode(dict(schema='c1pe-post-drain-v1',nonce=nonce,
                sequence=response['seq'],terminalSHA256=sha(v['journal']),files={n:sha(b) for n,b in v['files'].items()},
                statusSHA256=sha(files['gate-status.json']),eventsSHA256=sha(files['events.jsonl']))))
            self.drain_measurement=assess_causal_escape(v,self.controls,self.binding,self.cutoff,self.fence_prefix)
            freeze(self.out/'drain-measurement.json',encode(self.drain_measurement))
            if self.drain_measurement['status']=='FAIL': self.failure.set('CAUSAL_ORDINARY_ESCAPE')
        for n,b in v['files'].items():
            if n not in ('registration.json',) and not n.startswith('reader-'): p(n,b)
        p('terminal.jsonl',v['journal']);p('registration.json',v['files']['registration.json'])
        task=dict(v['task'],registration=self.client.manifest['registration.json'])
        p('task-readback.json',encode(task))
        admissions=(self.out/'controller-admissions.json').read_bytes()
        closures=(self.out/'controller-closures.json').read_bytes()
        for entry in strict(closures)['bundle']['entries']:
            name=entry['closed']['name']
            import base64
            if strict(v['files'][name]) != strict(base64.b64decode(strict(closures)['artifacts'][name])): raise Hold('Guest/controller closure disagreement')
        for n,b in strict(closures)['artifacts'].items():
            import base64
            p(n,base64.b64decode(b,validate=True))
        p('admissions.json',admissions);p('reader-closures.json',encode(strict(closures)['bundle']))
        refs=self.client.manifest
        task_wrapper=dict(schema='full300-task-closure-v1',nonce=nonce,**{k:refs[n] for k,n in dict(expected='expected.json',launch='launch.json',producerPin='original-producer-pin.json',inspectorFinal='inspector-final.json',inspectorExit='inspector-exit-proof.json',taskReadback='task-readback.json',terminalJournal='terminal.jsonl').items()},stopRequest=refs.get('stop-request.json'))
        p('task-closure.json',encode(task_wrapper))
        wrapper=dict(schema='full300-drain-v1',nonce=nonce,configSHA256=self.client.config_hash,binding=self.binding,
            **{k:refs[n] for k,n in dict(admissions='admissions.json',readerClosures='reader-closures.json',taskClosure='task-closure.json',inspectorExit='inspector-exit-proof.json',inspectorFinal='inspector-final.json',producerPin='original-producer-pin.json',terminalJournal='terminal.jsonl').items()},stopRequest=refs.get('stop-request.json'))
        bundle=dict(wrapper=encode(wrapper),files={n:(self.root/'proofs'/n).read_bytes() for n in refs})
        if check_exact_drain(bundle,nonce)['status']!='PASS': raise Hold('Exact drain refused')
        self.prelaunch_drain=bundle
        self.drain_ref=p('drain.json',bundle['wrapper'])
        self.live_ready = self.binding is not None and hasattr(self, 'drain_measurement')
        return bundle

    def cleanup(self, request):
        if type(request.get('Failure')) is not bool:
            raise Hold('Cleanup requires explicit boolean Failure')
        if getattr(self, '_cleanup_sent', False):
            return self.client.once('cleanup',dict(request=self.client.proof('cleanup-request.json',encode(request)),drain=self.drain_ref))
        self._cleanup_sent = True
        if not request.get('Failure', True):
            if not getattr(self, 'live_ready', False):
                raise Hold('Live preparation requires verified original drain and owner sample')
            from live_prepare import prepare_live
            if self.administrative_owner is not None:
                self.administrative_owner.resources['originalRun']['stockDeploymentAttempted']=True
                self.administrative_owner.journal.write('stock-boundary-reserved.json',encode(dict(nonce=self.nonce)))
            owner = getattr(self, 'administrative_owner', None)
            if owner is None or 'ssh' not in owner.resources:
                raise Hold('Pinned ssh executable required for live preparation')
            admission = prepare_live(dict(self.binding), self.nonce, dict(self.live_owner_sample),
                                     ssh=owner.resources['ssh'][0], out=self.out)
            from stock_controller import validate_receipt
            validate_receipt(admission, self.binding, self.nonce)
            self.stock_administrative_receipt = admission
        return self.client.command('cleanup',dict(request=self.client.proof('cleanup-request.json',encode(request)),drain=self.drain_ref))

    def can_reuse_cleanup(self):
        return self.client is not None and self.client.pending is None and self.client.responses.get('cleanup',{}).get('outcome')=='accepted'

    def stock_finalize(self, final, checked):
        if not hasattr(self, 'stock_administrative_receipt'):
            return
        from stock_controller import finalize_controller
        self.stock_outcome = finalize_controller(self.binding, self.nonce, final, checked, self.out)
        raw = self.stock_outcome['rawUiOutcome']
        self.stock_establishment = ('NOT_ATTEMPTED' if self.stock_outcome['schema'] in ('stock-no-launch-final-v1','stock-no-permit-receipt-v1')
            else 'UNKNOWN' if raw['state'] == 'unknown'
            else 'RETURNED_SUCCESS' if raw['BOOL'] == 1 and raw['dwError'] == 0 else 'RETURNED_FAILURE')
        freeze(self.out/'stock-administrative-provenance.json', encode(self.stock_outcome))

    def final(self, binding):
        if not self.preflight_attempted:
            proof=encode(dict(schema='full300-no-supervisor-attempt-v1',nonce=self.nonce))
            freeze(self.out/'no-supervisor-attempt.json',proof)
            v=self._collect(False)
            return dict(proof=proof,nonce=self.nonce,ras=v['ras'],bfe=v['bfe'],prelaunch_drain=self.prelaunch_drain)
        if binding is None:
            self._seal_no_launch()
            proof='no-launch.json';key='noLaunch'
        elif getattr(self,'final_owner_proof',None) is not None:
            proof='owner-exit.json';key='ownerExit'
        else:
            deadline=time.monotonic()+150
            while time.monotonic()<deadline:
                r,files=self._sample()
                if 'owner-exit.json' in files: break
                self.pause(.25)
            else: raise Hold('Retained owner exit unavailable')
            proof='owner-exit.json';key='ownerExit'
        b=(self.root/'proofs'/proof).read_bytes()
        if binding is not None:
            if getattr(self,'final_owner_proof',b)!=b:raise Hold('Original final proof changed')
            self.final_owner_proof=b
        response=self.client.once('exit-supervisor',{key:self.client.proof(proof,b)})
        v=self._collect(False)
        self.client.freeze_manifest()
        return dict(proof=b,response=response,once=(self.root/'proofs/supervisor-once.json').read_bytes(),owner_identity=getattr(self,'owner_identity',None),task_instance=(self.root/'task-instance.json').read_bytes(),task_final=(self.root/'task-final.json').read_bytes(),
            task_registration=(self.root/'task-registration.json').read_bytes(),
            exit_ready=(self.root/'proofs/supervisor-exit-ready.json').read_bytes(),
            bfe=v['bfe'],guids=getattr(self,'guids',None),ras=v['ras'],nonce=self.nonce,
            files={n.name:n.read_bytes() for n in (self.root/'samples').iterdir()})

validate_drain_bundle = lambda bundle, nonce: __import__('protected_evidence').check_exact_drain(bundle,nonce)

