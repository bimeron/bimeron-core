"""Protected controller; construction never executes native code.

Adapter contract: policy returns bfe_path/rules_path/guids_path/gate_request
(paths, read once). barrier returns path and journal_path. start returns bound
acknowledgement followed by a barrier-shaped fence. observe yields immutable
collections, never a summary boolean. Proof bundles use artifacts (digest:bytes)
and refs (name:digest); causal admission, lifecycle, drain and absence validators
must recompute raw facts in protected_evidence. Missing validators refuse safely.
No adapter-supplied verified flag grants authority.
"""
import hashlib
import importlib
import json
import pathlib
import re
import threading
import time
from cancellation import publish_once
from records import snapshot, unique

# Executable binding is derived from preflight bytes, never a release constant.
class Hold(RuntimeError): pass

def require(condition, message):
    if not condition: raise Hold(message)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(path): return sha(pathlib.Path(path).read_bytes())
def decode(raw): return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)

class Stage:
    def __init__(self, here, out, nonce, failure, adapter=None, evidence=None):
        require(re.fullmatch('[0-9a-f]{64}', nonce) is not None, 'Invalid nonce')
        self.here, self.out = pathlib.Path(here), pathlib.Path(out)
        self.nonce, self.failure = nonce, failure
        self.adapter, self.evidence = adapter, evidence
        self.thread = None
        self.binding = None
        self.ownerMayExist = False
        self.observationCompleted = False
        self.lifecycle = 'NEW'
        self.measurement = dict(status='INCONCLUSIVE', reasons=['CLOCK_BOUND_UNPROVEN'])
        self.executionFailure = self.cleanupFailure = self.error = None
        self.cleanupAttempted = False
        self.restorationAllowed = False
        self.prefix = b''
        self.raw = {}

    def start(self):
        require(self.thread is None, 'Stage already started')
        self.thread = threading.Thread(target=self._run, name='protected-stage', daemon=True)
        self.thread.start()

    def _pass(self, value, name):
        require(isinstance(value, dict) and value.get('status') == 'PASS', name+' not proven')
        return value

    def _validate(self, name, *args):
        fn = getattr(self.evidence, name, None)
        require(callable(fn), 'Missing raw evidence validator: '+name)
        return fn(*args)

    def _freeze(self, name, raw):
        require(isinstance(raw, bytes), 'Expected immutable bytes: '+name)
        path = self.out/('protected-'+name)
        with path.open('xb') as stream: stream.write(raw)
        self.raw[name] = raw
        return sha(raw)

    def _record_result(self, name):
        self._freeze(name, json.dumps(dict(schema='full300-protected-result-v1', nonce=self.nonce,
            measurement=self.measurement, lifecycle=self.lifecycle,
            observationCompleted=self.observationCompleted,
            executionFailure=str(self.executionFailure) if self.executionFailure is not None else None,
            cleanupFailure=str(self.cleanupFailure) if self.cleanupFailure is not None else None,
            liveOutcome=getattr(self.adapter, 'live_outcome', None),
            stockOutcome=getattr(self.adapter, 'stock_outcome', None),
            stockEstablishment=getattr(self.adapter, 'stock_establishment', None),
            restorationAllowed=self.restorationAllowed), allow_nan=False).encode())

    def _fence(self, value, pin, gate):
        raw = pathlib.Path(value['path']).read_bytes()
        journal = pathlib.Path(value['journal_path']).read_bytes()
        meta = decode(raw)
        parsed = snapshot(journal, self.nonce, pin['producer'])
        require(parsed['records'] and not parsed['partialBytes'], 'Incomplete barrier prefix')
        require(journal.startswith(self.prefix), 'Journal prefix rewritten')
        require(meta['nonce'] == self.nonce and meta['probeSHA256'] == sha(journal)
                and meta['gateSHA256'] == sha(gate)
                and meta['sequence'] == parsed['records'][-1]['sequence']
                and meta['round'] == parsed['records'][-1]['round'], 'Barrier binding mismatch')
        if 'challengeSHA256' in meta:
            from preexisting import validate_fence
            receipt=validate_fence(value['challenge'],parsed['records'],self.nonce,
                self.adapter.controls['files']['original-producer-pin.json'],self.binding['PolicySHA256'],value['ack'],value['owner'])
            require(receipt['sequence']==meta['sequence'] and meta['challengeSHA256']==sha(value['challenge']) and meta['ackSHA256']==sha(value['ack']) and meta['publicationSHA256']==sha(value['publication']), 'Fresh fence binding')
            require(0<=int(meta['afterNS'])-int(meta['beforeNS'])<=20000000000,'Challenge deadline')
        elif hasattr(self.adapter,'start_ack'):
            raise Hold('Post-ack producer challenge required')
        self.prefix = journal
        return raw, dict(sequence=meta['sequence'], round=max(r['round'] for r in parsed['records']))

    def _measurement(self, value):
        require(value.get('status') in ('PASS', 'FAIL', 'INCONCLUSIVE'), 'Invalid measurement schema')
        if self.measurement['status'] == 'FAIL': return
        if value['status'] == 'FAIL':
            self.measurement = value
            raise Hold('CAUSAL_ORDINARY_ESCAPE')
        self.measurement = dict(value, status='INCONCLUSIVE', reasons=list(dict.fromkeys(
            value.get('reasons', [])+['CLOCK_BOUND_UNPROVEN'])))

    def _run(self):
        try:
            require(self.adapter is not None, 'Missing reviewed protected transport adapter')
            self.evidence = self.evidence or importlib.import_module('protected_evidence')
            a = self.adapter
            self.lifecycle = 'ADMISSION'
            preflight = a.preflight(self.nonce, None)
            self.owner_hash = preflight['ownerSHA256']
            ready = a.wait_ready(self.failure)
            controls = a.collect_controls()
            # Host receives and freezes controls before any possible launch.
            self._freeze('controls.pcap', controls['pcap'])
            self._freeze('controls.jsonl', controls['journal'])
            self.prefix=controls['journal']
            admission = self._validate('check_causal_admission', controls, preflight, ready, self.nonce)
            require(admission.get('schema') == 'full300-admission-v1'
                    and admission.get('admitted') is True, 'Causal execution admission unproven')
            require(not self.failure.event.is_set(), 'Failure before admission')
            self._freeze('launch-intent.json', json.dumps(dict(nonce=self.nonce)).encode())
            self.ownerMayExist = True
            self.lifecycle = 'LAUNCHING'
            a.launch()  # Never retry an uncertain launch.
            policy = a.policy()
            bfe, rules, guids, gate = [pathlib.Path(policy[k]).read_bytes() for k in
                                      ('bfe_path','rules_path','guids_path','gate_request')]
            for name, raw in [('bfe.xml',bfe),('rules.json',rules),('guids.json',guids),('gate.json',gate)]:
                self._freeze(name, raw)
            self._pass(self.evidence.check_policy(bfe, rules, guids_json=guids), 'Independent policy')
            self.binding = dict(SHA256=self.owner_hash, Nonce=self.nonce,
                                PolicySHA256=sha((sha(rules)+'\n'+sha(guids)).encode()))
            require(decode(gate) == self.binding, 'Native binding mismatch')
            barrier, _ = self._fence(a.barrier(self.binding), controls['pin'], gate)
            self._freeze('barrier.json', barrier)
            self._pass(self._validate('check_start_lifecycle', policy, ready, self.binding), 'Start lifecycle/budget')
            deadline = time.monotonic()+360
            ack = a.start(dict(self.binding, BFESHA256=sha(bfe), BarrierSHA256=sha(barrier)))
            self._pass(self._validate('check_start_ack', ack, self.binding), 'Native acknowledgement')
            fence, cutoff = self._fence(a.barrier(self.binding), controls['pin'], gate)
            self._freeze('postack-fence.json', fence)
            self.lifecycle = 'OBSERVING'
            for index, interval in enumerate(a.observe(self.binding, self.failure)):
                require(time.monotonic() <= deadline, 'Observation watchdog expired')
                require(not self.failure.event.is_set(), 'Independent lifecycle failure')
                self._freeze('capture-%d.pcap'%index, interval['pcap'])
                self._freeze('journal-%d.jsonl'%index, interval['journal'])
                self._measurement(self._validate('assess_causal_escape', interval, controls, self.binding, cutoff, self.prefix))
                self._pass(self._validate('check_observation_lifecycle', interval, self.binding), 'Observation lifecycle')
                status = interval['native_status']
                require(all(status[k] == v for k,v in self.binding.items()), 'Status binding mismatch')
                require(not status['Errors'], 'Sticky native error')
                if status['Completed300'] is True:
                    require(type(status['ElapsedNS']) is int and status['ElapsedNS'] >= 300000000000, 'Short native interval')
                    # Native completion hands off to natural drain; supplemental
                    # acceptance uses the final producer interval, never this timer.
                    self.observationCompleted = True
                    self.lifecycle = 'AWAITING_NATURAL_DRAIN'
                    return
            raise Hold('Observation ended without native completion')
        except Exception as exc:
            self.error = self.executionFailure = exc
            self.lifecycle = 'ABORTED'
            self.failure.set(exc)
            self._record_result('failure.json')

    def before_restore(self):
        """Never retry cleanup publication; unproved drain retains protection."""
        try:
            if self.restorationAllowed: return
            require(self.thread is not None, 'Stage never started')
            self.thread.join(timeout=1)
            require(not self.thread.is_alive(), 'Stage still observing')
            require(self.adapter is not None, 'Missing adapter')
            self.evidence = self.evidence or importlib.import_module('protected_evidence')
            if self.ownerMayExist and self.binding is None and hasattr(self.adapter,'recover_binding'):
                self.binding=self.adapter.recover_binding()
                # Only the adapter's validated original-supervisor seal permits
                # recovery without a native binding; uncertainty still raises.
                if self.binding is None:
                    self.ownerMayExist = False
            proof = getattr(self,'administrative_drain',None)
            if proof is None:proof = self.adapter.verify_drain(self.nonce)
            latest=getattr(self.adapter,'drain_measurement',None)
            if latest and latest.get('status')=='FAIL':
                self.measurement=latest
                self.executionFailure=Hold('CAUSAL_ORDINARY_ESCAPE')
            validated = self._pass(self._validate('check_exact_drain', proof, self.nonce), 'Exact drain')
            self.administrative_drain=proof
            early = decode(proof['wrapper']).get('schema') == 'full300-early-drain-v1' if 'wrapper' in proof else False
            if early:
                require(not self.ownerMayExist and self.binding is None, 'Early drain cannot release a native owner')
            # Validator returns hashes only after checking all admitted readers,
            # retained two producer handles, inspector, task and cancellation.
            refs = validated['refs']
            if self.ownerMayExist:
                require(self.binding is not None, 'Uncertain partial launch: HOLD')
                require(not self.cleanupAttempted or getattr(self.adapter,'can_reuse_cleanup',lambda:False)(),
                        'Cleanup already attempted: collect original response')
                require(self.observationCompleted or self.executionFailure is not None or self.failure.event.is_set(), 'Observation incomplete')
                request = dict(self.binding, Failure=bool(self.executionFailure or self.failure.event.is_set()),
                               ReaderClosureSHA256=refs['readerClosure'], TaskClosureSHA256=refs['taskClosure'])
                for key in ('ReaderClosureSHA256','TaskClosureSHA256'):
                    require(re.fullmatch('[a-f0-9]{64}', request[key]) is not None, 'Invalid closure digest')
                self.cleanupAttempted = True
                self.adapter.cleanup(request)
            final = getattr(self,'administrative_absence',None)
            if final is None:final = self.adapter.final(self.binding)
            checked = self._pass(self._validate('check_independent_absence', final, self.binding, self.nonce), 'Independent absence')
            require(all(checked.get(k) is True for k in ('rasAbsent','ownerAbsent','taskReady')), 'Restoration prerequisites missing')
            self.administrative_absence=final
            if hasattr(self.adapter, 'stock_finalize'):
                self.adapter.stock_finalize(final, checked)
            if getattr(self.adapter, 'stock_establishment', None) in ('UNKNOWN', 'RETURNED_FAILURE', 'NOT_ATTEMPTED'):
                self.executionFailure = self.executionFailure or Hold('Stock UI unsuccessful or unknown; administrative restoration is separate')
            live = getattr(self.adapter, 'live_outcome', None)
            if live is not None and live['establishment'] != 'PASS':
                self.executionFailure = self.executionFailure or Hold('Live establishment failed; restoration is separate')
            publish_once(self.out/'protected-cleanup.json', dict(nonce=self.nonce,
                         rasAbsent=True, ownerAbsent=True, taskReady=True,
                         drainRefs=refs, absenceRefs=checked['refs']))
            if early:
                publish_once(self.out/'preparation-release.json', dict(schema='full300-preparation-release-v1',
                    nonce=self.nonce, earlySHA256=sha(proof['early']),
                    cleanupSHA256=digest(self.out/'protected-cleanup.json')))
            self.restorationAllowed = True
            self.lifecycle = 'RESTORATION_ALLOWED'
            self._record_result('result.json')
        except Exception as exc:
            self.cleanupFailure = exc
            self.lifecycle = 'HOLD'
            self.failure.set(exc)
            raise
