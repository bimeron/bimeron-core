"""Fresh-run original-owner administrative protocol; no operational imports.

The caller owns admission and retained resources. Persistence is append-only;
neither a new instance nor a receipt can adopt another instance's authority.
"""
import hashlib
import json
import os
import pathlib
import re
import secrets
import threading
import time
import unicodedata


class Hold(RuntimeError):
    pass


class Pending(OSError):
    """A request slot that is not readable yet (still open for write or growing).

    Transient by contract: the endpoint retries on its next tick and never
    publishes a rejection for it.
    """


def reason_text(value, limit=512):
    """Bounded single-line diagnostic text; control characters removed."""
    text = ''.join(' ' if unicodedata.category(c).startswith('C') else c for c in str(value)).strip()
    return text[:limit]


def require(value, reason):
    if not value:
        raise Hold(reason)


# Windows MAX_PATH without LongPathsEnabled: a full path (drive, separators and
# name, without the terminating NUL) must fit in 259 characters. Nothing here
# relies on the long-path opt-in of the interpreter or the host policy.
MAX_PATH_CHARS = 259
# Atomic publication temporaries: same directory, fixed short name that does
# not grow with the target name ('.' + 8 hex + '.tmp').
TEMPORARY_NAME_CHARS = 13
# Private run root name; the full nonce stays bound in owner-created.json and
# run-identity.json, the directory name is derived from it.
def private_root_name(nonce):
    digest(nonce)
    return 'cp-' + nonce[:16]


def bound_private_root(path, nonce):
    """An existing private run root whose run-identity.json binds nonce and name."""
    path = pathlib.Path(path)
    digest(nonce)
    value = decode((path / 'run-identity.json').read_bytes())
    require(value == dict(schema='fresh-admin-run-identity-v1', nonce=nonce, rootName=path.name),
            'Private run identity binding')
    return path
# Deepest relative paths a fresh administrative run creates or publishes under
# its private root (fixed templates at their widest counters). Guest archive and
# settlement proof entries have dynamic names; each reserves a 64-character
# basename here and is additionally refused at write time by require_path.
RUN_PATH_INVENTORY = (
    'owner-transport/rpc-evidence/999999-submit/transport-999-rpc.observer-exit.json',
    'owner-transport/rpc-evidence/999999-submit/fetch-admission.json',
    'owner-transport/proofs/supervisor-exit-ready.json',
    'owner-transport/responses/99999999.json',
    'watcher-query-999999/transport-999-capture-status.observer-exit.json',
    'original-transport-999999/transport-999-original.observer-exit.json',
    'guest-control/resident-reserved-99999999999999999999.json',
    'guest-control/resident-response-99999999999999999999.json',
    'settlement-inputs/settlement-confirmed.json',
    'settlement-validated/' + 'n' * 64,
    'integration-999999/' + 'n' * 64,
    'preparation/guest/logs/' + 'n' * 64,
    'administrative-bootstrap-aborted.json',
    'administrative-watcher-closed.json',
    'administrative-watcher-context.json',
    'administrative-watcher-request.json',
    'stock-administrative-provenance.json',
    'transport-resolution-999999.json',
    'independent-capture-health.jsonl',
    'independent-query-errors.jsonl',
    'independent-tick-errors.jsonl',
)


def full_path_length(path):
    return len(os.path.abspath(os.fspath(path)))


def require_path(path):
    """Refuse a create/publish path that Windows cannot open without long paths."""
    length = full_path_length(path)
    require(length <= MAX_PATH_CHARS, 'Path exceeds MAX_PATH budget (%d > %d)' % (length, MAX_PATH_CHARS))
    return path


def run_path_budget(root):
    """Longest full path (length, relative path) a run under root would use."""
    root = os.path.abspath(os.fspath(root))
    best = (len(root), '')
    for relative in RUN_PATH_INVENTORY:
        parts = relative.split('/')
        for depth in range(1, len(parts) + 1):
            entry = os.path.join(root, *parts[:depth])
            best = max(best, (len(entry), '/'.join(parts[:depth])))
            # A same-directory publication temporary beside every entry.
            best = max(best, (len(os.path.dirname(entry)) + 1 + TEMPORARY_NAME_CHARS,
                              '/'.join(parts[:depth - 1] + ['.xxxxxxxx.tmp'])))
    return best


def require_run_path_budget(root):
    """Admission-time refusal before the private root exists."""
    length, relative = run_path_budget(root)
    require(length <= MAX_PATH_CHARS,
            'Run path budget exceeded: %d > %d (%s)' % (length, MAX_PATH_CHARS, relative))
    return length


def short_temporary(path):
    """Exclusive short temporary beside path; returns the open binary stream."""
    path = pathlib.Path(path)
    for _ in range(4):
        temporary = path.with_name('.' + secrets.token_hex(4) + '.tmp')
        require_path(temporary)
        try:
            return temporary, temporary.open('xb')
        except FileExistsError:
            continue
    raise Hold('Publication temporary name collision')


def publish_exclusive(path, raw, conflict='Publication conflict'):
    """Atomic create-once publication: a poller sees no file or the whole file.

    Bytes go to a short same-directory temporary, are flushed and fsynced, then
    hard-linked to the final name, which never replaces an existing file.
    Identical existing bytes are idempotent; different bytes are refused.
    """
    path = require_path(pathlib.Path(path))
    require(type(raw) is bytes, 'Publication bytes')
    if path.exists():
        require(path.read_bytes() == raw, conflict)
        return
    temporary, stream = short_temporary(path)
    try:
        with stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        temporary.unlink(missing_ok=True)
    require(path.read_bytes() == raw, conflict)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    require(type(raw) is bytes and len(raw) <= 16 * 1024 * 1024, 'JSON bounds')
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'Duplicate JSON key')
            out[key] = value
        return out
    def nonfinite(value):
        raise Hold('Nonfinite JSON')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=nonfinite)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'Exact fields')


def digest(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'Digest')


def same(a, b):
    return encode(a) == encode(b)


BINDING = ('nonce', 'configSHA256', 'candidateSHA256', 'baselineSHA256',
           'owner', 'containmentOwner')


def binding(value):
    fields(value, BINDING)
    for key in BINDING[:4]:
        digest(value[key])
    for key in BINDING[4:]:
        fields(value[key], ('pid', 'creationFileTime', 'imageSHA256'))
        v = value[key]
        require(type(v['pid']) is int and v['pid'] > 0, 'Owner pid')
        require(type(v['creationFileTime']) is str and
                re.fullmatch('[1-9][0-9]{0,19}', v['creationFileTime']), 'Owner creation')
        digest(v['imageSHA256'])
    require(not same(value['owner'], value['containmentOwner']), 'Independent owner')


SSH_INPUTS = (('known_hosts2', 'knownHostsSHA256'), ('client2', 'clientSHA256'))


def ssh_input_hashes(value):
    """Required configuration binding for the read-only SSH inputs; no default."""
    fields(value, [field for _, field in SSH_INPUTS])
    for _, field in SSH_INPUTS:
        digest(value[field])
    return dict(value)


def pin_ssh_inputs(owner, key):
    """Pin known_hosts2/client2 read-only, bound to their configured hashes.

    Only paths, hashes and ACL evidence are journaled; key bytes are discarded.
    """
    hashes = ssh_input_hashes(owner.resources['sshInputs'])
    key = pathlib.Path(key)
    sources = []
    for name, field in SSH_INPUTS:
        _, record = owner.journal.admission.pin_readonly_source(key/name, hashes[field], 1024*1024)
        sources.append(record)
    owner.journal.write('readonly-ssh-pins.json',
                        encode(dict(schema='fresh-readonly-source-pins-v1', sources=sources)))


class Journal:
    """Use only inside the admitted private root; never reconstruct an owner."""
    def __init__(self, root, admission):
        self.root = pathlib.Path(root)
        self.admission = admission  # retained native pins, rechecked on each access

    def claim(self, raw):
        self.admission.revalidate()
        with (self.root/'owner-created.json').open('xb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        require((self.root/'owner-created.json').read_bytes()==raw,'Owner claim readback')

    def write(self, name, raw):
        require(re.fullmatch('[a-z][a-z0-9-]*[.]json', name), 'Journal name')
        self.admission.revalidate()
        path = require_path(self.root / name)
        # Atomic: pollers (watcher, resident) never observe a partial file.
        # Identical bytes can reconcile a failed acknowledgement, but cannot
        # make the dispatcher execute again.
        publish_exclusive(path, raw, 'Journal collision')
        self.admission.revalidate()
        require(path.read_bytes() == raw, 'Journal readback')


class Owner:
    """One original object, no reload/adoption constructor or effect retry API."""
    def __init__(self, bound, journal, resources, validate_phase1, validate_phase2):
        binding(bound)
        self.bound = decode(encode(bound))
        self.journal = journal
        self.resources = resources  # same mutable owner inventory through setup
        self.validate_phase1 = validate_phase1
        self.validate_phase2 = validate_phase2
        self.lock = threading.RLock()
        self.state = 'SETUP'
        self.failure = None
        self.last = 0
        self.requests = {}
        self.phase1 = None
        self.settlement = None
        self.effects = {}
        # Reserve before any setup call; no prior journal may be adopted.
        self.journal.claim(encode(dict(binding=self.bound)))

    def fail(self, error):
        with self.lock:
            if self.failure is None:
                self.failure = type(error).__name__ + ': ' + str(error)
            if self.state not in ('PHASE1', 'PHASE2', 'SETTLED', 'HOLD'):
                self.state = 'FAILED'
            # Retention does not depend on publication succeeding.
            try:
                self.journal.write('failure.json', encode(dict(
                    binding=self.bound, failure=self.failure)))
            except Exception:
                pass

    def hold(self, reason):
        """Distinct terminal HOLD: no settlement, nothing closed or released."""
        with self.lock:
            require(self.state not in ('SETTLED', 'ABORTED_NEVER_SUBMITTED'), 'Owner already terminal')
            self.journal.write('administrative-hold.json', encode(dict(
                schema='fresh-admin-hold-v1', binding=self.bound, failure=self.failure,
                reason=reason, normalCleanupSucceeded=False)))
            self.state = 'HOLD'
            return dict(ready='hold', reason=reason)

    def effect_once(self, name, action):
        """Reserve original setup/continuation identity before crossing boundary.

        Completion observation uses the retained resource, never this method.
        Only fixed call sites choose name/action; endpoint data cannot supply code.
        """
        with self.lock:
            require(name not in self.effects, 'Effect already reserved')
            require(re.fullmatch('[a-z][a-z0-9-]{0,60}', name), 'Effect name')
            record = dict(state='Reserved', result=None,action=action)
            self.effects[name] = record
            try:
                self.journal.write('effect-' + name + '.json', encode(dict(binding=self.bound,name=name)))
            except Exception:
                record['state']='ReservationFailed'
                raise
            try:
                result = action()
                record.update(state='Returned', result=result)
                return result
            except BaseException as error:
                record['state'] = 'Unknown'
                self.fail(error)
                raise

    def resume_reserved(self,name):
        """Resume a known pre-dispatch storage failure using the SAME callable."""
        with self.lock:
            record=self.effects[name]
            require(record['state']=='ReservationFailed','Original effect already attempted/unknown')
            self.journal.write('effect-'+name+'.json',encode(dict(binding=self.bound,name=name)))
            record['state']='Reserved'
            try:
                result=record['action']()
                record.update(state='Returned',result=result)
                return result
            except BaseException as error:
                record['state']='Unknown';self.fail(error);raise

    def inspect(self):
        return dict(state=self.state, failure=self.failure,
                    effects={k: v['state'] for k, v in self.effects.items()},
                    normalCleanupSucceeded=False)

    def _publish_response(self, seq, record):
        require(record['response'] is not None, 'Original request unresolved; no replay')
        if record.get('settlement') is not None:
            self.journal.write('administrative-settled.json', encode(record['settlement']))
        if record.get('bootstrapAbort') is not None:
            self.journal.write('administrative-bootstrap-aborted.json',encode(record['bootstrapAbort']))
        self.journal.write('response-%020d.json' % seq, record['response'])
        if record.get('settlement') is not None:
            self.settlement = record['settlement']
            self.state = 'SETTLED'
        if record.get('bootstrapAbort') is not None:self.state='ABORTED_NEVER_SUBMITTED'
        record['published'] = True
        return record['response']

    def request(self, raw, *, phase1=None, phase2=None, collect=None):
        """A request executes once even when validation/publication throws.

        collect is a fixed original-owner read-only collector, not user code.
        Proof bytes are passed by the private endpoint after pinned reads.
        """
        with self.lock:
            request = decode(raw)
            fields(request, ('schema', 'binding', 'sequence', 'verb', 'proofSHA256'))
            require(request['schema'] == 'fresh-admin-request-v1' and
                    same(request['binding'], self.bound), 'Request binding')
            seq = request['sequence']
            require(type(seq) is int and 0 < seq < 2**63, 'Request sequence')
            verb = request['verb']
            require(verb in ('inspect', 'collect-original', 'advance', 'phase1', 'settle'), 'Request verb')
            digest(request['proofSHA256'])
            fingerprint = sha(raw)
            if seq in self.requests:
                old = self.requests[seq]
                require(old['sha256'] == fingerprint, 'Sequence conflict')
                return self._publish_response(seq, old)
            require(seq == self.last + 1, 'Request sequence gap/stale')
            if verb != 'inspect':
                require(not any(v['response'] is None for v in self.requests.values()),
                        'Unresolved original request')
            # Pure validation precedes reservation: bad evidence has no effects
            # and must not permanently consume the owner continuation.
            if verb in ('inspect','collect-original','advance'):
                require(request['proofSHA256'] == sha(b''), 'Observation body')
                if verb == 'collect-original':
                    require(self.failure is not None and callable(collect), 'Original collector required')
                if verb == 'advance':
                    from admin_handoff import Handoff
                    handoff=self.resources.get('handoff')
                    require(self.failure is not None and isinstance(handoff,Handoff) and handoff.owner is self,
                            'Original fixed handoff required')
            elif verb == 'phase1':
                require(self.state == 'FAILED' and type(phase1) is bytes and
                        sha(phase1) == request['proofSHA256'], 'Phase1 order/body')
                result = self.validate_phase1(phase1, self.bound, self.resources)
            else:
                require(self.state == 'PHASE1' and type(phase2) is bytes and
                        sha(phase2) == request['proofSHA256'], 'Phase2 order/body')
                result = self.validate_phase2(phase2, self.phase1, self.bound, self.resources)
            self.last = seq
            record = dict(sha256=fingerprint, response=None, published=False)
            self.requests[seq] = record
            # Reservation is in memory first, then durable and read back before
            # dispatch. A failed flush has no effect and still burns the sequence.
            try:
                self.journal.write('request-%020d.json' % seq, raw)
            except Exception as error:
                # No dispatch was entered. Keep the consumed sequence, but do
                # not confuse a storage refusal with uncertain remote effects.
                record['response'] = encode(dict(schema='fresh-admin-response-v1',
                    binding=self.bound, sequence=seq, requestSHA256=fingerprint,
                    result=dict(dispatched=False, reservation='failed', error=type(error).__name__)))
                return self._publish_response(seq, record)
            if verb == 'inspect':
                result = self.inspect()
            elif verb in ('collect-original','advance'):
                try:
                    result = collect(self.resources) if verb=='collect-original' else handoff.advance()
                    if verb=='advance' and hasattr(handoff,'bootstrap_abort'):
                        record['bootstrapAbort']=handoff.bootstrap_abort
                except Exception as error:
                    # This callback only observes original objects. A fresh
                    # explicit request may observe them later, never resubmit.
                    result = dict(observation='unresolved', error=type(error).__name__,
                                  reason=reason_text(error))
            elif verb == 'phase1':
                self.phase1 = phase1
                self.state = 'PHASE1'
            else:
                self.state = 'PHASE2'
                # Final settlement publication is the last authority boundary.
                value = dict(schema='fresh-admin-settled-v1', binding=self.bound,
                             failure=self.failure, normalCleanupSucceeded=False,
                             phase1SHA256=sha(self.phase1), phase2SHA256=sha(phase2))
                record['settlement'] = value
            response = encode(dict(schema='fresh-admin-response-v1', binding=self.bound,
                                   sequence=seq, requestSHA256=fingerprint, result=result))
            # Cache before publication: repeating a request only republishes exact
            # response bytes through the endpoint, never repeats its callback.
            record['response'] = response
            return self._publish_response(seq, record)


def run_preparation(owner, setup, body, finalize, serve, pause=None):
    """The preparation entry's single failure boundary, including setup.

    The endpoint owns the calling frame until explicit positive settlement.
    A bounded serve iteration may return on timeout; this never returns ownership.
    """
    completed = False
    try:
        setup(owner.resources)
        owner.state = 'RUNNING'
        body(owner.resources)
        stage = owner.resources.get('stage')
        require(stage is None or stage.lifecycle not in ('ABORTED', 'HOLD'),
                'Stage failed without raising')
        completed = True
        finalize(owner.resources)
        return 'NORMAL'
    except BaseException as error:
        original = owner.resources.get('failure')
        original = getattr(original, 'value', None)
        owner.fail(original if original is not None else error)
    while owner.state not in ('SETTLED','ABORTED_NEVER_SUBMITTED','HOLD'):
        try:
            # After a completed normal body the watcher was released normally,
            # so the failed-run settlement is unreachable: terminal HOLD only.
            if completed:owner.hold('Normal finalizer failed after completed body')
            else:serve(owner)
        except Exception as error:
            owner.fail(error)
            # A failing serve slice must not become a busy loop.
            (pause or time.sleep)(.05)
    if owner.state=='HOLD':return 'ADMINISTRATIVE_HOLD'
    return 'BOOTSTRAP_ABORTED_NEVER_SUBMITTED' if owner.state=='ABORTED_NEVER_SUBMITTED' else 'ADMINISTRATIVELY_RESTORED_FAILED_RUN'
