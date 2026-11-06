"""Offline-safe cancellation evidence and immutable local control publication."""
import datetime
import json
import os
import pathlib
import secrets

ROLES = ('supervisor', 'collector', 'barrier')

def publish_once(path, value):
    """Publish a complete file without replacing an existing request."""
    path = pathlib.Path(path)
    # Short fixed-length temporary independent of the target name (MAX_PATH).
    temporary = path.with_name('.' + secrets.token_hex(4) + '.tmp')
    if len(os.path.abspath(path)) > 259 or len(os.path.abspath(temporary)) > 259:
        raise ValueError('Path exceeds MAX_PATH budget: ' + str(path))
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if json.loads(path.read_text(encoding='utf-8-sig')) != value:
                raise ValueError('Conflicting immutable control record')
    finally:
        temporary.unlink(missing_ok=True)

def stop_request(nonce, reason):
    return dict(schema=1, nonce=nonce, requestId=secrets.token_hex(32),
                reasonCode=reason,
                requestedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat())

def valid_stop(value, nonce):
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('nonce') != nonce:
        return False
    if not all(isinstance(value.get(k), str) and value[k] for k in ('requestId','reasonCode','requestedUtc')):
        return False
    try:
        return datetime.datetime.fromisoformat(value['requestedUtc'].replace('Z','+00:00')).tzinfo is not None
    except ValueError:
        return False


def closure_proven(status, nonce, admitted, local_evidence, request=None):
    """Require returned local owner evidence as well as fixed guest records."""
    if status.get('nonce') != nonce:
        return False
    for role in admitted:
        if role not in ROLES:
            return False
        records = (local_evidence.get(role), status.get('readers', {}).get(role, {}).get('closed'))
        for record in records:
            if not isinstance(record, dict) or record.get('nonce') != nonce or record.get('role') != role or not record.get('closed'):
                return False
            if request:
                if record.get('cancelled') is True:
                    if record.get('requestId') != request['requestId']:
                        return False
                else:
                    try:
                        closed = datetime.datetime.fromisoformat(record['closed'].replace('Z', '+00:00'))
                        requested = datetime.datetime.fromisoformat(request['requestedUtc'].replace('Z', '+00:00'))
                        if closed.tzinfo is None or closed > requested:
                            return False
                        if not record.get('failure'):
                            from persistent import validate_readers
                            returned = local_evidence[role]
                            validate_readers([dict(returned, role=r) for r in ROLES], nonce)
                    except (ValueError, KeyError, TypeError, OverflowError):
                        return False
    final = status.get('inspectorFinal') or {}
    task = status.get('task') or {}
    return (final.get('nonce', (final.get('launch') or {}).get('nonce')) == nonce and final.get('exitVerified') is True
            and final.get('taskClosureVerified') is True
            and task.get('state') == 3 and task.get('instances') == 0)

def failure_stage(elapsed, delivered, exited, restored):
    if elapsed >= 10 and not delivered:
        return 'HOLD: stop delivery unproven at 10s; capture/watchers retained'
    if elapsed >= 30 and not exited:
        return 'HOLD: inspector/task exit unproven at 30s; capture/watchers retained'
    if elapsed >= 60 and not restored:
        return 'HOLD: restoration/local drain unproven at 60s; capture/watchers retained'
    return None

def process_identity(process):
    """Read creation FILETIME from the retained Windows handle, never reopen PID."""
    identity = dict(pid=getattr(process, 'pid', None), startFiletime=None)
    handle = getattr(process, '_handle', None)
    if os.name != 'nt' or handle is None:
        identity['startIdentityStatus'] = 'unavailable'
        return identity
    import ctypes
    created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
    if ctypes.windll.kernel32.GetProcessTimes(ctypes.c_void_p(int(handle)),
            ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
        identity.update(startFiletime=created.value, startIdentityStatus='verified')
    else:
        identity['startIdentityStatus'] = 'query-failed'
    return identity


class Transport:
    """Retained Popen with file output: polling never waits on pipe capacity."""
    def __init__(self, command, out, label, administrative_owner=None):
        import subprocess
        import time
        self.started = time.monotonic()
        self.utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.command = command
        self.diagnostic = pathlib.Path(out)/(label+'.diagnostic.json')
        self.reported = False
        self.stdout = pathlib.Path(out) / (label + '.stdout')
        self.stderr = pathlib.Path(out) / (label + '.stderr')
        self.administrative_owner=administrative_owner;self.label=label
        from stock_controller import _stock_child_environment
        env=_stock_child_environment(pathlib.Path(command[0]))
        if administrative_owner is not None:
            from admin_recovery import encode, require
            require(label not in administrative_owner.resources['operations'],'Original reader already reserved')
            administrative_owner.resources['operations'][label]=dict(identity=None,submission='Reserved')
            administrative_owner.resources['operationOwners'][label]=self
            administrative_owner.journal.write('reader-'+label+'-reserved.json',encode(dict(
                binding=administrative_owner.bound,argv=command)))
        with self.stdout.open('xb') as a, self.stderr.open('xb') as b:
            self.process = subprocess.Popen(command, stdout=a, stderr=b,env=env)
        self.identity = process_identity(self.process)
        if administrative_owner is not None:
            from admin_recovery import require
            require(self.identity['startIdentityStatus']=='verified','Original reader identity unavailable')
            administrative_owner.resources['operations'][label].update(identity=self.identity,submission='Submitted')
    def poll(self):
        return self.process.poll()
    def administrative_closure(self):
        from admin_recovery import decode, require
        require(self.poll() is not None,'Original reader still pending')
        value=decode((self.stdout.parent/(self.label+'.session-closed.json')).read_bytes())
        require(value.get('nonce')==self.administrative_owner.bound['nonce'] and
                value.get('pid')==self.identity['pid'] and value.get('state')=='Closed' and
                value.get('creationFileTime')==str(self.identity['startFiletime']) and
                value.get('instanceId'),'Original reader session closure')
        return dict(identity=self.identity,submission='Submitted',terminal='Collected',sessionState='Closed',pending=False)
    def report(self, error=None):
        import time
        from readiness_diagnostics import bounded
        with self.stdout.open('rb') as stream:stdout, cutout = bounded(stream.read(65536))
        with self.stderr.open('rb') as stream:stderr, cuterr = bounded(stream.read(65536))
        record = dict(schema=1, command=[bounded(arg)[0] for arg in self.command],
                      process=self.identity,
                      returncode=self.poll(), stdout=stdout, stderr=stderr,
                      stdoutTruncated=cutout or self.stdout.stat().st_size>65536,
                      stderrTruncated=cuterr or self.stderr.stat().st_size>65536,
                      utcStart=self.utc, utcEnd=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      elapsedSeconds=time.monotonic()-self.started,
                      errorClassification=type(error).__name__ if error else None)
        try:
            temporary=self.diagnostic.with_suffix('.pending')
            with temporary.open('w', encoding='utf-8') as stream:
                json.dump(record, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary,self.diagnostic)
        except Exception as persistence_error:
            if error is not None:
                error.add_note('Transport diagnostic persistence failed')
                raise error from persistence_error
            raise RuntimeError('Transport diagnostic persistence failed') from persistence_error
    def result(self):
        error=None
        try:
            if self.poll() is None:
                raise RuntimeError('Owner still running')
            if self.process.returncode:
                raise RuntimeError('Transport exited nonzero; remote closure unknown')
            return json.loads(self.stdout.read_text(encoding='utf-8-sig'))
        except Exception as exc:
            error=exc
            raise
        finally:
            self.report(error)


def control(process, launch, out, nonce, latch, seconds, validate,
            diagnostic=False, readers=True, clock=None, pause=None, before_restore=None,
            retained_state=None):
    """Own every admitted process until returned evidence, or report bounded HOLD."""
    import time
    clock = clock or time.monotonic
    pause = pause or time.sleep
    started = clock()
    evidence = dict(schema=1, nonce=nonce, events=[], result='RUNNING')
    owners = {}
    local = {}
    pending = {}
    status = {}
    request = None
    delivered = False
    permit = False
    injected = False
    serial = 0
    producer_ready = False
    admission_started = None
    acknowledged = set()
    if retained_state is not None:
        if retained_state:
            raise RuntimeError('Original cancellation controller already entered')
        retained_state.update(process=process, owners=owners, local=local,
                              pending=pending, nonce=nonce, out=pathlib.Path(out),
                              completed=[], request=None, status=status, permit=False)
    def event(kind, **fields):
        evidence['events'].append(dict(kind=kind, utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), elapsedSeconds=clock()-started, **fields))
        target = pathlib.Path(out)/'cancellation-evidence.json'
        temporary = target.with_suffix('.pending')
        temporary.write_text(json.dumps(evidence), encoding='utf-8')
        os.replace(temporary, target)
    def start(mode, role=None):
        nonlocal serial
        serial += 1
        return launch(mode, role, '%s-%06d' % (role or mode, serial))
    event('controller-started')
    try:
        while True:
            now = clock()
            if process.poll() not in (None,0):
                latch.set('Preparation exited nonzero')
            if not owners and now-started>=60:
                latch.set('Producer startup readiness deadline exceeded at 60s')
            for mode, owner in pending.items():
                if owner.poll() is None and now-getattr(owner,'started',now)>=6:
                    latch.set('Transport observation deadline exceeded: '+mode)
                    if not getattr(owner,'reported',False):
                        try:owner.report(TimeoutError('Transport observation deadline'))
                        except Exception as exc:latch.set(exc)
                        owner.reported=True

            if not latch.event.is_set() and now-started > seconds+90:
                latch.set('Nominal preparation deadline exceeded')
            if latch.event.is_set() and request is None and (status or now-latch.monotonic>=6):
                request = stop_request(nonce, 'host-first-failure')
                publish_once(pathlib.Path(out)/'stop-request.json', request)
                event('failure-latched', failure=latch.value, requestId=request['requestId'])
            for mode, owner in list(pending.items()):
                if owner.poll() is None:
                    continue
                del pending[mode]
                if retained_state is not None:
                    retained_state['completed'].append((mode, owner))
                try:
                    value = owner.result()
                    if mode == 'stop':
                        if value.get('nonce') != nonce:
                            raise ValueError('Stop acknowledgement nonce mismatch')
                        adopted = value.get('adoptedRequest')
                        if adopted is not None:
                            if not valid_stop(adopted, nonce) or value.get('requestId') != adopted['requestId']:
                                raise ValueError('Invalid adopted stop acknowledgement')
                            prior = request
                            request = adopted
                            event('guest-stop-adopted', firstFailure=latch.value,
                                  adoptedRequest=request, priorHostRequest=prior)
                        if value.get('delivered') is True and request is not None and value.get('requestId') == request['requestId']:
                            delivered = True
                            event('stop-accepted', requestId=request['requestId'])
                    elif mode == 'drain-status':
                        if value.get('nonce') != nonce:
                            raise ValueError('Drain status nonce mismatch')
                        status = value
                        final = status.get('inspectorFinal') or {}
                        guest_request = status.get('stopRequest')
                        if guest_request is not None and not valid_stop(guest_request,nonce):
                            raise ValueError('Invalid guest stop request')
                        if final.get('failure') or final.get('holdReason') or guest_request:
                            latch.set('Inspector failure/stop: '+str(final.get('failure') or final.get('holdReason') or guest_request['reasonCode']))
                        if guest_request and (request is None or request != guest_request):
                            prior=request
                            request=guest_request
                            delivered=True
                            mailbox=pathlib.Path(out)/'stop-request.json'
                            if not mailbox.exists():publish_once(mailbox,request)
                            event('guest-stop-adopted',firstFailure=latch.value,adoptedRequest=request,priorHostRequest=prior)
                            event('stop-accepted',requestId=request['requestId'],source='guest-drain-status')
                    elif mode == 'ready' and not latch.event.is_set():
                        if value.get('failure'):
                            raise ValueError('Producer readiness refused')
                        if value.get('ready') is True and value.get('healthy') is True:
                            publish_once(pathlib.Path(out)/'producer-readiness.json', value)
                            producer_ready = True
                            if not readers:
                                owners['disabled'] = None
                except Exception as exc:
                    latch.set(exc)
            for role, owner in owners.items():
                if owner is None or role in local or owner.poll() is None:
                    continue
                try:
                    if hasattr(owner,'stdout'):
                        (pathlib.Path(out)/(role+'.stdout')).write_bytes(owner.stdout.read_bytes())
                        (pathlib.Path(out)/(role+'.stderr')).write_bytes(owner.stderr.read_bytes())
                    value = owner.result()
                    if value.get('nonce') != nonce or value.get('role') != role or not value.get('closed'):
                        raise ValueError('Returned reader closure binding invalid')
                    local[role] = value
                    event('reader-closed', role=role, record=value.get('closed'), requestId=value.get('requestId'))
                    if value.get('failure'):
                        latch.set('Reader failure: '+role)
                except Exception as exc:
                    latch.set(exc)
            for role in owners:
                if role not in ROLES or role in acknowledged:
                    continue
                marker = pathlib.Path(out)/('reader-'+role+'-session-open.json')
                if marker.exists():
                    try:
                        record = json.loads(marker.read_text(encoding='utf-8-sig'))
                        stamp = datetime.datetime.fromisoformat(record['sessionOpenedUtc'].replace('Z', '+00:00'))
                        if (record.get('schema') != 1 or record.get('nonce') != nonce or
                                record.get('role') != role or stamp.utcoffset() != datetime.timedelta(0)):
                            raise ValueError('Invalid session-open acknowledgement')
                        acknowledged.add(role)
                    except Exception as exc:
                        latch.set(exc)
            if admission_started is not None and len(acknowledged) < 3 and now-admission_started >= 10:
                latch.set('Reader session-start deadline exceeded at 10s')
            if (readers and producer_ready and not pending and not latch.event.is_set()
                    and len(owners) < 3 and len(acknowledged) == len(owners)):
                if admission_started is None:
                    admission_started = now
                role = ROLES[len(owners)]
                owners[role] = start('persistent', role)
            ready = status.get('readers', {})
            actual = all(isinstance(ready.get(r, {}).get('ready'), dict) and
                         ready[r]['ready'].get('nonce') == nonce and
                         ready[r]['ready'].get('role') == r and ready[r]['ready'].get('ready')
                         for r in ROLES)
            if diagnostic and actual and not injected and not latch.event.is_set():
                injected = True
                event('diagnostic-injection', ready={r:ready[r]['ready'] for r in ROLES})
                latch.set('Diagnostic failure after all retained reader handles ready')
            admitted = [r for r in owners if r in ROLES]
            exited = closure_proven(status, nonce, admitted, local, request)
            outcome_path = pathlib.Path(out)/'preparation-outcome.json'
            outcome = json.loads(outcome_path.read_text(encoding='utf-8-sig')) if outcome_path.exists() else {}
            no_launch = (outcome.get('nonce') == nonce and outcome.get('launchNeverOccurred') is True
                         and not admitted)
            if not permit and (exited or no_launch) and all(o.poll() is not None for o in pending.values()):
                if not latch.event.is_set() and readers:
                    try:
                        validate(list(local.values()))
                    except Exception as exc:
                        latch.set(exc)
                        continue
                if before_restore is not None:
                    freeze_controller_drain(out,nonce,owners,local)
                    before_restore()
                publish_once(pathlib.Path(out)/'restore-permit.json', dict(schema=1, nonce=nonce, readersDrained=True))
                permit = True
                event('restore-permit')
            if permit and process.poll() is not None and not pending:
                outcome = json.loads(outcome_path.read_text(encoding='utf-8-sig')) if outcome_path.exists() else {}
                if outcome.get('nonce') != nonce or outcome.get('restored') is not True:
                    raise RuntimeError('HOLD: preparation restoration unproven; capture/watchers retained')
                event('preparation-restored')
                evidence['result'] = 'FAIL' if latch.event.is_set() else 'PASS'
                event('local-drain-complete')
                return True
            if request:
                elapsed = now-latch.monotonic
                hold = failure_stage(elapsed, delivered, exited or no_launch, False)
                if hold:
                    raise RuntimeError(hold)
            if not permit and process.poll() is not None and not no_launch:
                latch.set('Preparation exited before restoration permit')
            if not permit:
                if request and not delivered and 'stop' not in pending:
                    pending['stop'] = start('stop')
                if 'drain-status' not in pending and (latch.event.is_set() or not readers or not producer_ready or len(acknowledged) == 3):
                    pending['drain-status'] = start('drain-status')
                if not producer_ready and not owners and not latch.event.is_set() and 'ready' not in pending:
                    pending['ready'] = start('ready')
            pause(.2)
    except Exception as exc:
        latch.set(exc)
        evidence['result'] = 'HOLD'
        event('hold', reason=str(exc))
        return False
    finally:
        # Strong references survive reporting expiry; no terminate/kill/dispose.
        if retained_state is not None:
            retained_state.update(request=request, status=status, permit=permit,
                                  delivered=delivered, evidence=evidence)
        RETAINED.append((process, owners, pending))

RETAINED = []


def freeze_controller_drain(out,nonce,owners,local):
    """Freeze original retained controller process receipts before restoration."""
    import base64
    import hashlib
    root=pathlib.Path(out);artifacts={};admitted=[];closures=[]
    def ref(name,value):
        raw=json.dumps(value,separators=(',',':')).encode()
        artifacts[name]=base64.b64encode(raw).decode()
        return dict(name=name,sha256=hashlib.sha256(raw).hexdigest(),length=len(raw))
    for role,owner in owners.items():
        if role not in ROLES:continue
        identity=owner.identity
        if identity.get('startIdentityStatus')!='verified' or owner.poll() is None:
            raise RuntimeError('Original reader transport exit not proved')
        command=hashlib.sha256(json.dumps(owner.command,separators=(',',':')).encode()).hexdigest()
        common=dict(schema='full300-local-transport-v1',nonce=nonce,role=role,
                    requestId=command,pid=identity['pid'],creationFileTime=str(identity['startFiletime']),commandSHA256=command)
        started=ref('reader-'+role+'-started.json',dict(common,state='started',exitCode=None,response=None))
        closed=ref('reader-'+role+'-closed.json',local[role])
        exited=ref('reader-'+role+'-signalled.json',dict(common,state='signalled',exitCode=owner.poll(),response=closed))
        marker=root/('reader-'+role+'-session-open.json')
        session=ref(marker.name,json.loads(marker.read_text(encoding='utf-8-sig'))) if marker.exists() else None
        admitted.append(dict(role=role,sessionOpen=session,transportReceipt=started))
        closures.append(dict(role=role,closed=closed,transportExit=exited))
    admissions=dict(schema='full300-reader-admissions-v1',nonce=nonce,sealed=True,entries=admitted)
    publish_once(root/'controller-admissions.json',admissions)
    digest=hashlib.sha256((root/'controller-admissions.json').read_bytes()).hexdigest()
    bundle=dict(schema='full300-reader-closures-v1',nonce=nonce,admissionsSHA256=digest,entries=closures)
    publish_once(root/'controller-closures.json',dict(bundle=bundle,artifacts=artifacts))
