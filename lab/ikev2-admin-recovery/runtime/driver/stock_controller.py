"""Retained stock controller and local recovery request client."""
import time

class Hold(RuntimeError):
    pass

NIC = ('<LAB_VM_ID>',
       r'Microsoft:<LAB_VM_ID_UPPER>/<LAB_VM_NIC_ID>'.replace('/', '\\'),
       '<LAB_GUEST_MAC_HEX>', '<LAB_VSWITCH_ID>')

_controllers = {}

def _wait_file(process, path, seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if path.is_file(): return path.read_bytes()
        # HOLD retains this Python owner, process registry, and capture pipeline.
        # Recovery requests are explicit and cannot transfer process ownership.
        if process.poll() is not None: raise Hold('Unsupported recovery: original controller exited without receipt; capture must remain retained')
        time.sleep(.1)
    # Deadline is an observation timeout, not authority to abandon the owner.
    while process.poll() is None:
        if path.is_file(): return path.read_bytes()
        time.sleep(.1)
    raise Hold('Unsupported recovery: original controller lost; capture must remain retained')

def _stock_child_environment(executable):
    """Restrict this Windows PowerShell child to machine WindowsPS module roots."""
    from windows_powershell import environment, PowerShellEnvironmentError
    try:
        return environment(executable)
    except PowerShellEnvironmentError as error:
        raise Hold(str(error)) from None

def operational_controller(binding, nonce, proof_path):
    import os,pathlib,subprocess
    from protected_transport import strict
    proof_path=pathlib.Path(proof_path)
    config=pathlib.Path(__file__).resolve().parents[1]/'stock-control-config.json'
    if not config.is_file(): raise Hold('Fresh stock-control-config.json required')
    if nonce in _controllers: raise Hold('Stock controller already attempted')
    import sys
    from live_prepare import absolute_executable
    exe=pathlib.Path('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
    child_environment=_stock_child_environment(exe)
    log=(proof_path.parent/'stock-controller.log').open('xb')
    process=subprocess.Popen([str(exe),'-NoProfile','-NonInteractive','-WindowStyle','Hidden',
        '-File',str(pathlib.Path(__file__).resolve().parents[1]/'host/stock-control.ps1'),
        '-ProofPath',str(proof_path.resolve()),'-ConfigPath',str(config.resolve()),
        '-PythonPath',absolute_executable(sys.executable,'interpreter')],
        stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,env=child_environment)
    root=proof_path.parent/'stock'
    _controllers[nonce]=(process,root,log)
    value=strict(_wait_file(process,root/'precleanup.json',600))
    validate_receipt(value,binding,nonce,root=root)
    return value

def validate_receipt(receipt,binding,nonce,root=None):
    from stock_receipt import validate,exact,require
    if root is None:
        if nonce not in _controllers: raise Hold('Retained controller missing')
        root=_controllers[nonce][1]
    if type(receipt) is dict and receipt.get('schema')=='stock-no-launch-v1':
        exact(receipt,('schema','nonce','binding','normalCleanupSucceeded','reason','deploymentAttempted','permitPublished','serviceMutations','rawUiOutcome'))
        require(receipt['nonce']==nonce and receipt['binding']==binding,'no launch binding')
        require(receipt['normalCleanupSucceeded'] is False and receipt['deploymentAttempted'] is False and receipt['permitPublished'] is False and type(receipt['serviceMutations']) is int and receipt['serviceMutations']==0 and receipt['reason']=='human-ready-unavailable' and receipt['rawUiOutcome']=={'state':'unknown'},'no stock launch')
        require(not (root/'deployment-intent.json').exists() and not (root/'permit-intent.json').exists(),'no-launch collision')
        return receipt
    if receipt.get('schema')=='stock-no-permit-precleanup-v1':
        from stock_receipt import validate_no_permit
        return validate_no_permit(receipt,root,binding,nonce,'precleanup')
    return validate(receipt,root,binding,nonce,'precleanup')

def finalize_controller(binding,nonce,final,checked,out):
    import pathlib,subprocess
    from protected_transport import strict,encode,freeze,sha
    from protected_evidence import check_independent_absence
    from live_prepare import ssh_command,canonical,partition,absolute_executable
    from stock_receipt import validate
    process,root,log=_controllers[nonce]
    pre=strict((root/'precleanup.json').read_bytes())
    if check_independent_absence(final,binding,nonce)!=checked: raise Hold('C1 validation changed')
    status_ref=strict(final['proof'])['nativeStatus']
    raw=final['files'][status_ref['name']]
    if sha(raw)!=status_ref['sha256']: raise Hold('C1 status digest')
    status=strict(raw);live=status['Live']
    if (status['State']!='CLOSED' or live['NoDial'] is not True or live['Attempted'] is not False
            or live['NativeEntered'] is not False or live['CleanupSucceeded'] is not True): raise Hold('C1 did not close with genuine NoDial')
    def retain(name,data):
        freeze(root/name,data)
        return dict(name=name,sha256=sha(data),length=len(data))
    counter=[0]
    def pack(v):
        if type(v) is bytes:
            counter[0]+=1
            return dict(bytes=retain('c1-raw-'+str(counter[0])+'.raw',v))
        if type(v) is dict:return {k:pack(x) for k,x in v.items()}
        if type(v) in (list,tuple):return [pack(x) for x in v]
        return v
    evidence_ref=retain('c1-evidence.json',encode(pack(final)))
    c1=dict(checked,nonce=nonce,binding=binding,nativeStatus=retain('c1-native-status.json',raw),evidence=evidence_ref)
    c1ref=retain('c1.json',encode(c1))
    if pre['schema']=='stock-no-launch-v1':
        try: code=process.wait(timeout=10)
        except subprocess.TimeoutExpired: raise Hold('No-launch controller exit unresolved')
        if code: raise Hold('No-launch controller failed')
        log.close()
        return dict(schema='stock-no-launch-final-v1',nonce=nonce,normalCleanupSucceeded=False,rawUiOutcome={'state':'unknown'},c1=c1ref)
    proof=strict((root.parent/'verified.json').read_bytes())
    capture_config=strict((pathlib.Path(out)/'host-supervisor-config.json').read_bytes())
    nft=subprocess.run(ssh_command('sudo nft -j list ruleset',capture_config['query'][0]),input=b'',capture_output=True,timeout=15,check=True).stdout
    own,other=partition(strict(nft),proof['table'])
    if canonical(own)!=canonical(strict((root.parent/'readback.json').read_bytes())) or canonical(other)!=canonical(strict((root.parent/'before.json').read_bytes())): raise Hold('Continuing observer guard changed')
    retain('finalize-guard.json',nft)
    capture_raw=subprocess.run([absolute_executable(capture_config['query'][0],'ssh'),*capture_config['query'][1:]],input=b'',capture_output=True,timeout=6,check=True).stdout
    capture=strict(capture_raw)
    if capture['Healthy'] is not True or capture['LiveIdentityHealthy'] is not True or capture['Identity']!=capture_config['capture']: raise Hold('Capture no longer healthy')
    retain('finalize-capture.json',capture_raw)
    pre_raw=(root/'precleanup.json').read_bytes()
    request=dict(schema='stock-finalize-request-v1',nonce=nonce,binding=binding,
        precleanup=dict(name='precleanup.json',sha256=sha(pre_raw),length=len(pre_raw)),c1=c1ref,
        guardSHA256=proof['admission']['GuardSHA256'],captureHealthy=True)
    retain('finalize-request.json',encode(request))
    receipt=strict(_wait_file(process,root/'final.json',90))
    if pre['schema']=='stock-no-permit-precleanup-v1':
        from stock_receipt import validate_no_permit
        validate_no_permit(receipt,root,binding,nonce,'final')
    else:
        validate(receipt,root,binding,nonce,'final')
    try: code=process.wait(timeout=10)
    except subprocess.TimeoutExpired: raise Hold('Final controller exit unresolved')
    if code: raise Hold('Final controller failure')
    log.close()
    return receipt

def exercise(adapter, clock=time.monotonic):
    """Mock-only order contract; adapter methods must never perform real operations.

    poll is nonblocking; disconnect is host-local; stop/readback resolves the
    outstanding mutation within 30 seconds or raises. No retry is permitted.
    """
    if adapter.offline is not True:
        raise Hold('Mock-only kernel')
    adapter.preflight()
    adapter.guard_and_original_drain()
    adapter.retain_private_handle_and_verify_readiness()
    adapter.verify_actual_human_and_review()
    deadline = clock() + 60
    adapter.permit_once(deadline)
    while clock() < deadline:
        if adapter.poll_readonly_nonblocking():
            break
        adapter.pause_bounded(deadline)
    adapter.disconnect_exact_host_nic(NIC)
    adapter.verify_disconnected(NIC)
    adapter.resolve_outstanding_reads()
    for name in ('RasMan', 'EapHost', 'IKEEXT'):
        adapter.stop_once_and_resolve(name, 30)
        adapter.verify_normal_stopped_identity_dependents_cohosts(name)
    adapter.verify_zero_ras_main_quick_and_bfe_policyagent()
    adapter.retire_retained_private_handle_only_if_live()
    adapter.finalize_exact_task_no_relaunch()
    adapter.restore_original_services_isolated()
    adapter.verify_original_context_profile_task_wrapper_policy_and_zero_state()
    adapter.close_session_positively()
    # Reconnect/C1 release deliberately absent: settlement schema not implemented.
    raise Hold('Mock disposition complete; no operational authority granted')


def request_recovery(root, nonce, candidate, request_id, verb):
    """Publish a bounded request to the retained owner; this grants no ownership.

    The controller authenticates the protected local directory ACL and binds the
    nonce/candidate. A duplicate ID with the same bytes is idempotent.
    """
    import pathlib
    from protected_transport import encode, freeze
    if type(request_id) is not int or not 0 < request_id < 2**63:
        raise Hold('Recovery request ID out of range')
    if verb not in ('inspect','reconcile','continue-disposition'):
        raise Hold('Recovery verb forbidden')
    raw=encode(dict(schema='stock-recovery-request-v1',nonce=nonce,
                    candidate=candidate,requestId=request_id,verb=verb))
    return freeze(pathlib.Path(root)/('recovery-request-%020d.json'%request_id),raw)
