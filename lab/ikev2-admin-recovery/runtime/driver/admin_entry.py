"""Explicit fresh-run bootstrap. Never invoked by the offline acceptance suite.

The externally reviewed bootstrap file/interpreter are the initial trust root.
Independent config/manifest/review anchors are mandatory; this module creates no
approval, baseline, credentials, runtime binary or operational admission inputs.
"""
import argparse
import os
import pathlib
import secrets
import sys
import time
from admin_recovery import ssh_input_hashes,require,fields,decode,encode,sha,Journal,Owner,Hold,Pending,private_root_name,require_run_path_budget
from admin_native import WindowsAdmission
from admin_bootstrap import load_pinned_modules,Endpoint


def anchored(ref,admission):
    fields(ref,('path','sha256'))
    path=pathlib.Path(ref['path']);admission.pin_source(path)
    raw=path.read_bytes()
    require(len(raw)<=16*1024*1024 and sha(raw)==ref['sha256'],'Admitted input bytes')
    return path,raw


def system_anchored(ref,admission,evidence):
    # System executable (ssh.exe): strict ACLs; extra hard links only for a
    # system-owned leaf held share=READ and hash-checked through that handle.
    fields(ref,('path','sha256'))
    path=pathlib.Path(ref['path'])
    raw,record=admission.pin_system_executable(path,ref['sha256'],16*1024*1024)
    evidence.append(record)
    return path,raw


def under(root,path,what):
    require(pathlib.Path(root) in pathlib.Path(path).parents,what+' outside the strict admission root')


def python_tree_sha256(tree):
    """sha256 over UTF-8 lines "name<TAB>sha256<LF>" sorted by name (code point order)."""
    return sha(''.join('%s\t%s\n'%(name,tree[name]) for name in sorted(tree)).encode('utf-8'))


def pinned_python(config,admission):
    """Official embeddable interpreter inside the strict admission root.

    The interpreter directory is a declared code directory: every entry is pinned
    strictly and hashed; the layout must be flat (no Lib/, no site-packages) and
    its single pythonXY._pth may list only pythonXY.zip and '.'. The running
    interpreter must be exactly this image, without any venv redirection, and
    the whole directory must match the configured treeSHA256.
    """
    ref=config['python'];fields(ref,('path','sha256','treeSHA256'))
    python=pathlib.Path(admission.canonical(ref['path']));under(config['admissionRoot'],python,'Interpreter')
    same_path=lambda left,right:os.path.normcase(str(left))==os.path.normcase(str(right))
    require(same_path(sys.executable,python),'Running interpreter is not the admitted one')
    directory=python.parent
    # pyvenv.cfg next to the image or in its parent redirects the base interpreter.
    for folder in (directory,directory.parent):
        require(not os.path.lexists(folder/'pyvenv.cfg'),'pyvenv.cfg forbidden near the interpreter')
    require(same_path(getattr(sys,'_base_executable',None),sys.executable),'Interpreter base executable redirected')
    require(same_path(sys.prefix,directory),'Interpreter prefix is not the admitted directory')
    admission.pin_source(directory)
    tag='python%d%d'%sys.version_info[:2];tree={}
    for entry in sorted(os.scandir(directory),key=lambda item:item.name):
        require(entry.is_file(follow_symlinks=False),'Embeddable interpreter tree must be flat')
        path=directory/entry.name;admission.pin_source(path)
        raw=path.read_bytes();require(len(raw)<=64*1024*1024,'Interpreter file bound')
        tree[entry.name]=sha(raw)
        if entry.name.lower().endswith('._pth'):
            require(entry.name.lower()==tag+'._pth','Unexpected ._pth file')
            lines=[line.strip() for line in raw.decode('utf-8').splitlines()]
            require(all(not line or line.startswith('#') or line in (tag+'.zip','.') for line in lines),
                    'Embeddable ._pth must stay isolated (no site, no extra paths)')
    require(tag+'._pth' in {name.lower() for name in tree},'Embeddable ._pth required')
    require(tree.get(python.name)==ref['sha256'],'Interpreter image hash')
    require(python_tree_sha256(tree)==ref['treeSHA256'],'Interpreter tree hash')
    return python,dict(schema='fresh-admin-python-v2',path=str(python),sha256=ref['sha256'],
                       treeSHA256=ref['treeSHA256'],tree=tree)


def readonly_anchored(ref,admission,evidence):
    # External read-only input: ancestors may have third-party writers. The
    # held handle, the bound content hash and revalidation carry integrity.
    fields(ref,('path','sha256'))
    path=pathlib.Path(ref['path'])
    raw,record=admission.pin_readonly_source(path,ref['sha256'],16*1024*1024)
    evidence.append(record)
    return path,raw


def bootstrap_failure(journal,context,stage,error,abort,owner_exists=False):
    """Bootstrap failure before any Owner exists; no capture/guest effect admitted.

    The idle containment child is kept until its positive abort receipt. When the
    bounded abort ends in Hold, a terminal administrative-hold.json is recorded;
    no Owner exists afterwards, so nothing can settle or advance this run.
    """
    try:journal.write('bootstrap-failure.json',encode(dict(error=type(error).__name__,stage=stage,**context)))
    except Exception:pass
    try:abort()
    except Hold as hold:
        try:journal.write('administrative-hold.json',encode(dict(schema='fresh-admin-hold-v1',
            binding=context,failure=type(error).__name__+': '+str(error),reason=str(hold),
            stage=stage,ownerExists=owner_exists,normalCleanupSucceeded=False)))
        except Exception:pass
        raise


def owner_stage(journal,context,abort,build):
    """Owner construction and wiring up to preparation, as one bootstrap stage.

    Any failure between a started idle containment and run_preparation is a
    bootstrap failure: bounded idle abort, HOLD only if the abort is unconfirmed.
    build(mark) calls mark(owner) once the Owner object exists.
    """
    created=[]
    try:return build(created.append)
    except BaseException as error:
        bootstrap_failure(journal,context,'owner',error,abort,owner_exists=bool(created));raise


def run(config_path,config_sha256):
    # Launch must already be isolated and the externally reviewed bootstrap path
    # protected. Self-hashing is deliberately not described as initial trust.
    require(sys.flags.isolated and sys.flags.no_site,'Bootstrap requires Python -I -S')
    raw=pathlib.Path(config_path).read_bytes()
    require(sha(raw)==config_sha256,'Independent configuration anchor')
    config=decode(raw)
    fields(config,('schema','sid','driver','host','driverManifest','hostManifest','review',
                   'baseline','baselineRoot','inputs','nativeOwner','admissionRoot','python','ssh','sshInputs',
                   'gitCheckout'))
    require(config['schema']=='fresh-admin-configuration-v1','Fresh configuration schema')
    ssh_inputs=ssh_input_hashes(config['sshInputs'])
    fields(config['python'],('path','sha256','treeSHA256'));fields(config['gitCheckout'],('gitDir','commonDir'))
    for name in ('driver','host'):under(config['admissionRoot'],config[name],'Code directory '+name)
    under(config['admissionRoot'],config['python']['path'],'Interpreter')
    admission=WindowsAdmission(config['sid'])
    # Code directories never get the relaxed ancestor mask (0x2/0x4 forbidden).
    admission.declare_code_directories([config['driver'],config['host'],
                                        str(pathlib.Path(config['python']['path']).parent)])
    admission.pin_source(pathlib.Path(config_path))
    require(pathlib.Path(config_path).read_bytes()==raw,'Configuration changed during admission')
    driver=pathlib.Path(config['driver']);host=pathlib.Path(config['host'])
    _,dm=anchored(config['driverManifest'],admission);_,hm=anchored(config['hostManifest'],admission)
    candidate=sha(encode(dict(driverSHA256=sha(dm),hostSHA256=sha(hm))))
    _,review_raw=anchored(config['review'],admission);review=decode(review_raw)
    fields(review,('schema','verdict','effort','candidateSHA256','nativeOwnerSHA256','pythonSHA256',
                   'pythonTreeSHA256','sshSHA256'))
    require(review==dict(schema='fresh-admin-review-v2',verdict='APPROVED',effort='HIGH',
        candidateSHA256=candidate,nativeOwnerSHA256=config['nativeOwner']['sha256'],
        pythonSHA256=config['python']['sha256'],pythonTreeSHA256=config['python']['treeSHA256'],
        sshSHA256=config['ssh']['sha256']),
        'Exact reviewed bootstrap/runtime admission')
    # Strict embeddable interpreter tree before any further module is loaded.
    _,python_tree=pinned_python(config,admission)
    # Only the four explicit trust-root modules may already be loaded. Every
    # application dependency after this point executes captured admitted bytes.
    manifest=decode(dm)
    for name in ('admin_entry','admin_recovery','admin_native','admin_bootstrap'):
        module=sys.modules.get(name)
        require(module is not None and pathlib.Path(module.__file__)==driver/(name+'.py') and
                sha(pathlib.Path(module.__file__).read_bytes())==manifest['files'][name+'.py'],
                'Bootstrap trust-root module binding')
        module.__admin_source_sha256__=manifest['files'][name+'.py']
    modules=load_pinned_modules(driver,dm,sha(dm),admission,
        ['admin_containment','admin_processes','admin_transport','resident_rpc','admin_evidence',
         'admin_handoff','preparation_entry','admin_collect','process_handles'])
    host_manifest=decode(hm);fields(host_manifest,('schema','files'))
    require(host_manifest['schema']=='fresh-admin-sources-v1','Host source closure')
    for name,digest in host_manifest['files'].items():
        require(pathlib.Path(name).name==name and ':' not in name and '\\' not in name and '/' not in name,
                'Host source basename')
        admission.pin_source(host/name);require(sha((host/name).read_bytes())==digest,'Host source digest')
    readonly=[]
    native,native_raw=readonly_anchored(config['nativeOwner'],admission,readonly)
    ssh,_=system_anchored(config['ssh'],admission,readonly)
    _,baseline=anchored(config['baseline'],admission)
    fields(config['inputs'],('capture-supervisor.py','sinks.py','prior-expected.json','retained-action.json'))
    inputs={name:anchored(ref,admission)[1] for name,ref in config['inputs'].items()}
    body=(driver/'preparation_body.py').read_bytes()
    require(sha(body)==manifest['files']['preparation_body.py'],'Original preparation body')
    owner_pin=modules['process_handles'].Handle(os.getpid())
    owner_identity=dict(pid=os.getpid(),creationFileTime=str(owner_pin.creation),imageSHA256=config['python']['sha256'])
    require(os.path.normcase(owner_pin.exe)==os.path.normcase(sys.executable),'Original owner executable')
    nonce=secrets.token_hex(32);root=driver/private_root_name(nonce)
    # Every path the run creates must fit MAX_PATH without long-path support;
    # refuse before the private root or any child exists.
    require_run_path_budget(root)
    root=admission.create_root(root)
    journal=Journal(root,admission)
    # The short directory name is derived from the nonce; the full nonce is bound here.
    journal.write('run-identity.json',encode(dict(schema='fresh-admin-run-identity-v1',
        nonce=nonce,rootName=root.name)))
    journal.write('readonly-source-pins.json',encode(dict(schema='fresh-readonly-source-pins-v1',sources=readonly)))
    journal.write('python-pins.json',encode(python_tree))
    containment=modules['admin_containment'].Containment(root,driver,admission,nonce,sha(raw),candidate,dm)
    def abort_bootstrap():
        if containment.process is not None:containment.abort_idle_bounded()
    try:
        containment.start()
    except BaseException as error:
        # No capture config/guest effect was admitted. Keep the original child
        # object until its separate positive idle-abort handshake completes.
        bootstrap_failure(journal,dict(nonce=nonce,configSHA256=sha(raw)),'containment',error,abort_bootstrap)
        raise
    def build(mark):
        bound=dict(nonce=nonce,configSHA256=sha(raw),candidateSHA256=candidate,
                   baselineSHA256=sha(baseline),owner=owner_identity,containmentOwner=containment.bound)
        evidence=modules['admin_evidence']
        resources=dict(baseline=baseline,baselineRoot=pathlib.Path(config['baselineRoot']),
            originalRun=dict(supervisorAttempted=False,stockDeploymentAttempted=False,stockPermitAttempted=False),
            entryInventory=dict(guestAttempted=False,preparationAttempted=False,captureAttempted=False,sinkAttempted=False,monitorAttempted=False),
            bodyEntered=False,controllerEntered=False,nativeLaunchAttempted=False,
            operations={},operationOwners={},observations={},c1Binding=None,
            independent=containment.process,containment=containment,ownerPin=owner_pin,
            nativeOwner=native,captureSources={name:inputs[name] for name in ('capture-supervisor.py','sinks.py')})
        resources.update(sshExecutable=ssh,sshInputs=ssh_inputs,gitCheckout=dict(config['gitCheckout']))
        owner=Owner(bound,journal,resources,evidence.validate_phase1,evidence.validate_phase2);mark(owner)
        resources['original_remote_transport']=modules['admin_transport'].OriginalTransports(owner)
        resources['spawn_owned']=modules['admin_processes'].OriginalProcesses(owner)
        modules['admin_handoff'].Handoff(owner)
        def setup(owned):
            # Inputs were pinned/hashed before containment. Publication is reserved
            # before any PS preparation child can consume these private copies.
            for name in ('prior-expected.json','retained-action.json'):journal.write(name,inputs[name])
            modules['resident_rpc'].ResidentRPC(owner,driver)
        def proof_reader(expected):
            from admin_recovery import digest
            digest(expected)
            for name in ('administrative-phase1.json','administrative-phase2.json'):
                path=root/name
                if path.is_file():
                    # Keep the pre-Pending outcome: an unreadable proof is unavailable.
                    try:data=admission.read_once(path,16*1024*1024)
                    except Pending:continue
                    if sha(data)==expected:return data
            require(False,'Original proof unavailable')
        endpoint=Endpoint(root,admission,proof_reader,modules['admin_collect'].collect_original)
        return owner,endpoint,setup
    owner,endpoint,setup=owner_stage(journal,dict(nonce=nonce,configSHA256=sha(raw)),abort_bootstrap,build)
    return modules['preparation_entry'].execute(owner,body,sha(body),driver/'preparation_body.py',endpoint,setup=setup)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--configuration',required=True);parser.add_argument('--sha256',required=True)
    args,preparation_args=parser.parse_known_args()
    sys.argv=[sys.argv[0],*preparation_args]
    return run(args.configuration,args.sha256)
