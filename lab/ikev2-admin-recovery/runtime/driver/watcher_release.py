"""Fixed-path settlement-to-independent-watcher release handshake."""
import os, pathlib, re, time
from settlement import read, safe_path, require, PROOFS
from admin_recovery import require_path, short_temporary
from protected_transport import strict, encode, sha
from live_prepare import fields, digest

REQUEST='watcher-release.json'
ACK='watcher-release-ack.json'
SAMPLE='watcher-release-sample.json'

def publish(path, raw, before_visible=lambda: None):
    path=require_path(safe_path(path))
    # Short fixed-length temporary: a long target name never pushes it past MAX_PATH.
    temporary,f=short_temporary(path)
    with f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    try:
        before_visible()
        os.link(temporary,path)  # Atomic, exclusive publication; never replace.
    finally:
        temporary.unlink()

def bindings(root, nonce):
    root=pathlib.Path(root);digest(nonce)
    blobs={n:read(root/n) for n in ('protected-cleanup.json','settlement-request.json','settlement-accepted.json','settlement-confirmed.json')}
    cleanup,request,accepted,confirmed=(strict(blobs[n]) for n in blobs)
    fields(cleanup,('nonce','rasAbsent','ownerAbsent','taskReady','drainRefs','absenceRefs'))
    require(cleanup['nonce']==nonce and all(cleanup[k] is True for k in ('rasAbsent','ownerAbsent','taskReady')),'release cleanup')
    for k in ('drainRefs','absenceRefs'):
        require(type(cleanup[k]) is dict and bool(cleanup[k]),'cleanup refs')
        for h in cleanup[k].values():digest(h)
    fields(request,('schema','nonce','protectedCleanupSHA256','durationRestoredSHA256','prelaunchBaselineSHA256','readbackSHA256'))
    require(request['schema']=='l1-settlement-request-v1' and request['nonce']==nonce and request['protectedCleanupSHA256']==sha(blobs['protected-cleanup.json']),'release request')
    for k in ('durationRestoredSHA256','prelaunchBaselineSHA256','readbackSHA256'):digest(request[k])
    fields(accepted,('schema','nonce','requestSHA256','confirmationSHA256','proofs'))
    fields(confirmed,('schema','nonce','requestSHA256','proofs'))
    require(accepted['schema']=='l1-settlement-accepted-v1' and confirmed['schema']=='l1-settlement-confirmed-v1','settlement schemas')
    require(accepted['nonce']==confirmed['nonce']==nonce and accepted['requestSHA256']==confirmed['requestSHA256']==sha(blobs['settlement-request.json']) and accepted['confirmationSHA256']==sha(blobs['settlement-confirmed.json']),'settlement binding')
    fields(accepted['proofs'],PROOFS);fields(confirmed['proofs'],PROOFS)
    require(accepted['proofs']==confirmed['proofs'],'proof references changed')
    names=set()
    for ref in accepted['proofs'].values():
        fields(ref,('name','sha256','length'));name=ref['name']
        require(type(name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,119}',name) and not name.endswith('.') and name.split('.')[0].upper() not in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(10)),*(f'LPT{i}' for i in range(10))},'proof basename')
        require(name.lower() not in names,'duplicate proof');names.add(name.lower());digest(ref['sha256'])
        data=read(root/'settlement'/name)
        require(type(ref['length']) is int and ref['length']>0 and len(data)==ref['length'] and sha(data)==ref['sha256'],'proof bytes')
        require(read(root/'settlement-validated'/name)==data,'validated proof bytes')
    return dict(schema='watcher-release-v1',nonce=nonce,protectedCleanupSHA256=sha(blobs['protected-cleanup.json']),settlementRequestSHA256=sha(blobs['settlement-request.json']),settlementAcceptedSHA256=sha(blobs['settlement-accepted.json']))

def validate_release(root,nonce):
    raw=read(pathlib.Path(root)/REQUEST);value=strict(raw)
    fields(value,('schema','nonce','protectedCleanupSHA256','settlementRequestSHA256','settlementAcceptedSHA256'))
    require(value==bindings(root,nonce),'release binding');return raw

def acknowledge(root,nonce,identity,sample):
    root=pathlib.Path(root);release=validate_release(root,nonce)
    def fresh():
        require(time.monotonic()-sample['after']<=8,'watcher release sample stale')
    fresh()
    data=encode(sample);publish(root/SAMPLE,data,before_visible=fresh)
    publish(root/ACK,encode(dict(schema='watcher-release-ack-v1',nonce=nonce,releaseSHA256=sha(release),identity=identity,sampleSHA256=sha(data))),before_visible=fresh)

def await_release(root,nonce,failure):
    root=pathlib.Path(root)
    require(not failure.event.is_set(),'lifecycle failed before release')
    identity=strict(read(root/'host-supervisor-identity.json'))
    require(identity['nonce']==nonce and identity['configSHA256']==sha(read(root/'host-supervisor-config.json')),'watcher identity binding')
    release=encode(bindings(root,nonce))
    def healthy():
        require(not failure.event.is_set(),'lifecycle failed before release publication')
    healthy()
    if (root/REQUEST).exists():
        require(read(root/REQUEST)==release,'existing release differs; retain original ownership')
    else:
        publish(root/REQUEST,release,before_visible=healthy)
    deadline=time.monotonic()+15
    while True:
        require(not failure.event.is_set(),'lifecycle failure awaiting watcher')
        require(time.monotonic()<deadline,'watcher acknowledgement timeout; retain capture')
        if (root/ACK).exists():
            value=strict(read(root/ACK));fields(value,('schema','nonce','releaseSHA256','identity','sampleSHA256'))
            require(value['schema']=='watcher-release-ack-v1' and value['nonce']==nonce and value['releaseSHA256']==sha(release) and value['identity']==identity,'watcher acknowledgement binding')
            sample=read(root/SAMPLE);require(sha(sample)==value['sampleSHA256'],'ack sample binding')
            observed=strict(sample);fields(observed,('before','after','value'))
            cfg=strict(read(root/'host-supervisor-config.json'));v=observed['value']
            require(v['Healthy'] is True and v['LiveIdentityHealthy'] is True and v['Identity']==cfg['capture'],'ack observation')
            require(read(root/REQUEST)==release,'release changed')
            require(not failure.event.is_set(),'lifecycle failed before release return')
            require(strict(read(root/'host-supervisor-identity.json'))==identity and identity['configSHA256']==sha(read(root/'host-supervisor-config.json')),'watcher identity/config changed')
            require(time.monotonic()<deadline,'watcher acknowledgement validated after deadline; retain capture')
            return
        time.sleep(.1)
