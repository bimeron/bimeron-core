"""Fixed fresh pre-stock continuation on the original preparation owner.

No historical command transcript is used. Capture operations below are derived
from preparation_body and the sealed capture-supervisor contract. Imports are
inert; advance is invoked only by the admitted original owner's private endpoint.
"""
import ntpath
import pathlib
import re
from admin_recovery import require, fields, encode, decode, sha, same
from admin_evidence import pack, unpack, validate_phase1, validate_phase2, capture_archive
from admin_collect import collect_original
from cancellation import closure_proven, freeze_controller_drain, publish_once
from sink_contract import retirement_commands


BRANCH = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*')


def _same_path(text, expected):
    return ntpath.normcase(ntpath.normpath(text)) == ntpath.normcase(ntpath.normpath(str(expected)))


def _line(raw, prefix=''):
    # Exactly one LF-terminated line; no CR, NUL or trailing content.
    text = raw.decode('utf-8')
    require(text.endswith('\n') and text.count('\n') == 1 and '\r' not in text and '\0' not in text
            and text.startswith(prefix), 'Checkout metadata line')
    return text[len(prefix):-1]


def read_checkout(admission, repo, checkout, expected, records):
    """HEAD/branch of a linked worktree from pinned files only; git is never run.

    Each file is a read-only pin (reparse/hardlink refused, held share=READ)
    whose exact content is derived from configuration and baseline:
    <repo>/.git -> configured gitDir; gitDir/gitdir -> <repo>/.git;
    gitDir/commondir -> configured commonDir; gitDir/HEAD -> the baseline branch;
    loose ref or packed-refs entry -> the baseline commit.
    """
    fields(checkout, ('gitDir', 'commonDir'))
    branch, head = expected['branch'], expected['HEAD']
    require(type(branch) is str and BRANCH.fullmatch(branch) is not None and '..' not in branch and
            not branch.endswith(('.lock', '.')), 'Baseline branch name')
    require(type(head) is str and re.fullmatch('[a-f0-9]{40}', head), 'Baseline HEAD')
    repo = pathlib.Path(repo); gitdir = pathlib.Path(checkout['gitDir']); common = pathlib.Path(checkout['commonDir'])
    limit = 64 * 1024
    def pin(path, check, size=limit):
        raw, record = admission.pin_readonly_content(path, size, check)
        records.append(record)
        return raw
    pin(repo / '.git', lambda raw: require(_same_path(_line(raw, 'gitdir: '), gitdir), 'Worktree gitdir pointer'))
    pin(gitdir / 'gitdir', lambda raw: require(_same_path(_line(raw), repo / '.git'), 'Worktree back pointer'))
    pin(gitdir / 'commondir', lambda raw: require(
        _same_path(ntpath.join(str(gitdir), _line(raw).replace('/', '\\')), common), 'Worktree common directory'))
    pin(gitdir / 'HEAD', lambda raw: require(_line(raw, 'ref: ') == 'refs/heads/' + branch, 'Worktree HEAD branch'))
    loose = common.joinpath('refs', 'heads', *branch.split('/'))
    if loose.exists() or loose.is_symlink():
        pin(loose, lambda raw: require(_line(raw) == head, 'Branch ref commit'))
        source = 'loose'
    else:
        def packed(raw):
            text = raw.decode('utf-8')
            require('\r' not in text and '\0' not in text, 'packed-refs text')
            hits = [line for line in text.split('\n') if line.endswith(' refs/heads/' + branch)
                    and not line.startswith(('#', '^'))]
            require(hits == [head + ' refs/heads/' + branch], 'Packed branch ref commit')
        pin(common / 'packed-refs', packed, 16 * 1024 * 1024)
        source = 'packed'
    return dict(gitDir=str(gitdir), commonDir=str(common), ref=source)


class Handoff:
    def __init__(self,owner):
        self.owner=owner;self.resources=owner.resources;self.proofs={}
        self.phase1=self.phase2=None
        self.sequence=0
        self.reads={}
        require('handoff' not in self.resources,'Original handoff already installed')
        self.resources['handoff']=self

    def observe(self,name,value,identity):
        """Internal fixed producers only; endpoint input cannot populate inventory."""
        if name in self.proofs:
            old=unpack(decode(self.proofs[name]))
            require(same(pack(old['value']),pack(value)) and same(old['identity'],identity),
                    'Original observation changed')
            self.owner.journal.write('observation-'+name+'.json',self.proofs[name])
            return self.proofs[name]
        self.sequence+=1
        raw=encode(dict(schema='fresh-admin-observation-v1',binding=self.owner.bound,
                        identity=identity,sequence=self.sequence,value=pack(value)))
        self.resources['observations'][name]=dict(identity=identity,sequence=self.sequence,
                                                 sha256=sha(raw),collected=True)
        self.proofs[name]=raw
        self.owner.journal.write('observation-'+name+'.json',raw)
        return raw

    def _read_remote(self,key,command,argv=None):
        """A fresh explicit read may follow a completed or failed earlier read."""
        number=self.reads.get(key,0);remote=self.resources['original_remote_transport']
        if key in ('capture-confirm','capture-health','sink-status','sink-retirement'):
            remote.permit_retirement_readback()
        try:
            return remote.fixed('admin-read-'+key+'-%d'%number,
                                argv if argv is not None else self.resources['ssh']+[command],mutation=False)
        finally:
            if remote.pending is None:self.reads[key]=number+1

    def _prepare_restore(self):
        r=self.resources;owner=self.owner
        require(all(r['originalRun'][k] is False for k in
                    ('stockDeploymentAttempted','stockPermitAttempted')),'Original stock controller required')
        entry=r['entryInventory']
        if entry['monitorAttempted']:
            r['stop'].set();r['thread'].join(timeout=.1)
            require(not r['thread'].is_alive(),'Original monitor query still draining')
        if entry['preparationAttempted'] is False and r['nativeLaunchAttempted'] is False:
            collect_original(r)
            if 'captureIdentity' not in r:
                require(entry['captureAttempted'] is True,'No original capture attempt')
                current=decode(self._read_remote('capture-original-identity','sudo cat /var/lib/step8/run-'+owner.bound['nonce']+'/identity.json'))
                health=decode(self._read_remote('capture-original-health','sudo cat /var/lib/step8/run-'+owner.bound['nonce']+'/health.json'))
                require(health.get('Nonce')==owner.bound['nonce'] and same(health.get('Identity'),current),
                        'Original capture startup identity unavailable')
                r['captureIdentity']=current
            config=dict(nonce=owner.bound['nonce'],capture=r['captureIdentity'],
                query=r['ssh']+['sudo python3 '+r['capture']+' status '+owner.bound['nonce']],
                cleanup=str(owner.journal.root/'protected-cleanup.json'),captureFinal=str(owner.journal.root/'health.json'))
            publish_once(owner.journal.root/'host-supervisor-config.json',config)
            self.observe('drain',dict(schema='fresh-admin-never-entered-v1',nonce=owner.bound['nonce']),owner.bound['owner'])
            if 'absence' not in self.proofs:
                # The retained proof is the cache; final() is never re-entered.
                final=(r['stage'].adapter.final(None) if r['originalRun']['supervisorAttempted']
                       else dict(schema='fresh-admin-no-guest-effect-v1',nonce=owner.bound['nonce']))
                self.observe('absence',final,owner.bound['owner'])
            self.observe('waiter',dict(neverSubmitted=True),owner.bound['owner'])
            r['waiterIdentity']=None
            return
        stage=r['stage']
        require(stage.thread is not None and not stage.thread.is_alive(),'Original Stage still running')
        # The independent watcher still owns capture supervision throughout.
        r['stop'].set();r['thread'].join(timeout=.1)
        require(not r['thread'].is_alive(),'Original monitor query still draining')
        collect_original(r)
        if r.get('controllerEntered') is False and not r.get('preControllerSealed',False):
            require(not r.get('cancellation_state'),'Unexpected pre-controller state')
            original=r['spawn_owned']
            process=original.observe_original('preparation')
            stage.adapter.bind_preparation(process,original.children['preparation']['argv'])
            r['cancellation_state']=dict(process=process,owners={},local={},pending={},
                completed=[],nonce=owner.bound['nonce'],out=owner.journal.root,
                request=None,status={},permit=False)
            # A sealed empty inventory may be reused; control() is never entered.
            r['preControllerSealed']=True
        c=r['cancellation_state']
        require(not c['pending'],'Original cancellation operations outstanding')
        outcome=decode((owner.journal.root/'preparation-outcome.json').read_bytes())
        no_launch=(outcome.get('nonce')==owner.bound['nonce'] and
                   outcome.get('launchNeverOccurred') is True and not c['owners'])
        require(no_launch or closure_proven(c['status'],c['nonce'],
            [role for role in c['owners'] if role!='disabled'],c['local'],c['request']),
            'Original controller drain missing')
        freeze_controller_drain(owner.journal.root,c['nonce'],c['owners'],c['local'])
        stage.before_restore()
        r['c1Binding']=stage.binding
        self.observe('drain',stage.administrative_drain,owner.bound['owner'])
        self.observe('absence',stage.administrative_absence,owner.bound['owner'])
        permit=dict(schema=1,nonce=owner.bound['nonce'],readersDrained=True)
        if 'administrative-restore-permit' not in owner.effects:
            owner.effect_once('administrative-restore-permit',lambda:publish_once(
                owner.journal.root/'restore-permit.json',permit))
        elif owner.effects['administrative-restore-permit']['state']=='ReservationFailed':
            owner.resume_reserved('administrative-restore-permit')
        require(decode((owner.journal.root/'restore-permit.json').read_bytes())==permit,
                'Original restore permit readback')
        require(type(c['process'].poll()) is int and c['process'].poll() in (0,1),'Original waiter has not positively completed')
        stage.adapter.verify_preparation_exit()
        outcome=decode((owner.journal.root/'preparation-outcome.json').read_bytes())
        require(outcome.get('nonce')==owner.bound['nonce'] and outcome.get('restored') is True,
                'Original restoration outcome')
        self.observe('waiter',dict(identity=r['waiterIdentity'],signalled=True,exitCode=c['process'].poll()),
                     owner.bound['owner'])

    def _readback(self):
        r=self.resources;resident=r['resident'];context=encode(self.owner.bound)
        policy=decode(resident.fixed('phase1-policy','restore-session-policy',context))
        require(policy.get('nonce')==self.owner.bound['nonce'] and policy.get('scope')=='Process'
                and policy.get('restored') is True,'Original policy restoration')
        local={name:decode(resident.fixed('phase1-'+name,name,context))
               for name in ('guest','services','absence')}
        self.observe('restoration',dict(wrapperSHA256=local['guest']['wrapperSHA256'],
            policy=local['guest']['policy'],task=local['guest']['task'],duration=local['absence']['task']['duration']),
            self.owner.bound['owner'])
        # A recorded eight-proof is final: a retry after a later step failed
        # reuses it. Raw nft/ip bytes naturally change between reads.
        if 'eight' not in self.proofs:
            proof=dict(local)
            proof['nft']=decode(self._read_remote('nft','sudo nft -j list ruleset'))
            for interface,key in [('labnet','labnetFeatures'),('uplink','uplinkFeatures')]:
                proof[key]=self._read_remote(key,'sudo ethtool -k '+interface)
            proof['topology']={name:decode(self._read_remote(name,cmd)) for name,cmd in
                [('links','ip -j link show'),('addresses','ip -j address show'),
                 ('routes','ip -j route show table all')]}
            baseline=unpack(decode(r['baseline']));repo=pathlib.Path(r['baselineRoot'])
            require(repo.is_absolute(),'Original source root')
            # No git process: checkout metadata is read from pinned files.
            readonly=[]
            worktree=read_checkout(self.owner.journal.admission,repo,r['gitCheckout'],baseline['git'],readonly)
            git=dict(HEAD=baseline['git']['HEAD'],branch=baseline['git']['branch'],worktree=worktree,files={})
            for name,expected in baseline['git']['files'].items():
                path=pathlib.PurePosixPath(name)
                require(not path.is_absolute() and '..' not in path.parts and ':' not in name and '\\' not in name,
                        'Baseline source relative path')
                original=repo.joinpath(*path.parts)
                # Read-only Core checkout: third-party writers tolerated, content
                # bound to the baseline hash through the held handle.
                raw,record=self.owner.journal.admission.pin_readonly_source(original,expected,16*1024*1024)
                git['files'][name]=sha(raw);readonly.append(record)
            self.owner.journal.write('readonly-core-pins.json',encode(dict(
                schema='fresh-readonly-source-pins-v1',sources=readonly)))
            proof['git']=git
            from admin_evidence import eight_proofs
            eight_proofs(proof,baseline,r['gitCheckout'])
            self.observe('eight',proof,self.owner.bound['owner'])
        # Close only after all fixed original reads. No later guest operation.
        closure=resident.close_session();resident.finish(closure)
        self._collect_closures()
        value=dict(schema='fresh-admin-phase1-v1',binding=self.owner.bound,
                   normalCleanupSucceeded=False,**{name:self.proofs[name] for name in
                   ('drain','absence','waiter','restoration','eight','closures')})
        raw=encode(pack(value));validate_phase1(raw,self.owner.bound,r)
        self.owner.journal.write('administrative-phase1.json',raw);self.phase1=raw

    def _collect_closures(self):
        r=self.resources;closures={}
        # Reservations identify every expected session owner before setup. Each
        # fixed producer supplies its own positive closure, never a request file.
        for name,entry in r['operations'].items():
            original=r['operationOwners'][name]
            value=original.administrative_closure()
            require(same(value['identity'],entry['identity']),'Original closure identity')
            closures[name]=value
        self.observe('closures',closures,self.owner.bound['owner'])

    def _retire_capture(self):
        require(self.owner.state=='PHASE1' and self.owner.phase1==self.phase1,
                'Accepted phase1 required before capture retirement')
        r=self.resources;nonce=self.owner.bound['nonce'];root=self.owner.journal.root
        commands=retirement_commands(nonce,r['capture']);remote=r['original_remote_transport']
        def retire(key):
            # Same ledger and exact bytes as the normal body; None once attempted.
            command,data=commands[key];remote.retire(key,r['ssh']+[command],data)
        unit='step10-prep-'+nonce
        remote_root='/var/lib/step8/run-'+nonce+'/'
        retire('admin-capture-confirm')
        confirmed=self._read_remote('capture-confirm','sudo cat '+remote_root+'cleanup-confirmed.json')
        require(same(decode(confirmed),decode(commands['confirmation'])),'Original cleanup confirmation readback')
        remote.resolve_retirement('admin-capture-confirm',sha(confirmed))
        health=decode(self._read_remote('capture-health','sudo cat '+remote_root+'health.json'))
        if health.get('ExitCode') is None:retire('admin-capture-stop')
        require(type(health.get('ExitCode')) is int and health['ExitCode']==0,'Original capture still pending/failed')
        archive={name:self._read_remote('archive-'+name,'sudo cat '+remote_root+name)
                 for name in ('ingress.pcap','capture.log','identity.json')}
        capture=dict(identity=decode(archive['identity.json']),health=health,
                     pcap=archive['ingress.pcap'],log=archive['capture.log'].decode('utf-8'))
        capture['archiveSHA256']=sha(encode(pack(capture)))
        capture_archive(capture,r['captureIdentity'])
        remote.resolve_retirement('admin-capture-stop',sha(encode(pack(capture))))
        self.observe('capture',capture,self.owner.bound['owner'])
        if r['entryInventory']['sinkAttempted']:
            status=self._read_remote('sink-status','sudo systemctl list-units --all --plain --no-legend --no-pager '+unit+'.service').decode()
            if status.strip():
                require(len(status.splitlines())==1 and status.split()[0]==unit+'.service','Original sink unit listing')
                retire('admin-sink-stop')
            retirement=decode(self._read_remote('sink-retirement','sudo cat '+remote_root+'sink-exit.json'))
            status=self._read_remote('sink-status','sudo systemctl list-units --all --plain --no-legend --no-pager '+unit+'.service').decode()
            require(status.strip()=='','Original sink unit still listed')
            sink=dict(unit=unit,retirement=retirement,listed=[])
        else:sink=dict(unit=unit,neverSubmitted=True)
        from admin_evidence import validate_sink
        validate_sink(sink,self.owner.bound,r)
        remote.resolve_retirement('admin-sink-stop',sha(encode(sink)))
        self.observe('sink',sink,self.owner.bound['owner'])
        for name in ('capture','sink'):self.owner.journal.write('administrative-'+name+'.json',self.proofs[name])
        context={key:r[key] for key in ('baseline','originalRun','observations','c1Binding',
                                     'waiterIdentity','operations','captureIdentity','entryInventory','nativeLaunchAttempted','gitCheckout')}
        if not hasattr(self,'watcher_context'):
            self.watcher_context=encode(pack(dict(binding=self.owner.bound,failure=self.owner.failure,resources=context)))
        self.owner.journal.write('administrative-watcher-context.json',self.watcher_context)
        self.owner.journal.write('administrative-watcher-request.json',encode(dict(
            schema='fresh-admin-watcher-request-v1',binding=self.owner.bound,phase1SHA256=sha(self.phase1),
            captureSHA256=sha(self.proofs['capture']),sinkSHA256=sha(self.proofs['sink']))))
        require(r['independent'].poll()==1,'Original watcher has not positively completed')
        ack=decode((root/'administrative-watcher-closed.json').read_bytes())
        self.observe('watcher',dict(identity=self.owner.bound['containmentOwner'],ack=ack,
                                   signalled=True,exitCode=1),self.owner.bound['owner'])
        require((r['entryInventory']['monitorAttempted'] is False or not r['thread'].is_alive()) and r['original_remote_transport'].pending is None,
                'Original operations not drained')
        self.observe('drained',dict(operations=sorted(r['operations']),monitorJoined=True,
                                   pendingTransports=[]),self.owner.bound['owner'])
        value=dict(schema='fresh-admin-phase2-v1',binding=self.owner.bound,normalCleanupSucceeded=False,
                   phase1SHA256=sha(self.phase1),**{name:self.proofs[name] for name in ('capture','sink','watcher','drained')})
        raw=encode(pack(value));validate_phase2(raw,self.phase1,self.owner.bound,r)
        self.owner.journal.write('administrative-phase2.json',raw);self.phase2=raw

    def advance(self):
        require(self.owner.failure is not None,'Administrative failed-run only')
        self.owner.journal.admission.revalidate()
        entry=self.resources['entryInventory']
        fields(entry,('guestAttempted','preparationAttempted','captureAttempted','sinkAttempted','monitorAttempted'))
        require(all(type(value) is bool for value in entry.values()),'Original entry inventory')
        if all(value is False for value in entry.values()):
            require(self.resources['nativeLaunchAttempted'] is False and
                    all(value is False for value in self.resources['originalRun'].values()),
                    'Operational authority already entered')
            remote=self.resources['original_remote_transport']
            if remote.pending is not None:remote.collect_original()
            require(all(item['mutation'] is False for item in remote.entries),'Operational command already reserved')
            resident=self.resources.get('resident')
            if resident is not None:
                require(resident.sequence==0 and resident.pending is None,'Original resident operation was submitted')
                # A resident whose start never spawned has no session to close.
                if resident.process is not None:resident.finish(resident.close_session())
            receipt=self.resources['containment'].abort_idle()
            self.bootstrap_abort=dict(schema='fresh-admin-bootstrap-aborted-v1',binding=self.owner.bound,
                failure=self.owner.failure,operationalEffectsSubmitted=False,containment=receipt,
                normalCleanupSucceeded=False)
            return dict(ready='bootstrap-aborted',sha256=sha(encode(self.bootstrap_abort)))
        if (self.owner.journal.root/'watcher-release-ack.json').exists():
            # The independent watcher already released normally; the failed-run
            # watcher disposition can no longer be proven. Distinct terminal HOLD.
            return self.owner.hold('Normal watcher release ACK already issued')
        if self.phase1 is None:
            self._prepare_restore();self._readback()
            return dict(ready='phase1',sha256=sha(self.phase1))
        require(self.owner.state=='PHASE1','Submit original phase1 for acceptance')
        if self.phase2 is None:self._retire_capture()
        return dict(ready='settle',sha256=sha(self.phase2))
