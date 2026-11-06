"""One-shot external guard installation. Import is inert; failures never restore."""
import os
import pathlib
import re
import subprocess

from protected_transport import Hold, encode, freeze, sha, strict

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = HERE.parent / 'live-config.json'
ARTIFACTS = {'renderer', 'expected', 'kernel', 'review', 'fixture', 'ca', 'topology', 'hostCode', 'events', 'ownerExe'}
VM = '<LAB_VM_ID>'
GUEST = '<LAB_GUEST_NAME>'


def fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise Hold('Live configuration schema mismatch')


def digest(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{64}', value):
        raise Hold('Invalid live digest')
    return value


def no_bools(value):
    if type(value) is bool:
        raise Hold('Boolean is not live admission evidence')
    if isinstance(value, dict):
        for v in value.values(): no_bools(v)
    if isinstance(value, list):
        for v in value: no_bools(v)


def validate_binding(binding, nonce, owner):
    fields(binding, ('SHA256', 'Nonce', 'PolicySHA256'))
    for v in binding.values(): digest(v)
    if binding['Nonce'] != digest(nonce): raise Hold('Live nonce mismatch')
    fields(owner, ('pid', 'creationFileTime', 'path', 'sha256', 'handleState', 'exitCode'))
    if owner['handleState'] != 'live' or owner['exitCode'] is not None:
        raise Hold('Retained original owner is not live')
    if (type(owner['pid']) is not int or owner['pid'] <= 0 or
            type(owner['creationFileTime']) is not str or
            not re.fullmatch('[1-9][0-9]{0,19}', owner['creationFileTime']) or
            owner['sha256'] != binding['SHA256'] or
            type(owner['path']) is not str or
            owner['path'].replace('\\', '/').lower() !=
            ('C:/BimeronFull300/' + nonce + '/full300-owner.exe').lower()):
        raise Hold('Live owner binding mismatch')


def canonical(value):
    """Preserve order and every semantic field; discard only nft volatile data."""
    def walk(v, counter=False):
        if isinstance(v, list):
            return [walk(x) for x in v if not (type(x) is dict and set(x) == {'metainfo'})]
        if type(v) is dict:
            return {k: walk(x, k == 'counter') for k, x in v.items()
                    if k != 'handle' and not (counter and k in ('packets', 'bytes'))}
        return v
    import json
    return json.dumps(walk(value), sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def substitute(value, old, new):
    if isinstance(value, list): return [substitute(v, old, new) for v in value]
    if isinstance(value, dict): return {k: substitute(v, old, new) for k, v in value.items()}
    return new if value == old else value


def stable_topology(value):
    """Ignore only address lease countdowns; preserve every other ip-j field."""
    import copy
    value = copy.deepcopy(value)
    fields(value, ('links', 'addresses', 'routes'))
    for interface in value['addresses']:
        for address in interface.get('addr_info', []):
            address.pop('valid_life_time', None)
            address.pop('preferred_life_time', None)
    return canonical(value)


def host_code_paths():
    return {p.relative_to(HERE.parent).as_posix(): p for p in
            [*HERE.glob('*.py'), *HERE.glob('*.ps1'), HERE.parent/'host/publish-live.ps1']}


def live_outcome(status, binding):
    """Restoration and establishment are independent claims."""
    if any(status.get(k) != v for k, v in binding.items()): raise Hold('Final live binding mismatch')
    live = status.get('Live')
    flags = {'Attempted', 'NoDial', 'NativeEntered', 'NativeReturned', 'ReturnedZero',
             'LiveEstablished', 'CleanupSucceeded', 'EvidenceFailed'}
    fields(live, flags | {'Binding', 'Errors'})
    if live['Binding'] != binding or any(type(live[k]) is not bool for k in flags):
        raise Hold('Final live result schema mismatch')
    if live['Errors'] is not None and (type(live['Errors']) is not list or any(type(x) is not str for x in live['Errors'])):
        raise Hold('Final live errors schema mismatch')
    safe = live['CleanupSucceeded'] and (live['NoDial'] or
           (live['NativeEntered'] and live['NativeReturned']))
    if status.get('State') != 'CLOSED' or not safe: raise Hold('Owned termination unproven')
    passed = (live['Attempted'] and not live['NoDial'] and live['NativeEntered'] and
              live['NativeReturned'] and live['LiveEstablished'] and
              not live['EvidenceFailed'] and not live['Errors'])
    return dict(establishment='PASS' if passed else 'FAIL', termination='PROVEN', native=live)


def partition(value, table):
    fields(value, ('nftables',))
    if type(value['nftables']) is not list: raise Hold('Invalid nft readback')
    owned, other = [], []
    for item in value['nftables']:
        if type(item) is not dict or len(item) != 1: raise Hold('Invalid nft object')
        kind, obj = next(iter(item.items()))
        if kind == 'metainfo': continue
        if type(obj) is not dict: raise Hold('Invalid nft object body')
        target = obj.get('name') if kind == 'table' else obj.get('table')
        (owned if target == table else other).append(item)
    return {'nftables': owned}, {'nftables': other}


def load_config(path=CONFIG):
    path = pathlib.Path(path)
    c = strict(path.read_bytes())
    no_bools(c)
    fields(c, ('schema', 'templateTable', 'artifacts'))
    if c['schema'] != 'l1-live-config-v1' or type(c['templateTable']) is not str or not re.fullmatch(r'ikeq_[a-z][a-z0-9_]{0,24}', c['templateTable']):
        raise Hold('Invalid live config version/table')
    fields(c['artifacts'], ARTIFACTS)
    blobs = {}
    for name, ref in c['artifacts'].items():
        fields(ref, ('path', 'sha256'))
        digest(ref['sha256'])
        if type(ref['path']) is not str or not ref['path']: raise Hold('Invalid artifact path')
        p = pathlib.Path(ref['path'])
        raw = (p if p.is_absolute() else path.parent / p).read_bytes()
        if sha(raw) != ref['sha256']: raise Hold('Live artifact changed: ' + name)
        blobs[name] = raw
    code = strict(blobs['hostCode']); no_bools(code)
    fields(code, ('schema', 'files'))
    if code['schema'] != 'l1-host-code-v1': raise Hold('Host code manifest version')
    paths = host_code_paths()
    fields(code['files'], paths)
    for name, p in paths.items():
        if sha(p.read_bytes()) != digest(code['files'][name]): raise Hold('Reviewed host code changed: '+name)
    f = strict(blobs['fixture']); no_bools(f)
    fields(f, ('schema', 'vm', 'guest', 'principalSid', 'guestIP', 'guestMAC', 'peer', 'profile', 'serverName', 'caSHA256', 'lab', 'uplink'))
    fixed = dict(schema='l1-live-fixture-v1', vm=VM, guest=GUEST,
                 principalSid='<LAB_GUEST_SID_1001>',
                 guestIP='192.0.2.2', guestMAC='<LAB_GUEST_MAC>', peer='<LAB_PUBLIC_IP>',
                 profile='Bimeron Step8', serverName='ikev2.bimeron.test', lab='labnet', uplink='uplink',
                 caSHA256=c['artifacts']['ca']['sha256'])
    if f != fixed: raise Hold('Lab fixture mismatch')
    expected = strict(blobs['expected'])
    own, other = partition(expected, c['templateTable'])
    if other['nftables'] or not own['nftables']: raise Hold('Expected template includes other objects or is empty')
    k = strict(blobs['kernel']); no_bools(k)
    fields(k, ('schema', 'result', 'rendererSHA256', 'expectedSHA256', 'fixtureSHA256', 'topologySHA256', 'eventsSHA256', 'tests'))
    if k['schema'] != 'l1-kernel-result-v1' or k['result'] != 'PASS': raise Hold('Kernel fixture not passed')
    for name in ('renderer', 'expected', 'fixture', 'topology', 'events'):
        if k[name+'SHA256'] != c['artifacts'][name]['sha256']: raise Hold('Kernel fixture binding mismatch')
    required = {'valid500', 'valid4500', 'esp', 'udpESP', 'keepalive', 'truncated', 'markerOnly',
                'wrongVersion', 'wrongExchange', 'firstFragment', 'laterFragment', 'ipv6', 'dnsInput', 'existingFlow'}
    fields(k['tests'], required)
    if any(v != 'PASS' for v in k['tests'].values()): raise Hold('Kernel controls incomplete')
    review = strict(blobs['review']); no_bools(review)
    fields(review, ('schema', 'effort', 'verdict', 'artifacts'))
    if (review['schema'], review['effort'], review['verdict']) != ('l1-review-v1', 'HIGH', 'APPROVED'):
        raise Hold('HIGH review required')
    fields(review['artifacts'], ARTIFACTS - {'review'})
    for name, h in review['artifacts'].items():
        if h != c['artifacts'][name]['sha256']: raise Hold('Review artifact binding mismatch')
    topology = strict(blobs['topology'])
    fields(topology, ('links', 'addresses', 'routes'))
    return c, blobs, f


def absolute_executable(path, what='executable'):
    """A local child image is always an absolute local path, never a PATH/cwd lookup."""
    path = str(path)
    if not pathlib.PureWindowsPath(path).is_absolute() or path.startswith(('\\', '/')):
        raise Hold('Absolute '+what+' path required')
    return path


def ssh_command(command, ssh):
    # Same protected observer identity/options as preparation.py. Commands below
    # are constants; the rule batch travels on stdin, never through a shell.
    key = pathlib.Path(os.environ['LOCALAPPDATA']) / 'Bimeron/step8-observer-20261103'
    return [absolute_executable(ssh, 'ssh'), '-F', 'none', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3', '-o',
            'StrictHostKeyChecking=yes', '-o', 'HostKeyAlias=step8-observer', '-o',
            'UserKnownHostsFile='+str(key/'known_hosts2'), '-i', str(key/'client2'),
            'lab@192.168.196.130', command]


def prepare_live(binding, nonce, owner_identity, *, ssh, out=None, config_path=CONFIG, runner=None):
    """Call only after original drain and command50. Never retries or rolls back."""
    runner = runner or subprocess.run
    # The admitted private run root (bound by its run-identity.json) is passed in;
    # no root name is derived here.
    if not out: raise Hold('Admitted private run root required')
    absolute_executable(ssh, 'ssh')
    validate_binding(binding, nonce, owner_identity)
    binding = {k: binding[k] for k in ('SHA256', 'Nonce', 'PolicySHA256')}
    c, blobs, fixture = load_config(config_path)
    if c['artifacts']['ownerExe']['sha256'] != binding['SHA256']:
        raise Hold('Reviewed executable differs from current owner')
    out = pathlib.Path(out)
    evidence = out / 'live'
    evidence.mkdir(parents=True, exist_ok=True)
    # Exclusive attempt latch, including an uncertain installer/publisher result.
    with (evidence/'attempt.json').open('xb') as s:
        s.write(encode(dict(binding=binding, owner=owner_identity)))
    for name, raw in blobs.items(): freeze(evidence/(name+'.frozen'), raw)
    freeze(evidence/'config.json', pathlib.Path(config_path).read_bytes())
    table = 'ikeq_l' + nonce[:16]
    namespace = {'__name__': 'reviewed_renderer'}
    exec(compile(blobs['renderer'], '<reviewed-renderer>', 'exec'), namespace)
    rules = namespace['render']('l'+nonce[:16], fixture['lab'], fixture['uplink']).encode()
    freeze(evidence/'guard.nft', rules)
    expected = substitute(strict(blobs['expected']), c['templateTable'], table)
    freeze(evidence/'expected.json', canonical(expected))

    def remote(command, name, data=None):
        r = runner(ssh_command(command, ssh), input=b'' if data is None else data, capture_output=True, timeout=15, check=False)
        freeze(evidence/name, r.stdout)
        if r.returncode: raise Hold('Observer operation failed; guard retained, no retry')
        return r.stdout

    topology = dict(links=strict(remote('ip -j link show', 'links.json')),
                    addresses=strict(remote('ip -j address show', 'addresses.json')),
                    routes=strict(remote('ip -j route show table all', 'routes.json')))
    if stable_topology(topology) != stable_topology(strict(blobs['topology'])): raise Hold('Observer topology changed')
    before = strict(remote('sudo nft -j list ruleset', 'before.raw.json'))
    owned, baseline = partition(before, table)
    if owned['nftables']: raise Hold('Run table already exists')
    freeze(evidence/'before.json', canonical(baseline))
    for interface in ('labnet', 'uplink'):
        raw = remote('sudo ethtool -k '+interface, interface+'-before.txt')
        match = re.search(rb'^generic-receive-offload: (on|off)(?: \[fixed\])?\r?$', raw, re.M)
        if not match: raise Hold('GRO readback missing')
        if match[1] == b'on': remote('sudo ethtool -K '+interface+' gro off', interface+'-disable.txt')
        after = remote('sudo ethtool -k '+interface, interface+'-after.txt')
        if not re.search(rb'^generic-receive-offload: off(?: \[fixed\])?\r?$', after, re.M):
            raise Hold('GRO still enabled')
    remote('sudo nft --check -f -', 'compile.txt', rules)
    remote('sudo nft -f -', 'install.txt', rules)
    # Separate invocation after the installer has exited proves persistent state.
    after = strict(remote('sudo nft -j list ruleset', 'after.raw.json'))
    installed, remaining = partition(after, table)
    freeze(evidence/'after.json', canonical(remaining))
    readback = canonical(installed)
    freeze(evidence/'readback.json', readback)
    if canonical(remaining) != canonical(baseline) or readback != canonical(expected):
        raise Hold('Exact guard/baseline readback failed; retain guard, no cleanup')
    admission = dict(Binding=binding, GuardSHA256=sha(readback),
                     FixtureSHA256=c['artifacts']['fixture']['sha256'],
                     ReviewedSHA256=c['artifacts']['review']['sha256'])
    proof = dict(admission=admission, owner=owner_identity, fixture=fixture,
                 rulesSHA256=sha(rules), beforeSHA256=sha(canonical(baseline)),
                 afterSHA256=sha(canonical(remaining)), table=table)
    proof_path = freeze(evidence/'verified.json', encode(proof))
    from stock_controller import operational_controller
    return operational_controller(binding, nonce, proof_path)
