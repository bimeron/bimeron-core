"""Local evidence barrier only. No operator actions or capture ownership."""
import pathlib
import re
import stat
import time

from protected_transport import Hold, encode, freeze, sha, strict
from live_prepare import canonical, stable_topology, fields, digest, partition

SID = '<LAB_GUEST_SID_1001>'
COMPUTER = '<LAB_GUEST_NAME>'
SERVICES = dict(BFE='Running', RasMan='Running', IKEEXT='Stopped', PolicyAgent='Stopped')
PROOFS = {'nft', 'labnetFeatures', 'uplinkFeatures', 'topology', 'services', 'guest', 'absence', 'git'}
LIMIT = 180
POLL = .25


def require(ok, reason):
    if not ok:
        raise Hold('Settlement HOLD: ' + reason)


def safe_path(path):
    path = pathlib.Path(path).absolute()
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not
                getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
                'reparse/symlink path')
    return path


def read(path):
    path = safe_path(path)
    require(path.is_file(), 'missing regular evidence: ' + path.name)
    return path.read_bytes()


def retain(path, raw):
    return freeze(safe_path(path), raw)


def integer(value, expected):
    return type(value) is int and value == expected


def same(a, b):
    # Python equality otherwise equates False with 0 and True with 1.
    import json
    return json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False)


def guest(value):
    require(type(value) is dict, 'guest object')
    required = {'systemRoot', 'testSid', 'computer', 'adminTemp', 'utc', 'shells',
                'query', 'wrapperSHA256', 'task', 'queryExit', 'policy', 'testTemp'}
    require(required <= set(value) <= required | {'PSComputerName', 'RunspaceId', 'PSShowComputerName'}, 'guest fields')
    require(all(type(value[k]) is str and value[k] for k in
                ('systemRoot', 'testSid', 'computer', 'adminTemp', 'utc', 'testTemp')), 'guest string types')
    require(value['testSid'] == SID and value['computer'] == COMPUTER, 'guest identity')
    require(integer(value['queryExit'], 0), 'query exit')
    require(type(value['query']) is str and len(re.findall(
        r'^\s*>?\s*test\s+\S+\s+2\s+Active\s+.+$', value['query'], re.M)) == 1, 'active test session 2')
    require(type(value['shells']) is list and bool(value['shells']), 'explorer shells')
    matching = False
    for shell in value['shells']:
        fields(shell, ('sid', 'pid', 'result', 'session'))
        require(type(shell['sid']) is str and all(type(shell[k]) is int for k in ('pid','result','session'))
                and shell['pid'] > 0, 'explorer types')
        matching |= shell['sid'] == SID and integer(shell['session'], 2) and integer(shell['result'], 0)
    require(matching, 'explorer identity')
    task = value['task']
    fields(task, ('sddl', 'state', 'xml', 'instances', 'settings'))
    require(integer(task['state'], 3) and integer(task['instances'], 0), 'task not idle')
    require(all(type(task[k]) is str and task[k] for k in ('sddl', 'xml', 'settings')), 'task strings')
    settings = strict(task['settings'])
    require(type(settings) is dict and settings.get('ExecutionTimeLimit') == 'PT3M', 'task duration')
    require(type(value['wrapperSHA256']) is str and re.fullmatch('[A-Fa-f0-9]{64}', value['wrapperSHA256']), 'wrapper hash')
    policies = value['policy']
    require(type(policies) is list and len(policies) == 5, 'policy list')
    scopes = set()
    for item in policies:
        fields(item, ('Scope', 'ExecutionPolicy'))
        for key in item:
            fields(item[key], ('value', 'Value'))
            require(type(item[key]['value']) is int and type(item[key]['Value']) is str, 'PS enum types')
        scope = item['Scope']
        require((scope['value'], scope['Value']) in {(4, 'MachinePolicy'), (3, 'UserPolicy'),
                (0, 'Process'), (1, 'CurrentUser'), (2, 'LocalMachine')}, 'policy scope')
        scopes.add(scope['Value'])
        policy = item['ExecutionPolicy']
        require((policy['value'], policy['Value']) in {(0, 'Unrestricted'), (1, 'RemoteSigned'),
                (2, 'AllSigned'), (3, 'Restricted'), (4, 'Bypass'), (5, 'Undefined')}, 'policy enum')
    require(len(scopes) == 5, 'duplicate policy scope')
    return value


def git_record(value):
    fields(value, ('HEAD', 'branch', 'status', 'files'))
    require(type(value['HEAD']) is str and re.fullmatch('[a-f0-9]{40}', value['HEAD']), 'Git HEAD')
    require(type(value['branch']) is str and bool(value['branch']) and type(value['status']) is str, 'Git text')
    require(type(value['files']) is dict and len(value['files']) == 20, 'Git exact twenty files')
    for name, h in value['files'].items():
        require(type(name) is str and not name.startswith('/') and '\\' not in name
                and ':' not in name and all(p not in ('', '.', '..') for p in name.split('/')), 'Git relative path')
        digest(h)


def baseline(raw):
    value = strict(raw)
    fields(value, ('schema', 'guest', 'services', 'git'))
    require(value['schema'] == 'l1-settlement-baseline-v1', 'baseline version')
    guest(value['guest'])
    require(same(value['services'], SERVICES), 'service baseline')
    git_record(value['git'])
    return value


def absence(value, original):
    required = {'wrapper', 'owners', 'shells', 'ras', 'guest', 'dedicatedTasks', 'task', 'console', 'reference'}
    require(type(value) is dict and required <= set(value) <= required | {'PSComputerName', 'RunspaceId', 'PSShowComputerName'}, 'absence fields')
    require(value['guest'] == COMPUTER and value['owners'] == [] and value['dedicatedTasks'] == [], 'owner/task absence')
    require(value['ras'] in ('No connections\r\nCommand completed successfully.\r\n',
                             'No connections\nCommand completed successfully.\n'), 'RAS absence')
    task = value['task']
    fields(task, ('state', 'duration', 'xml', 'instances', 'sddl'))
    require(integer(task['state'], 3) and integer(task['instances'], 0) and task['duration'] == 'PT3M', 'ordinary task')
    require(value['wrapper'] == original['wrapperSHA256'] and
            all(task[k] == original['task'][k] for k in ('xml', 'sddl')), 'absence restoration cross-check')


def prerequisites(out, nonce, baseline_path):
    digest(nonce)
    names = ['protected-cleanup.json', 'duration-restored.json', 'live/readback.json',
             'live/verified.json', 'live/before.json', 'live/after.json', 'live/expected.json',
             'live/guard.nft', 'live/topology.frozen', 'live/labnet-before.txt', 'live/uplink-before.txt']
    blobs = {name: read(out / name) for name in names}
    blobs['prelaunch-baseline.json'] = read(baseline_path)
    base = baseline(blobs['prelaunch-baseline.json'])
    stock_root = out / 'live' / 'stock'
    if (stock_root / 'precleanup.json').is_file():
        from stock_receipt import validate as validate_stock, read_ref
        provenance = read(out / 'stock-administrative-provenance.json')
        stock = strict(provenance)
        pre = strict(read(stock_root / 'precleanup.json'))
        if pre['schema'] == 'stock-admin-precleanup-v1':
            require(stock == strict(read(stock_root / 'final.json')), 'stock final companion mismatch')
            validate_stock(stock, stock_root, pre['binding'], nonce, 'final')
        elif pre['schema'] == 'stock-no-permit-precleanup-v1':
            from stock_receipt import validate_no_permit
            require(stock == strict(read(stock_root / 'final.json')), 'no-permit final companion mismatch')
            validate_no_permit(stock, stock_root, pre['binding'], nonce, 'final')
        else:
            require(pre['schema'] == 'stock-no-launch-v1' and stock['schema'] == 'stock-no-launch-final-v1'
                    and stock['nonce'] == nonce and stock['normalCleanupSucceeded'] is False,
                    'stock no-launch companion')
            from stock_controller import validate_receipt
            validate_receipt(pre, pre['binding'], nonce, root=stock_root)
            c1 = read_ref(stock_root, stock['c1'])
            native = read_ref(stock_root, c1['nativeStatus'])
            require(native['State'] == 'CLOSED' and native['Live']['NoDial'] is True
                    and native['Live']['Attempted'] is False and native['Live']['CleanupSucceeded'] is True,
                    'no-stock C1 NoDial')
        blobs['stock-administrative-provenance.json'] = provenance
    cleanup = strict(blobs['protected-cleanup.json'])
    fields(cleanup, ('nonce', 'rasAbsent', 'ownerAbsent', 'taskReady', 'drainRefs', 'absenceRefs'))
    require(cleanup['nonce'] == nonce and all(cleanup[k] is True for k in ('rasAbsent', 'ownerAbsent', 'taskReady')), 'positive protected cleanup')
    for key in ('drainRefs', 'absenceRefs'):
        require(type(cleanup[key]) is dict and bool(cleanup[key]), 'cleanup references')
        for h in cleanup[key].values():
            digest(h)
    ack = strict(blobs['duration-restored.json'])
    fields(ack, ('schema', 'nonce', 'restored', 'duration', 'restoredUtc'))
    require(type(ack['restoredUtc']) is str and bool(ack['restoredUtc']), 'duration timestamp')
    require(integer(ack['schema'], 1) and ack['nonce'] == nonce and ack['restored'] is True and ack['duration'] == 'PT3M', 'duration acknowledgement')
    verified = strict(blobs['live/verified.json'])
    admission = verified['admission']
    require(admission['Binding']['Nonce'] == nonce and verified['table'] == 'ikeq_l' + nonce[:16], 'installed guard nonce')
    for key, name in (('GuardSHA256', 'readback.json'),):
        require(admission[key] == sha(blobs['live/' + name]), 'guard binding')
    for key, name in (('beforeSHA256', 'before.json'), ('afterSHA256', 'after.json'), ('rulesSHA256', 'guard.nft')):
        require(verified[key] == sha(blobs['live/' + name]), 'guard verification input')
    require(blobs['live/before.json'] == blobs['live/after.json'] and
            blobs['live/readback.json'] == blobs['live/expected.json'], 'installed guard verification')
    own, other = partition(strict(blobs['live/readback.json']), verified['table'])
    require(bool(own['nftables']) and not other['nftables'], 'installed owned guard')
    tables = [item['table'] for item in own['nftables'] if 'table' in item]
    require(len(tables) == 2 and {t.get('family') for t in tables} == {'inet', 'netdev'}, 'two installed guard tables')
    own, _ = partition(strict(blobs['live/before.json']), verified['table'])
    require(not own['nftables'], 'guard in baseline')
    for name, raw in blobs.items():
        retain(out / 'settlement-inputs' / name, raw)
    return blobs, base


def confirmation(out, nonce, request, raw, blobs, base):
    value = strict(raw)
    fields(value, ('schema', 'nonce', 'requestSHA256', 'proofs'))
    require(value['schema'] == 'l1-settlement-confirmed-v1' and value['nonce'] == nonce
            and value['requestSHA256'] == sha(request), 'confirmation binding')
    fields(value['proofs'], PROOFS)
    payloads, names = {}, set()
    for key, ref in value['proofs'].items():
        fields(ref, ('name', 'sha256', 'length'))
        name = ref['name']
        require(type(name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,119}', name)
                and not name.endswith('.') and name.split('.')[0].upper() not in
                {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(10)), *(f'LPT{i}' for i in range(10))}, 'proof basename')
        require(name.lower() not in names, 'duplicate proof basename')
        names.add(name.lower())
        digest(ref['sha256'])
        require(type(ref['length']) is int and ref['length'] > 0, 'proof length')
        data = read(out / 'settlement' / name)
        require(len(data) == ref['length'] and sha(data) == ref['sha256'], 'proof bytes')
        payloads[key] = data
    nft = strict(payloads['nft'])
    partition(nft, 'ikeq_l' + nonce[:16])
    require(canonical(nft) == canonical(strict(blobs['live/before.json'])), 'nft baseline')
    for key, name in (('labnetFeatures', 'labnet'), ('uplinkFeatures', 'uplink')):
        require(payloads[key] == blobs['live/' + name + '-before.txt'], 'feature baseline')
    require(stable_topology(strict(payloads['topology'])) == stable_topology(strict(blobs['live/topology.frozen'])), 'topology baseline')
    require(same(strict(payloads['services']), base['services']), 'service restoration')
    current = guest(strict(payloads['guest']))
    require(all(same(current[k], base['guest'][k]) for k in ('task', 'wrapperSHA256', 'policy')), 'guest restoration')
    absence(strict(payloads['absence']), base['guest'])
    git = strict(payloads['git']); git_record(git)
    require(same(git, base['git']), 'Git restoration')
    for key, data in payloads.items():
        retain(out / 'settlement-validated' / value['proofs'][key]['name'], data)
    retain(out / 'settlement-inputs' / 'settlement-confirmed.json', raw)
    return dict(schema='l1-settlement-accepted-v1', nonce=nonce, requestSHA256=sha(request),
                confirmationSHA256=sha(raw), proofs=value['proofs'])


def await_settlement(out, nonce, failure, baseline_path):
    """One bounded attempt; failure never calls any stop or restores anything."""
    started = time.monotonic()
    out = pathlib.Path(out)
    try:
        def healthy():
            require(not failure.event.is_set(), 'original lifecycle failure; capture retained')
            require(time.monotonic() - started < LIMIT, '180 second timeout; capture retained')
        healthy()
        blobs, base = prerequisites(out, nonce, baseline_path)
        request = encode(dict(schema='l1-settlement-request-v1', nonce=nonce,
            protectedCleanupSHA256=sha(blobs['protected-cleanup.json']),
            durationRestoredSHA256=sha(blobs['duration-restored.json']),
            prelaunchBaselineSHA256=sha(blobs['prelaunch-baseline.json']),
            readbackSHA256=sha(blobs['live/readback.json'])))
        healthy()
        retain(out / 'settlement-request.json', request)
        path = safe_path(out / 'settlement-confirmed.json')
        while True:
            healthy()
            if path.exists():
                accepted = confirmation(out, nonce, request, read(path), blobs, base)
                # Detect replacement of original inputs during the operator interval.
                for name, raw in blobs.items():
                    original = baseline_path if name == 'prelaunch-baseline.json' else out / name
                    require(read(original) == raw, 'prerequisite changed during wait')
                require(read(out / 'settlement-request.json') == request, 'request changed')
                require(sha(read(path)) == accepted['confirmationSHA256'], 'confirmation changed')
                stock_root = out / 'live/stock'
                provenance_name = 'stock-administrative-provenance.json'
                established = strict(blobs[provenance_name]) if provenance_name in blobs else None
                final_schemas = {'stock-admin-receipt-v1', 'stock-no-permit-receipt-v1'}
                if (stock_root / 'final.json').is_file() or (established is not None and established.get('schema') in final_schemas):
                    from stock_receipt import validate as validate_stock, validate_no_permit
                    require(established is not None, 'stock final without validated provenance')
                    stock = strict(read(out / provenance_name))
                    require(stock == strict(read(stock_root / 'final.json')), 'stock final companion mismatch')
                    pre = strict(read(stock_root / 'precleanup.json'))
                    validators = {
                        'stock-admin-receipt-v1': ('stock-admin-precleanup-v1', validate_stock),
                        'stock-no-permit-receipt-v1': ('stock-no-permit-precleanup-v1', validate_no_permit),
                    }
                    require(stock.get('schema') in validators, 'unknown stock final schema')
                    pre_schema, validate_final = validators[stock['schema']]
                    require(pre.get('schema') == pre_schema, 'stock settlement branch mismatch')
                    validate_final(stock, stock_root, pre['binding'], nonce, 'final')
                healthy()
                retain(out / 'settlement-accepted.json', encode(accepted))
                healthy()
                return
            time.sleep(min(POLL, max(0, LIMIT - (time.monotonic() - started))))
    except Exception as exc:
        failure.set(exc)
        raise Hold('Settlement HOLD: capture continuation refused; guard state requires actual readback') from exc
