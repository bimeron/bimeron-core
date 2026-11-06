"""Pure fresh-run administrative validation; never emits normal settlement."""
import base64
import re
import struct

from admin_recovery import decode, encode, sha, fields, require, same, binding
from protected_evidence import check_exact_drain, check_independent_absence
from settlement import guest, git_record, absence, PROOFS
from live_prepare import canonical, stable_topology, partition


def unpack(value):
    if type(value) is dict:
        if '$bytes' in value:
            fields(value, ('$bytes',))
            require(type(value['$bytes']) is str, 'Byte encoding')
            raw = base64.b64decode(value['$bytes'], validate=True)
            require(base64.b64encode(raw).decode() == value['$bytes'], 'Canonical base64')
            return raw
        return {k: unpack(v) for k, v in value.items()}
    if type(value) is list:
        return [unpack(v) for v in value]
    return value


def pack(value):
    if type(value) is bytes:
        return {'$bytes': base64.b64encode(value).decode()}
    if type(value) is dict:
        require('$bytes' not in value, 'Reserved byte key')
        return {k: pack(v) for k, v in value.items()}
    if type(value) is list:
        return [pack(v) for v in value]
    return value


def envelope(raw, bound, schema, names):
    binding(bound)
    value = decode(raw)
    fields(value, ('schema', 'binding', 'normalCleanupSucceeded', *names))
    require(value['schema'] == schema and same(value['binding'], bound), 'Evidence binding')
    require(value['normalCleanupSucceeded'] is False, 'Administrative only')
    return unpack(value)


def original_observation(name, raw, bound, inventory):
    """Only output retained by the original owner can supply a proof.

    The inventory is owned memory populated by collection, never a request field.
    A hash anchors bytes; authenticated original operation identity anchors trust.
    """
    require(name in inventory, 'Original observation missing: ' + name)
    entry = inventory[name]
    fields(entry, ('identity', 'sequence', 'sha256', 'collected'))
    require(entry['collected'] is True and type(entry['sequence']) is int and
            entry['sequence'] > 0 and entry['sha256'] == sha(raw), 'Original collection')
    value = decode(raw)
    fields(value, ('schema', 'binding', 'identity', 'sequence', 'value'))
    require(value['schema'] == 'fresh-admin-observation-v1' and
            same(value['binding'], bound) and
            same(value['identity'], entry['identity']) and
            type(value['sequence']) is int and value['sequence'] == entry['sequence'],
            'Observation provenance')
    return unpack(value['value']), value['sequence']


def eight_proofs(proofs, baseline, checkout):
    fields(proofs, PROOFS)
    fields(baseline, PROOFS)
    # These comparisons are extracted from normal settlement, with no normal
    # prerequisite files, writes, receipts, or stale U4/U8 fallback.
    partition(proofs['nft'], '__admin_no_owned_table__')
    require(canonical(proofs['nft']) == canonical(baseline['nft']), 'nft restoration')
    for key in ('labnetFeatures', 'uplinkFeatures'):
        require(type(proofs[key]) is bytes and proofs[key] and
                proofs[key] == baseline[key], 'Feature restoration')
    require(stable_topology(proofs['topology']) == stable_topology(baseline['topology']),
            'Topology restoration')
    require(same(proofs['services'], baseline['services']), 'Service restoration')
    current = guest(proofs['guest'])
    original = guest(baseline['guest'])
    require(all(same(current[k], original[k]) for k in ('task', 'wrapperSHA256', 'policy')),
            'Guest restoration')
    absence(proofs['absence'], original)
    admin_git(proofs['git'], baseline['git'], checkout)


def admin_git(proof, baseline, checkout):
    """Administrative checkout proof: pinned metadata, no git process.

    HEAD, branch and the twenty source hashes must equal the baseline. The
    baseline 'status' text is not re-proven: no git status is ever run, so
    "no other changes in the checkout" is outside this proof.
    """
    git_record(baseline)
    fields(proof, ('HEAD', 'branch', 'files', 'worktree'))
    require(all(same(proof[key], baseline[key]) for key in ('HEAD', 'branch', 'files')),
            'Twenty source hashes/HEAD/branch')
    worktree = proof['worktree']
    fields(worktree, ('gitDir', 'commonDir', 'ref'))
    require(type(worktree['gitDir']) is str and type(worktree['commonDir']) is str and
            worktree['ref'] in ('loose', 'packed'), 'Worktree metadata record')
    fields(checkout, ('gitDir', 'commonDir'))
    require(worktree['gitDir'] == str(checkout['gitDir']) and worktree['commonDir'] == str(checkout['commonDir']),
            'Worktree metadata differs from configuration')


def validate_phase1(raw, bound, resources):
    value = envelope(raw, bound, 'fresh-admin-phase1-v1',
                     ('drain', 'absence', 'waiter', 'restoration', 'closures', 'eight'))
    baseline_raw = resources['baseline']
    require(sha(baseline_raw) == bound['baselineSHA256'], 'Fresh baseline digest')
    baseline = unpack(decode(baseline_raw))
    run = resources['originalRun']
    fields(run, ('supervisorAttempted','stockDeploymentAttempted','stockPermitAttempted'))
    require(all(type(v) is bool for v in run.values()) and
            run['stockDeploymentAttempted'] is False and run['stockPermitAttempted'] is False,
            'Fresh pre-stock disposition only; use original stock controller after deployment')
    inventory = resources['observations']
    entry=resources['entryInventory']
    fields(entry,('guestAttempted','preparationAttempted','captureAttempted','sinkAttempted','monitorAttempted'))
    require(all(type(v) is bool for v in entry.values()) and entry['captureAttempted'] is True,
            'Original attempt inventory')
    seen = []
    def observe(name, data):
        result, sequence = original_observation(name, data, bound, inventory)
        seen.append(sequence)
        return result
    drain = observe('drain', value['drain'])
    final = observe('absence', value['absence'])
    never_entered=drain.get('schema')=='fresh-admin-never-entered-v1'
    no_supervisor=False
    if never_entered:
        require(drain==dict(schema='fresh-admin-never-entered-v1',nonce=bound['nonce']) and
                entry['preparationAttempted'] is False and resources['nativeLaunchAttempted'] is False,
                'Original preparation/native launch never-entered seal')
        no_supervisor=run['supervisorAttempted'] is False
        if no_supervisor:require(final==dict(schema='fresh-admin-no-guest-effect-v1',nonce=bound['nonce']),
                                 'Original no-supervisor-effect seal')
    else:require(check_exact_drain(drain, bound['nonce'])['status'] == 'PASS', 'Original drain')
    c1 = resources['c1Binding']
    if c1 is None and not never_entered:
        proof=decode(final['proof'])
        if proof.get('schema')=='full300-no-supervisor-attempt-v1':
            require(run['supervisorAttempted'] is False,'Missing binding is not no-attempt authority')
    if never_entered:require(c1 is None,'Never-entered native binding conflict')
    if not no_supervisor:
        checked = check_independent_absence(final, c1, bound['nonce'])
        require(checked['status'] == 'PASS' and all(checked[k] is True for k in
                ('rasAbsent', 'ownerAbsent', 'taskReady')), 'Independent absence')
    if c1 is not None:
        status_ref = decode(final['proof'])['nativeStatus']
        status = decode(final['files'][status_ref['name']])
        require(status['Live']['NoDial'] is True and status['Live']['Attempted'] is False
                and status['Live']['NativeEntered'] is False and
                status['Live']['CleanupSucceeded'] is True, 'C1 original NoDial close')
    waiter = observe('waiter', value['waiter'])
    if never_entered:
        require(waiter==dict(neverSubmitted=True) and resources['waiterIdentity'] is None,'Never-submitted waiter')
    else:
        fields(waiter, ('identity', 'signalled', 'exitCode'))
        require(same(waiter['identity'], resources['waiterIdentity']) and
                waiter['signalled'] is True and type(waiter['exitCode']) is int and
                waiter['exitCode'] in (0,1), 'Original waiter terminal restoration')
    restore = observe('restoration', value['restoration'])
    fields(restore, ('wrapperSHA256', 'policy', 'task', 'duration'))
    expected = baseline['guest']
    require(restore['duration'] == 'PT3M' and all(same(restore[k], expected[k]) for k in
            ('wrapperSHA256', 'policy', 'task')), 'Original task/wrapper/policy restoration')
    eight = observe('eight', value['eight'])
    eight_proofs(eight, baseline, resources['gitCheckout'])
    closures = observe('closures', value['closures'])
    # Inventory comes from reservations before setup; unknown submissions cannot
    # disappear or acquire NeverSubmitted status through a proof.
    fields(closures, resources['operations'])
    for name, original in resources['operations'].items():
        current = closures[name]
        fields(current, ('identity', 'submission', 'terminal', 'sessionState', 'pending'))
        require(original['submission'] == 'Submitted' and
                current['submission'] == 'Submitted' and
                same(current['identity'], original['identity']) and
                current['terminal'] == 'Collected' and current['sessionState'] == 'Closed'
                and current['pending'] is False, 'Original operation/session closure: ' + name)
    require(seen == sorted(set(seen)), 'Phase1 observation order')
    return dict(phase=1, phase1SHA256=sha(raw), normalCleanupSucceeded=False)


def capture_archive(value, expected):
    fields(value, ('identity', 'health', 'pcap', 'log', 'archiveSHA256'))
    require(same(value['identity'], expected), 'Original capture identity')
    require(value['health'].get('ExitCode') == 0 and
            type(value['health'].get('ExitCode')) is int, 'Positive capture exit')
    pcap = value['pcap']
    require(type(pcap) is bytes and 24 <= len(pcap) <= 16 * 1024 * 1024, 'Full pcap bounds')
    require(pcap[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'), 'pcap magic')
    endian = '<' if pcap[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    major, minor, zone, sig, snap, link = struct.unpack(endian + 'HHIIII', pcap[4:24])
    require((major, minor) == (2, 4) and snap > 0 and link == 1, 'pcap header')
    offset = 24
    while offset < len(pcap):
        require(offset + 16 <= len(pcap), 'Partial pcap record')
        sec, usec, captured, original = struct.unpack(endian + 'IIII', pcap[offset:offset+16])
        require(usec < 1000000 and captured <= original and captured <= snap and
                offset + 16 + captured <= len(pcap), 'Partial/invalid pcap packet')
        offset += 16 + captured
    log = value['log']
    require(type(log) is str and len(re.findall(r'(?m)^0 packets dropped by kernel\s*$', log)) == 1,
            'Capture drop accounting')
    require(value['archiveSHA256'] == sha(encode(pack(dict(
        identity=value['identity'], health=value['health'], pcap=pcap, log=log)))),
        'Complete archive binding')


def validate_phase2(raw, phase1, bound, resources):
    validate_phase1(phase1, bound, resources)
    value = envelope(raw, bound, 'fresh-admin-phase2-v1',
                     ('phase1SHA256', 'capture', 'sink', 'watcher', 'drained'))
    require(value['phase1SHA256'] == sha(phase1), 'Phase1 binding')
    inventory = resources['observations']
    results = {}
    seq = []
    for name in ('capture', 'sink', 'watcher', 'drained'):
        results[name], number = original_observation(name, value[name], bound, inventory)
        seq.append(number)
    require(seq == sorted(set(seq)) and seq[0] > inventory['closures']['sequence'], 'Phase2 order')
    capture_archive(results['capture'], resources['captureIdentity'])
    sink = results['sink']
    validate_sink(sink,bound,resources)
    watcher = results['watcher']
    fields(watcher, ('identity', 'ack', 'signalled', 'exitCode'))
    require(same(watcher['identity'], bound['containmentOwner']) and
            watcher['signalled'] is True and type(watcher['exitCode']) is int and
            watcher['exitCode'] == 1, 'Original failed watcher cooperative exit')
    ack = watcher['ack']
    fields(ack, ('schema', 'binding', 'phase1SHA256', 'captureSHA256', 'sinkSHA256',
                 'failure', 'pendingQueries', 'normalCleanupSucceeded'))
    require(ack['schema'] == 'fresh-admin-watcher-closed-v1' and same(ack['binding'], bound)
            and ack['phase1SHA256'] == sha(phase1) and
            ack['captureSHA256'] == sha(value['capture']) and
            ack['sinkSHA256'] == sha(value['sink']) and
            type(ack['failure']) is str and bool(ack['failure']) and
            type(ack['pendingQueries']) is int and ack['pendingQueries'] == 0 and
            ack['normalCleanupSucceeded'] is False, 'Distinct administrative watcher ACK')
    drained = results['drained']
    fields(drained, ('operations', 'monitorJoined', 'pendingTransports'))
    require(drained['monitorJoined'] is True and drained['pendingTransports'] == [] and
            same(drained['operations'], sorted(resources['operations'])), 'Final owner drain')
    return dict(phase=2, phase2SHA256=sha(raw), normalCleanupSucceeded=False)


def validate_sink(sink,bound,resources):
    if resources['entryInventory']['sinkAttempted'] is False:
        require(sink==dict(unit='step10-prep-'+bound['nonce'],neverSubmitted=True),'Original sink never-submitted seal')
    else:
        from sink_contract import CONTRACT_SHA256
        fields(sink,('unit','retirement','listed'))
        require(sink['unit']=='step10-prep-'+bound['nonce'] and sink['listed']==[], 'Exact sink unit absence')
        receipt=sink['retirement']
        fields(receipt,('schema','nonce','unit','contractSHA256','invocationId','result','exitCode','exitStatus'))
        require(receipt['schema']=='fresh-sink-exit-v1' and receipt['nonce']==bound['nonce'] and
                receipt['unit']==sink['unit']+'.service' and receipt['contractSHA256']==CONTRACT_SHA256 and
                type(receipt['invocationId']) is str and re.fullmatch('[a-f0-9]{32}',receipt['invocationId']) and
                receipt['result']=='success' and (receipt['exitCode'],receipt['exitStatus']) in
                (('exited','0'),('killed','TERM')), 'Original sink post-stop completion')
