"""Late collection from the original preparation's retained resources only."""
from admin_recovery import require, sha


def collect_original(resources):
    """One observation slice. Does not submit, fetch, restore, close or stop.

    Mailbox bytes are validated by the original client's receive path. Other
    late results remain observations for their fixed continuation call sites.
    A new explicit request can observe a still-running original operation later.
    """
    result = {}
    stage = resources.get('stage')
    if stage is not None and stage.thread is not None:
        require(not stage.thread.is_alive(), 'Original Stage still active')
    resident = resources.get('resident')
    client = getattr(getattr(stage, 'adapter', None), 'client', None)
    if resident is not None and resident.pending is None and client is not None and client.pending is not None:
        raw=resident.cached_original(sha(client.pending[1]))
        if raw is not None:
            client.receive_original(raw)
            result['mailbox']=dict(outputSHA256=sha(raw),source='original-resident-cache')
    if resident is not None and resident.pending is not None:
        pending = dict(resident.pending)
        raw = resident.collect(seconds=.1)
        resources.setdefault('late_resident', {})[pending['sequence']] = (pending, raw)
        if client is not None and client.pending is not None:
            require(pending['requestSHA256'] == sha(client.pending[1]),
                    'Late original mailbox request mismatch')
            client.receive_original(raw)
        result['resident'] = dict(sequence=pending['sequence'], outputSHA256=sha(raw))
    remote = resources.get('original_remote_transport')
    if remote is not None and remote.pending is not None:
        raw = remote.collect_original()
        result['remote'] = dict(outputSHA256=sha(raw), remoteClosureProven=False)
    control = resources.get('cancellation_state')
    if control:
        result['controller'] = []
        for mode, original in list(control['pending'].items()):
            code = original.poll()
            if code is None:
                result['controller'].append(dict(mode=mode, state='Pending'))
                continue
            value = original.result()
            require(value.get('nonce') == control['nonce'], 'Original controller nonce')
            control['completed'].append((mode, original))
            control.setdefault('late', {})[mode] = value
            del control['pending'][mode]
            if mode == 'drain-status':
                control['status'] = value
            if mode == 'stop':
                require(control['request'] is not None and value.get('delivered') is True and
                        value.get('requestId') == control['request']['requestId'],
                        'Original stop acknowledgement')
                control['delivered'] = True
            result['controller'].append(dict(mode=mode, state='Collected'))
        for role, original in control['owners'].items():
            if original is None or role in control['local'] or original.poll() is None:
                continue
            value = original.result()
            require(value.get('nonce') == control['nonce'] and value.get('role') == role and
                    value.get('closed'), 'Original reader closure')
            control['local'][role] = value
    return result
