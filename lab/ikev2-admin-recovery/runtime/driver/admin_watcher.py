"""Cooperative failed-run watcher transition, separate from normal release."""
from admin_recovery import decode, encode, sha, fields, require, same
from admin_evidence import validate_phase1, original_observation, capture_archive,validate_sink


def administrative_tick(state, request, phase1, capture, sink, bound, resources,
                        pending, publish):
    """Called by the original watcher after processing its pending query.

    Never cancels/abandons a query. Caller stops scheduling NEW queries after
    this returns True and exits with failed supervision (1), not normal ACK.
    """
    value = decode(request)
    fields(value, ('schema', 'binding', 'phase1SHA256', 'captureSHA256', 'sinkSHA256'))
    require(value['schema'] == 'fresh-admin-watcher-request-v1' and
            same(value['binding'], bound), 'Watcher administrative binding')
    require(value['phase1SHA256'] == sha(phase1) and
            value['captureSHA256'] == sha(capture) and value['sinkSHA256'] == sha(sink),
            'Watcher proof bindings')
    fingerprint = sha(request)
    if state.get('requestSHA256') is not None:
        require(state['requestSHA256'] == fingerprint, 'Watcher request conflict')
    else:
        state['requestSHA256'] = fingerprint
    require(pending is None, 'Original watcher query still pending')
    validate_phase1(phase1, bound, resources)
    cap, cap_seq = original_observation('capture', capture, bound, resources['observations'])
    end, sink_seq = original_observation('sink', sink, bound, resources['observations'])
    require(resources['observations']['closures']['sequence'] < cap_seq < sink_seq,
            'Watcher disposition order')
    capture_archive(cap, resources['captureIdentity'])
    validate_sink(end,bound,resources)
    require(type(state.get('failure')) is str and bool(state['failure']),
            'Original failure must remain recorded')
    ack = encode(dict(schema='fresh-admin-watcher-closed-v1', binding=bound,
                      phase1SHA256=sha(phase1), captureSHA256=sha(capture),
                      sinkSHA256=sha(sink), failure=state['failure'],
                      pendingQueries=0, normalCleanupSucceeded=False))
    # Publication is exclusive or compares exact bytes; no operation is repeated
    # if the durable acknowledgement's observation was lost.
    publish('administrative-watcher-closed.json', ack)
    state['ack'] = ack
    state['exitCode'] = 1
    return True
