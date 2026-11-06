"""Fixed private administrative watcher input; no operational effect callbacks."""
from admin_recovery import decode, require, same
from admin_evidence import unpack
from admin_watcher import administrative_tick
from settlement import read
from watcher_release import publish


def tick(root, identity, pending, state):
    path=root/'administrative-watcher-request.json'
    if not path.exists():return False
    context=unpack(decode(read(root/'administrative-watcher-context.json')))
    bound=context['binding']
    expected=dict(pid=identity['pid'],creationFileTime=str(identity['startFiletime']),
                  imageSHA256=identity['exeSHA256'])
    require(same(bound['containmentOwner'],expected) and bound['nonce']==identity['nonce'],
            'Original watcher identity')
    # The original owner's failure, never this watcher's own (possibly
    # self-generated refusal) failure, authorizes the failed-run disposition.
    require(type(context.get('failure')) is str and bool(context['failure']),
            'Administrative watcher requires original failed lifecycle')
    state['failure']=context['failure']
    def write(name,raw):
        target=root/name
        if target.exists():require(read(target)==raw,'Administrative ACK conflict')
        else:publish(target,raw)
    return administrative_tick(state,read(path),read(root/'administrative-phase1.json'),
        read(root/'administrative-capture.json'),read(root/'administrative-sink.json'),
        bound,context['resources'],pending,write)
