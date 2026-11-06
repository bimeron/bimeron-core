"""Retained one-at-a-time read-only capture queries; timeout never kills."""
import json
import os
import pathlib
import time
from transport import Transport
from admin_recovery import require, reason_text


class Query:
    def __init__(self,root,argv,clock=time.monotonic,transport=Transport):
        self.root=pathlib.Path(root);self.argv=list(argv);self.clock=clock
        self.transport=transport;self.entries=[];self.active=None

    def _state(self):
        """'not-dispatched', 'surviving', 'terminal' or 'terminal-unauthenticated'.

        Only the retained original Popen is polled; no PID is reopened and no
        process is signalled. A child whose handle/identity read failed stays
        owned while it runs and resolves once that same Popen reports exit.
        """
        t=self.active['transport']
        children=[] if t is None else list(t.children)
        if not children:return 'not-dispatched'
        require(len(children)==1,'Original capture query child inventory')
        child=children[0]
        try:code=child['process'].poll()
        except Exception:return 'surviving'
        if code is None:return 'surviving'
        if child['handle'] is None or child['record']['identity'] is None:
            return 'terminal-unauthenticated'
        return 'terminal'

    def unresolved(self):
        if self.active is None:return None
        return self.active if self._state()=='surviving' else None

    def __call__(self):
        if self.active is None:
            directory=self.root/('watcher-query-%06d'%(len(self.entries)+1))
            directory.mkdir()
            entry=dict(before=self.clock(),transport=None)
            self.active=entry;self.entries.append(entry)
            t=self.transport(directory,self.clock()+7,clock=self.clock)
            entry['transport']=t
            output=t.observe(self.argv,'capture-status',timeout=6,mutation=False)
            self.active=None
        else:
            state=self._state()
            require(state!='surviving','Original capture query still outstanding')
            entry=self.active
            if state!='terminal':
                # Known no-dispatch, or terminal without authenticated identity:
                # the slot is released, no output is read, the query is a
                # supervision failure and grants no retirement authority.
                self.active=None;entry['resolution']=state
                if entry['transport'] is not None and hasattr(entry['transport'],'close'):
                    try:entry['transport'].close()
                    except Exception as error:entry['closeError']=reason_text(error)
                require(False,'Original read-only capture query '+state+'; no output collected')
            child=entry['transport'].children[0]
            code=child['process'].poll()
            with pathlib.Path(child['record']['files']['stdout']).open('rb') as stream:
                output=stream.read(16*1024*1024+1)
            require(len(output)<=16*1024*1024,'Original query output bound')
            # Terminal read-only query failure is recorded as supervision failure.
            # It grants no capture/sink/session retirement authority.
            self.active=None;entry['resolution']='terminal'
            require(code==0,'Original read-only capture query failed')
        return dict(before=entry['before'],after=self.clock(),value=json.loads(output))


class TickJournal:
    """Bounded per-tick refusal journal for the independent watcher.

    Every refusal/exception is counted; consecutive identical ones are folded
    into a repeat count. At most `limit` records are written; the in-memory
    count keeps growing and is reported in the heartbeat. A journal write
    failure never masks or replaces the refusal itself.
    """
    def __init__(self,root,name='independent-tick-errors.jsonl',limit=256,clock=time.time):
        self.path=pathlib.Path(root)/name;self.limit=limit;self.clock=clock
        self.count=0;self.written=0;self.repeats=0;self.last=None;self.writeErrors=0

    def refuse(self,tick,stage,error):
        self.count+=1
        reason=reason_text(error)
        key=(stage,type(error).__name__,reason)
        if key==self.last:
            self.repeats+=1;return
        record=dict(utc=self.clock(),tick=tick,stage=stage,error=type(error).__name__,
                    reason=reason,count=self.count,repeatsOfPrevious=self.repeats)
        self.last=key;self.repeats=0
        if self.written>=self.limit:return
        self.written+=1
        if self.written==self.limit:record['limitReached']=True
        try:
            with self.path.open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(record,sort_keys=True)+'\n');stream.flush();os.fsync(stream.fileno())
        except Exception:
            self.writeErrors+=1
