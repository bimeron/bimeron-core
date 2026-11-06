"""Finite reader ownership and guest interval acceptance; no native calls on import."""
import concurrent.futures
import datetime
import math
import threading
import time

ROLES = ('supervisor', 'collector', 'barrier')

class FirstFailure:
    def __init__(self):
        self._lock = threading.Lock()
        self._value = None
        self.event = threading.Event()
        self.monotonic = None

    def set(self, error):
        if error is not None:
            with self._lock:
                if self._value is None:
                    self._value = str(error)
                    self.monotonic = time.monotonic()
                    self.event.set()

    @property
    def value(self):
        with self._lock:
            return self._value

def stamp(value):
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Unzoned guest timestamp')
    return result.timestamp()

def validate_readers(values, nonce):
    if len(values) != 3 or {v['role'] for v in values} != set(ROLES):
        raise ValueError('Three distinct reader roles required')
    ready, closed, ends, completions, gaps, durations = [], [], [], [], {}, {}
    for v in values:
        if v['schema'] != 1 or v['nonce'] != nonce or v['failure']:
            raise ValueError('Reader binding/schema/failure')
        h = v['readiness']
        if h['ready'] is not True or h['healthy'] is not True or h.get('failure'):
            raise ValueError('Reader readiness refused')
        opened, start, close = map(stamp, (v['opened'], v['ready'], v['closed']))
        if not 0 <= opened-stamp(h['utc']) <= 8:
            raise ValueError('Stale/future readiness')
        end = v['terminal']
        if end['nonce'] != nonce or (end['kind'], end['target'], end['status']) != ('end','all','complete'):
            raise ValueError('Invalid terminal')
        terminal = stamp(end['utc'])
        if end['producer'] != v['producer']:
            raise ValueError('Terminal producer mismatch')
        final = v['completion']
        if final['completed'] is not True or final.get('failure') or final['launch']['nonce'] != nonce or len(final['processes']) != 2 or any(p['alive'] is not False for p in final['processes']):
            raise ValueError('Completion unproven')
        if not any(p['pid']==v['producer']['pid'] and p['start']==v['producer']['start'] for p in final['processes']):
            raise ValueError('Completion producer mismatch')
        completed = stamp(v['completionObserved'])
        if not terminal <= completed <= close:
            raise ValueError('Early close before process completion')
        completions.append(completed)
        samples = v['samples']
        if not 2 <= len(samples) <= 1100 or not opened <= start < terminal <= close:
            raise ValueError('Incomplete/early-close/terminal-only interval')
        previous = None
        maximum = 0
        duration = 0
        for sample in samples:
            a, b = stamp(sample['before']), stamp(sample['after'])
            m, d = sample['mono'], sample['done']
            if not all(type(x) in (int,float) and math.isfinite(x) for x in (m,d)) or not 0 <= m <= d <= 1020:
                raise ValueError('Invalid monotonic sample')
            if not opened <= a <= b <= close or b-a > 8 or d-m > 8:
                raise ValueError('Invalid read interval')
            if type(sample['bytes']) is not int or not 0 <= sample['bytes'] <= 64*1024*1024:
                raise ValueError('Invalid snapshot size')
            duration = max(duration,b-a,d-m)
            if previous:
                gap = m-previous['done']
                wall_gap = a-stamp(previous['after'])
                if not 0 <= gap <= 8 or not 0 <= wall_gap <= 8:
                    raise ValueError('Read sample gap exceeded')
                maximum = max(maximum, gap, wall_gap)
            previous = sample
        if stamp(samples[0]['after']) != start or stamp(samples[-1]['after']) < terminal:
            raise ValueError('Missing readiness/terminal read')
        if stamp(samples[0]['before'])-opened > 8 or close-stamp(samples[-1]['after']) > 8:
            raise ValueError('Unsampled handle boundary')
        ready.append(start);closed.append(close);ends.append(terminal);gaps[v['role']]=maximum
        durations[v['role']]=duration
    completion = min(completions)
    if len(set(ends)) != 1 or max(ready) >= ends[0] or min(closed) < completion:
        raise ValueError('No positive common handle interval through completion')
    return dict(start=max(ready), end=completion, terminal=ends[0], commonClose=min(closed), maxSampleGaps=gaps, maxReadDurations=durations)

def run_owned(process, setup, reader, validate, latch, seconds, *, pool_factory=concurrent.futures.ThreadPoolExecutor, clock=time.monotonic):
    """Drain started owners, then ALWAYS wait owned process; return cleanup eligibility."""
    futures=[];pool=None;drained=True;waited=False;values=[]
    def guarded_reader(role):
        try: return reader(role)
        except Exception as exc:
            latch.set(exc)
            raise
    try:
        setup()
        pool=pool_factory(max_workers=3)
        for role in ROLES:
            if latch.value is not None:
                break
            futures.append(pool.submit(guarded_reader, role))
    except Exception as exc:
        latch.set(exc)
    finally:
        try:
            deadline=clock()+1050
            for future in futures:
                try:
                    values.append(future.result(timeout=max(0,deadline-clock())))
                except Exception as exc:
                    latch.set(exc)
                finally:
                    drained = future.done() and drained
            if drained and len(values)==3:
                try: validate(values)
                except Exception as exc: latch.set(exc)
        finally:
            try:
                if pool is not None: pool.shutdown(wait=False) # Never claim cancellation.
            finally:
                try:
                    process.wait(timeout=seconds+105)
                    waited=True
                except Exception as exc:
                    latch.set(exc)
    if not drained or not waited:
        latch.set('HOLD: reader/process owner undrained')
    return drained and waited
