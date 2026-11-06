import concurrent.futures as cf
import copy
import datetime as dt
import threading
import pathlib
import textwrap
import types
import unittest
from persistent import FirstFailure, ROLES, run_owned, validate_readers

def utc(n): return (dt.datetime(2026,11,4,tzinfo=dt.timezone.utc)+dt.timedelta(seconds=n)).isoformat()
def evidence(role):
    producer=dict(pid=1,start=utc(0),sid='fixture')
    return dict(schema=1,nonce='a'*64,role=role,failure=None,producer=producer,
        readiness=dict(ready=True,healthy=True,utc=utc(0)),opened=utc(1),ready=utc(2),closed=utc(10),
        terminal=dict(nonce='a'*64,kind='end',target='all',status='complete',utc=utc(8),producer=producer),
        completion=dict(completed=True,launch=dict(nonce='a'*64),processes=[dict(pid=1,start=utc(0),alive=False),dict(pid=2,start=utc(0),alive=False)]),completionObserved=utc(9),
        samples=[dict(before=utc(n),after=utc(n+1),mono=n,done=n+1,bytes=100) for n in range(1,9)])

class Intervals(unittest.TestCase):
    def test_positive(self):
        value=validate_readers([evidence(r) for r in ROLES],'a'*64)
        self.assertEqual(value['end']-value['start'],7)
        self.assertEqual(value['maxSampleGaps'],dict.fromkeys(ROLES,0))
    def test_refusals(self):
        mutations=[lambda v:v.update(closed=utc(7)),lambda v:v.update(ready=utc(8)),lambda v:v.update(ready=utc(9)),
          lambda v:v.update(samples=v['samples'][:1]),lambda v:v.update(samples=v['samples'][-1:]),
          lambda v:v.update(nonce='b'*64),lambda v:v.update(role='wrong'),lambda v:v.update(schema=2),
          lambda v:v['readiness'].update(utc=utc(-20)),lambda v:v['readiness'].update(utc=utc(2)),
          lambda v:v.update(terminal=None),lambda v:v['completion'].update(completed=False),
          lambda v:v['completion']['processes'][0].update(alive=True),lambda v:v.update(completionObserved=utc(11)),
          lambda v:v.update(failure='reader failure'),lambda v:v['samples'][2].update(mono=99),
          lambda v:v['terminal'].update(producer={}),lambda v:v['readiness'].update(ready='true')]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                rows=[copy.deepcopy(evidence(r)) for r in ROLES];mutate(rows[0])
                with self.assertRaises((ValueError,TypeError,KeyError)):validate_readers(rows,'a'*64)
        with self.assertRaises(ValueError):validate_readers([evidence('supervisor')],'a'*64)

class Owned(unittest.TestCase):
    def test_actual_preparation_uses_owned_controller_interlock(self):
        import ast
        source=pathlib.Path(__file__).with_name('preparation.py').read_text()
        calls=[n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='control']
        self.assertEqual(len(calls),1)
        self.assertTrue(any(k.arg=='before_restore' and isinstance(k.value,ast.Attribute) and k.value.attr=='before_restore' for k in calls[0].keywords))
    def invoke(self, *, setup_error=None, submit_error=None, result_error=None, validation_error=None, wait_error=None, undrained=False):
        events=[];latch=FirstFailure()
        class Process:
            def wait(self,timeout):
                events.append('wait')
                if wait_error:raise wait_error
        class Future:
            def result(self,timeout):
                events.append('drain')
                if result_error:raise result_error
                return 1
            def done(self):return not undrained
        class Pool:
            count=0
            def __init__(self,**kw):pass
            def submit(self,*a):
                self.count+=1
                if submit_error and self.count==2:raise submit_error
                return Future()
            def shutdown(self,wait):events.append('shutdown')
        def setup():
            if setup_error:raise setup_error
        def validate(values):
            events.append('validate')
            if validation_error:raise validation_error
        eligible=run_owned(Process(),setup,lambda r:None,validate,latch,900,pool_factory=Pool,clock=lambda:0)
        if eligible:events.append('cleanup')
        return events,latch.value,eligible
    def test_drain_wait_cleanup(self):
        for kw in ({},{'setup_error':RuntimeError('setup')},{'submit_error':RuntimeError('submit')},{'result_error':TimeoutError('reader')},{'validation_error':ValueError('validation')}):
            with self.subTest(kw=kw):
                events,failure,eligible=self.invoke(**kw)
                self.assertTrue(eligible);self.assertEqual(events[-2:],['wait','cleanup'])
                if kw:self.assertIsNotNone(failure)
                self.assertEqual(events.count('drain'),0 if 'setup_error' in kw else 1 if 'submit_error' in kw else 3)
    def test_hold(self):
        for kw in ({'wait_error':TimeoutError('process')},{'undrained':True,'result_error':TimeoutError('reader')}):
            events,failure,eligible=self.invoke(**kw)
            self.assertFalse(eligible);self.assertEqual(events[-1],'wait');self.assertIsNotNone(failure)
    def test_monitor_failure_during_drain(self):
        latch=FirstFailure();entered=threading.Event();release=threading.Event();events=[]
        class Process:
            def wait(self,timeout):events.append('wait')
        class Future:
            def result(self,timeout):
                entered.set();self_test.assertTrue(release.wait(2));events.append('drain');return 1
            def done(self):return True
        class Pool:
            def __init__(self,**kw):pass
            def submit(self,*a):return Future()
            def shutdown(self,wait):pass
        def monitor():
            self.assertTrue(entered.wait(2));latch.set('monitor failed during drain');release.set()
        self_test=self;thread=threading.Thread(target=monitor);thread.start()
        try:
            self.assertTrue(run_owned(Process(),lambda:None,lambda r:None,lambda v:latch.set('later validation'),latch,900,pool_factory=Pool))
        finally:thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(latch.value,'monitor failed during drain');self.assertEqual(events,['drain']*3+['wait'])
    def test_reader_error_stops_submissions(self):
        latch=FirstFailure();roles=[]
        class Pool:
            def __init__(self,**kw):pass
            def submit(self,fn,role):
                roles.append(role);f=cf.Future()
                try:f.set_result(fn(role))
                except Exception as exc:f.set_exception(exc)
                return f
            def shutdown(self,wait):pass
        def reader(role):raise RuntimeError('reader failed')
        class Process:
            def wait(self,timeout):pass
        self.assertTrue(run_owned(Process(),lambda:None,reader,lambda v:None,latch,900,pool_factory=Pool))
        self.assertEqual(roles,['supervisor']);self.assertEqual(latch.value,'reader failed')

if __name__=='__main__':unittest.main()
