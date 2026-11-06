import json
import tempfile
import threading
import unittest
from pathlib import Path
from cancellation import control, ROLES

class GateTests(unittest.TestCase):
    def run_case(self, mode):
        now = [0.0]
        calls = []
        class Latch:
            event = threading.Event()
            value = None
            monotonic = 0
            def set(self, value):
                if not self.event.is_set():
                    self.value = str(value)
                    self.monotonic = now[0]
                    self.event.set()
        latch = Latch()
        class Owner:
            def __init__(self, kind, role=None):
                self.kind, self.role, self.started = kind, role, now[0]
            def poll(self):
                if self.kind == 'persistent':
                    return 1 if mode == 'failure' and now[0]-self.started >= .4 else None
                return 0 if now[0]-self.started >= .4 else None
            def result(self):
                if self.kind == 'ready': return dict(ready=True, healthy=True)
                if self.kind == 'persistent': raise RuntimeError('reader failed')
                return dict(nonce='n')
            def report(self, error): pass
        class Process:
            def poll(self): return None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def launch(kind, role, label):
                markers = list(root.glob('*session-open.json'))
                if kind == 'drain-status' and not latch.event.is_set() and any(c[0]=='persistent' for c in calls):
                    self.assertEqual(len(markers), 3)
                if kind == 'persistent':
                    self.assertEqual(len(markers), ROLES.index(role))
                calls.append((kind, role, now[0]))
                return Owner(kind, role)
            def pause(seconds):
                now[0] += seconds
                for kind, role, start in calls:
                    if kind == 'persistent' and mode == 'success' and now[0]-start >= .4:
                        (root/f'reader-{role}-session-open.json').write_text(json.dumps(dict(schema=1,nonce='n',role=role,sessionOpenedUtc='2026-11-04T00:00:00Z')))
                if mode == 'success' and len(list(root.glob('*session-open.json'))) == 3:
                    latch.set('test complete')
            control(Process(), launch, root, 'n', latch, 900, lambda x:None, clock=lambda:now[0], pause=pause)
        admitted = [c for c in calls if c[0]=='persistent']
        if mode == 'success': self.assertEqual(len(admitted),3)
        else:
            self.assertEqual(len(admitted),1)
            self.assertLessEqual(latch.monotonic-admitted[0][2],10.21)
            self.assertIn('deadline' if mode=='missing' else 'reader failed',latch.value)
        self.assertTrue(any(c[0]=='stop' for c in calls))
    def test_failure_after_one_ack_drains_to_permit(self):
        now = [0.0]
        calls = []
        closed = {}
        class Latch:
            event = threading.Event()
            value = None
            monotonic = 0
            def set(self, value):
                if not self.event.is_set():
                    self.value, self.monotonic = str(value), now[0]
                    self.event.set()
        latch = Latch()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            class Owner:
                def __init__(self, kind):
                    self.kind, self.started = kind, now[0]
                def poll(self):
                    return None if self.kind == 'persistent' and not closed else 0
                def result(self):
                    if self.kind == 'ready': return dict(ready=True, healthy=True)
                    if self.kind == 'persistent': return closed
                    if self.kind == 'stop':
                        request = json.loads((root/'stop-request.json').read_text())
                        closed.update(nonce='n', role='supervisor', closed=request['requestedUtc'],
                                      cancelled=True, requestId=request['requestId'])
                        return dict(nonce='n', delivered=True, requestId=request['requestId'])
                    return dict(nonce='n', readers={'supervisor': {'closed': dict(closed)}},
                                inspectorFinal=dict(nonce='n', exitVerified=bool(closed), taskClosureVerified=bool(closed)),
                                task=dict(state=3, instances=0))
            class Process:
                def poll(self):
                    if (root/'restore-permit.json').exists():
                        (root/'preparation-outcome.json').write_text(json.dumps(dict(nonce='n', restored=True)))
                        return 0
                    return None
            def launch(kind, role, label):
                calls.append((kind, role, latch.event.is_set()))
                return Owner(kind)
            def pause(seconds):
                now[0] += seconds
                if any(k == 'persistent' for k, _, _ in calls) and not latch.event.is_set():
                    (root/'reader-supervisor-session-open.json').write_text(json.dumps(dict(
                        schema=1, nonce='n', role='supervisor', sessionOpenedUtc='2026-11-04T00:00:00Z')))
                    latch.set('failure after first session acknowledgement')
                self.assertLess(now[0], 20)
            self.assertTrue(control(Process(), launch, root, 'n', latch, 900,
                                    lambda x: self.fail('Failure path must not validate success'),
                                    clock=lambda: now[0], pause=pause))
            self.assertTrue((root/'restore-permit.json').exists())
            evidence = json.loads((root/'cancellation-evidence.json').read_text())
            self.assertEqual(evidence['result'], 'FAIL')
            self.assertEqual(evidence['events'][-1]['kind'], 'local-drain-complete')
        self.assertEqual([r for k, r, _ in calls if k == 'persistent'], ['supervisor'])
        self.assertTrue(any(k == 'stop' and failed for k, _, failed in calls))
        self.assertTrue(any(k == 'drain-status' and failed for k, _, failed in calls))

    def test_success(self): self.run_case('success')
    def test_missing(self): self.run_case('missing')
    def test_failure(self): self.run_case('failure')

if __name__ == '__main__': unittest.main()
