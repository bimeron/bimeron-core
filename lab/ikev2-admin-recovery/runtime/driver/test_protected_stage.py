import pathlib
import tempfile
import threading
import unittest
from protected_stage import Stage, Hold

class Failure:
    def __init__(self):
        self.event = threading.Event()
        self.value = None
    def set(self, error):
        if not self.event.is_set():
            self.value = str(error)
            self.event.set()

class InterlockTests(unittest.TestCase):
    def test_missing_transport_latches_and_cannot_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            failure = Failure()
            stage = Stage(directory, directory, 'a'*64, failure)
            stage.start()
            stage.thread.join(2)
            self.assertTrue(failure.event.is_set())
            with self.assertRaises(Hold): stage.before_restore()
            self.assertFalse((pathlib.Path(directory)/'protected-cleanup.json').exists())
    def test_unstarted_and_invalid_nonce(self):
        with self.assertRaises(Hold): Stage('.', '.', '../escape', Failure())
        with self.assertRaises(Hold): Stage('.', '.', 'a'*64, Failure()).before_restore()
    def test_stale_cleanup_marker_does_not_authorize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)/'protected-cleanup.json'
            path.write_text('{"cleanupVerified":true}')
            stage = Stage(directory, directory, 'b'*64, Failure())
            with self.assertRaises(Hold): stage.before_restore()
    def test_evidence_unknown_is_not_pass(self):
        stage = Stage('.', '.', 'a'*64, Failure())
        for value in (None, True, {}, {'verdict':'INCONCLUSIVE'}):
            with self.assertRaises(Hold): stage._pass(value, 'coverage')



class ProofTests(unittest.TestCase):
    def make_stage(self, directory, owner=False):
        from types import SimpleNamespace
        calls=[]
        refs=dict(readerClosure='a'*64,taskClosure='b'*64)
        evidence=SimpleNamespace(
            check_exact_drain=lambda *a: dict(status='PASS',refs=refs),
            check_independent_absence=lambda *a: dict(status='PASS',rasAbsent=True,ownerAbsent=True,taskReady=True,refs={'raw':'c'*64}))
        adapter=SimpleNamespace(verify_drain=lambda *a: calls.append('drain') or {},
            cleanup=lambda r: calls.append(('close',r)),final=lambda *a: calls.append('absence') or {})
        stage=Stage(directory,directory,'a'*64,Failure(),adapter,evidence)
        stage.thread=threading.Thread(target=lambda:None);stage.thread.start();stage.thread.join()
        stage.ownerMayExist=owner
        if owner: stage.binding=dict(SHA256='a'*64,Nonce='a'*64,PolicySHA256='b'*64)
        return stage,calls

    def test_measurement_clock_does_not_latch(self):
        stage=Stage('.','.','a'*64,Failure())
        stage._measurement(dict(status='INCONCLUSIVE',reasons=['CLOCK_BOUND_UNPROVEN']))
        self.assertFalse(stage.failure.event.is_set())
        self.assertEqual(stage.measurement['status'],'INCONCLUSIVE')

    def test_fail_sticky(self):
        stage=Stage('.','.','a'*64,Failure())
        with self.assertRaises(Hold):stage._measurement(dict(status='FAIL',reasons=['escape']))
        stage._measurement(dict(status='INCONCLUSIVE',reasons=['later malformed']))
        self.assertEqual(stage.measurement['status'],'FAIL')

    def test_no_launch_drain_and_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            stage,calls=self.make_stage(directory)
            stage.before_restore()
            self.assertEqual(calls,['drain','absence'])
            import json
            proof=json.loads((pathlib.Path(directory)/'protected-cleanup.json').read_text())
            self.assertTrue(all(proof[k] for k in ('rasAbsent','ownerAbsent','taskReady')))
            stage.before_restore()
            self.assertEqual(len(calls),2)

    def test_uncertain_launch_holds(self):
        with tempfile.TemporaryDirectory() as directory:
            stage,calls=self.make_stage(directory,True);stage.binding=None
            with self.assertRaises(Hold):stage.before_restore()
            self.assertEqual(calls,['drain'])

    def test_healthy_inconclusive_cleanup_is_not_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            stage,calls=self.make_stage(directory,True);stage.observationCompleted=True
            stage.before_restore()
            self.assertEqual(calls[0],'drain');self.assertEqual(calls[2],'absence')
            self.assertFalse(calls[1][1]['Failure'])
            self.assertFalse(stage.failure.event.is_set())

    def test_real_failure_early_close(self):
        with tempfile.TemporaryDirectory() as directory:
            stage,calls=self.make_stage(directory,True);stage.executionFailure=Hold('fault')
            stage.before_restore();self.assertTrue(calls[1][1]['Failure'])

    def test_uncertain_cleanup_never_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            stage,calls=self.make_stage(directory,True);stage.observationCompleted=True
            def timeout(request):calls.append('timeout');raise TimeoutError('response lost')
            stage.adapter.cleanup=timeout
            with self.assertRaises(TimeoutError):stage.before_restore()
            with self.assertRaises(Hold):stage.before_restore()
            self.assertEqual(calls.count('timeout'),1)
            self.assertNotIn('absence',calls)

    def test_missing_raw_validator_blocks_boolean_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            stage,calls=self.make_stage(directory)
            del stage.evidence.check_exact_drain
            with self.assertRaises(Hold):stage.before_restore()
            self.assertFalse(stage.restorationAllowed)

    def test_missing_each_closure_blocks_close(self):
        for missing in ('readerClosure','taskClosure'):
            with tempfile.TemporaryDirectory() as directory:
                stage,calls=self.make_stage(directory,True);stage.observationCompleted=True
                stage.evidence.check_exact_drain=lambda *a:dict(status='PASS',refs={k:'a'*64 for k in ('readerClosure','taskClosure') if k!=missing})
                with self.assertRaises(KeyError):stage.before_restore()
                self.assertEqual(calls,['drain'])

    def test_status_schema(self):
        stage=Stage('.','.','a'*64,Failure())
        stage._pass({'status':'PASS'},'policy')
        with self.assertRaises(Hold):stage._pass({'verdict':'PASS'},'policy')

if __name__ == '__main__': unittest.main()
