import pathlib
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'driver'))
from protected_transport import Adapter

class BoundaryTests(unittest.TestCase):
    def adapter(self):
        a = Adapter.__new__(Adapter)
        a.binding = dict(SHA256='a'*64, Nonce='b'*64, PolicySHA256='c'*64)
        a.nonce = 'b'*64
        a.owner_identity = {'pid': 123}
        a.live_owner_sample = dict(a.owner_identity, handleState='live', exitCode=None)
        a.client = Mock()
        a.drain_ref = 'verified-drain'
        a.live_ready = True
        a.out = pathlib.Path('unused-offline')
        return a

    def test_default_refuses_before_relay(self):
        a = self.adapter()
        with self.assertRaises(Exception): a.cleanup(dict(Failure=False))
        a.client.command.assert_not_called()

    def test_failure_bypasses(self):
        a = self.adapter()
        with patch('live_prepare.prepare_live') as hook:
            a.cleanup(dict(Failure=True))
            hook.assert_not_called()
        a.client.command.assert_called_once()

    def test_once_bound(self):
        a = self.adapter()
        admission = dict(Binding=a.binding, GuardSHA256='d'*64, FixtureSHA256='e'*64, ReviewedSHA256='f'*64)
        with patch('live_prepare.prepare_live', return_value=admission) as hook:
            a.cleanup(dict(Failure=False))
            with self.assertRaises(Exception): a.cleanup(dict(Failure=False))
            hook.assert_called_once_with(a.binding, a.nonce, a.live_owner_sample, out=a.out)
        a.client.command.assert_called_once()
        from protected_transport import strict
        requests = [strict(c.args[1]) for c in a.client.proof.call_args_list if c.args[0] == 'cleanup-request.json']
        self.assertEqual(requests, [dict(Failure=False)])

    def test_no_sample_no_hook(self):
        a = self.adapter(); a.live_ready = False
        with patch('live_prepare.prepare_live') as hook:
            with self.assertRaises(Exception): a.cleanup(dict(Failure=False))
        hook.assert_not_called()
        a.client.command.assert_not_called()

    def test_bad_binding(self):
        a = self.adapter()
        with patch('live_prepare.prepare_live', return_value={'Binding': {}}):
            with self.assertRaises(Exception): a.cleanup(dict(Failure=False))
        a.client.command.assert_not_called()

    def test_wait_budget(self):
        import inspect
        self.assertIn('deadline=time.monotonic()+150', inspect.getsource(Adapter.final))

if __name__ == '__main__': unittest.main()
