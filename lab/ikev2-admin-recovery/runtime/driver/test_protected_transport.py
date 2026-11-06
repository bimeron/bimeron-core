import json
import tempfile
import unittest
from protected_transport import MailboxClient as Adapter, Hold, freeze, strict, PSDirectRPC
from types import SimpleNamespace
import subprocess

class MailboxTests(unittest.TestCase):
    def test_dispatch_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = freeze(directory + '/command.json', json.dumps(dict(nonce='a'*64, op='seal-no-launch')).encode())
            calls = []
            def run(args, **kwargs):
                calls.append((args, kwargs))
                return SimpleNamespace(returncode=0, stdout=b'raw')
            rpc = PSDirectRPC('protected-guest.ps1', 'a'*64, runner=run)
            self.assertEqual(rpc('fetch', path), b'raw')
            self.assertEqual(calls[0][0][-1], 'fetch')
            self.assertIn('final', calls[0][0])
            def timeout(*args, **kwargs):
                raise subprocess.TimeoutExpired('private command', 30, output=b'private')
            rpc.runner = timeout
            with self.assertRaisesRegex(TimeoutError, 'fetch only') as caught:
                rpc('submit', path)
            self.assertNotIn('private', str(caught.exception))

    def test_duplicate_keys(self):
        with self.assertRaises(Hold):
            strict(b'{"seq":1,"s\\u0065q":2}')

    def test_uncertain_launch_only_fetches(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def rpc(operation, path):
                calls.append(operation)
                raise TimeoutError('injected RPC loss')
            adapter = Adapter(directory, 'a'*64, json.dumps({'nonce':'a'*64}).encode(), rpc)
            with self.assertRaises(TimeoutError):
                adapter.command('launch', {})
            self.assertTrue(adapter.ownerMayExist)
            with self.assertRaises(Hold):
                adapter.command('launch', {})
            with self.assertRaises(TimeoutError):
                adapter.reconcile()
            self.assertEqual(calls, ['submit', 'fetch'])

    def test_immutable_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = freeze(directory + '/proof', b'first')
            freeze(path, b'first')
            with self.assertRaises(Hold):
                freeze(path, b'changed')
            self.assertEqual(path.read_bytes(), b'first')

if __name__ == '__main__':
    unittest.main()
