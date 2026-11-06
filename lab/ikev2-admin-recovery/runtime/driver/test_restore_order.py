import json
import pathlib
import tempfile
import threading
import unittest
from cancellation import control

class Ordering(unittest.TestCase):
    def run_control(self, fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            outcome=root/'preparation-outcome.json'
            outcome.write_text(json.dumps(dict(nonce='n',launchNeverOccurred=True,restored=False)))
            class Latch:
                event=threading.Event()
                value=None
                monotonic=0
                def set(self, value):
                    self.value=str(value)
                    self.event.set()
            class Process:
                def poll(self):
                    if (root/'restore-permit.json').exists():
                        outcome.write_text(json.dumps(dict(nonce='n',restored=True)))
                        return 0
                    return None
            calls=[]
            def callback():
                self.assertFalse((root/'restore-permit.json').exists())
                calls.append('callback')
                if fail: raise TimeoutError('drain deadline')
            result=control(Process(),lambda *args:self.fail('unexpected launch'),root,'n',Latch(),45,lambda values:None,readers=False,clock=lambda:0,pause=lambda _:None,before_restore=callback)
            self.assertEqual(calls,['callback'])
            self.assertEqual(result,not fail)
            self.assertEqual((root/'restore-permit.json').exists(),not fail)
    def test_callback_before_permit_and_exit(self): self.run_control()
    def test_callback_timeout_withholds_permit(self): self.run_control(True)

if __name__=='__main__': unittest.main()
