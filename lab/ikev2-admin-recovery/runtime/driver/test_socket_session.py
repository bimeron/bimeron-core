"""Read-only replay of saved failed run1; no execution authority."""
import copy
import hashlib
import json
import pathlib
import unittest
from preexisting import continuity

class SessionTests(unittest.TestCase):
    def setUp(self):
        repo=pathlib.Path(__file__).resolve().parents[3]
        run=repo/'build/carrier-discrimination-20261104/preexisting-exact/run1'
        self.run=json.loads((run/'run.json').read_bytes())
        diagnostic=json.loads((run/'drain-diagnostic.json').read_bytes())
        self.path=pathlib.Path(self.run['capture'])/'owner-transport/proofs/terminal.jsonl'
        self.raw=self.path.read_bytes()
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),diagnostic['wrapper']['terminalJournal']['sha256'])
        self.rows=[json.loads(x) for x in self.raw.splitlines()]
    def test_saved_terminal_session_zero(self):
        self.assertEqual({r['detail']['session'] for r in self.rows if r['kind']=='socket-open'},{0})
        self.assertIsNone(continuity(self.rows,self.run['nonce'],terminal=True))
        self.assertEqual(self.rows[-1]['status'],'cancelled')
        self.assertEqual(self.path.read_bytes(),self.raw)
    def test_negative_and_types(self):
        for value in (-1,False,True,0.0,'0',None):
            with self.subTest(value=value):
                rows=copy.deepcopy(self.rows)
                next(r for r in rows if r['kind']=='socket-open')['detail']['session']=value
                with self.assertRaisesRegex(ValueError,'Socket properties'):
                    continuity(rows,self.run['nonce'],terminal=True)
    def test_attempt_session_replacement(self):
        rows=copy.deepcopy(self.rows)
        next(r for r in rows if r['kind']=='attempt' and 'socket' in r.get('detail',{}))['detail']['socket']['session']=2
        with self.assertRaisesRegex(ValueError,'Socket continuity/replacement'):
            continuity(rows,self.run['nonce'],terminal=True)

if __name__=='__main__':unittest.main()
