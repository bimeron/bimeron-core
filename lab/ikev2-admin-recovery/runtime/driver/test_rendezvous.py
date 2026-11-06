import json,pathlib,tempfile,unittest
from rendezvous import release,ROLES
N='a'*64
class Tests(unittest.TestCase):
 def test_positive_and_duplicate_dispatch(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)
   for r in ROLES:(p/(r+'.ready')).write_text(json.dumps(dict(nonce=N,role=r)))
   release(p,N,0);self.assertEqual(json.loads((p/'readers.dispatch').read_text())['roles'],list(ROLES))
   with self.assertRaises(FileExistsError):release(p,N,0)
 def test_negatives(self):
  for case in ('missing','stale','wrong-role','duplicate-key','partial'):
   with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d)
    for r in ROLES:(p/(r+'.ready')).write_text(json.dumps(dict(nonce=N,role=r)))
    f=p/'collector.ready'
    if case=='missing':f.unlink()
    if case=='stale':f.write_text(json.dumps(dict(nonce='b'*64,role='collector')))
    if case=='wrong-role':f.write_text(json.dumps(dict(nonce=N,role='barrier')))
    if case=='duplicate-key':f.write_text('{"nonce":"x","nonce":"y","role":"collector"}')
    if case=='partial':f.write_text('{')
    with self.assertRaises(ValueError):release(p,N,0)
    self.assertFalse((p/'readers.dispatch').exists())
if __name__=='__main__':unittest.main()
