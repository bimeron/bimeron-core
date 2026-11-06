import unittest,json
from records import snapshot,Progress,TARGETS
N='a'*64; ID=dict(pid=7,start='2026-11-03T00:00:00Z',sid='S-1-5-21-1')
def fixture():
 rows=[]
 def add(kind,target='all',round=0):
  rows.append(dict(nonce=N,sequence=len(rows)+1,round=round,producer=ID,utc='2026-11-03T00:00:00Z',ticks=len(rows),kind=kind,target=target,status='sent'))
 add('start');add('round-start',round=1)
 for t in sorted(TARGETS):add('attempt',t,1);add('result',t,1)
 add('round-complete',round=1)
 return rows
def encode(rows):return b''.join(json.dumps(r).encode()+b'\n' for r in rows)
class Tests(unittest.TestCase):
 def test_complete(self):self.assertEqual(len(snapshot(encode(fixture()),N,ID)['rounds']),1)
 def test_partial(self):
  data=encode(fixture())+b'{"nonce"';v=snapshot(data,N,ID);self.assertEqual(v['partialBytes'],8)
 def test_corruption(self):
  for change in ('gap','identity','round','target','clock'):
   rows=fixture()
   if change=='gap':rows[2]['sequence']=10
   if change=='identity':rows[2]['producer']={}
   if change=='round':rows[-1]['round']=2
   if change=='target':rows[2]['target']='unknown'
   if change=='clock':rows[2]['ticks']=-1
   with self.assertRaises(ValueError):snapshot(encode(rows),N,ID)
 def test_missing_challenge(self):
  rows=fixture();rows.pop(3)
  for i,r in enumerate(rows):r['sequence']=i+1
  with self.assertRaises(ValueError):snapshot(encode(rows),N,ID)
 def test_sticky(self):
  p=Progress();data=encode(fixture());p.observe(data,N,ID,0)
  with self.assertRaises(ValueError):p.observe(data,N,ID,9)
  with self.assertRaises(ValueError):p.observe(data,N,ID,10)
 def test_read_error_sticky(self):
  p=Progress();data=encode(fixture());p.observe(data,N,ID,0)
  with self.assertRaises(ValueError):p.fail('read-error')
  with self.assertRaises(ValueError):p.observe(data,N,ID,1)
 def test_malformed(self):
  for data in (b'{}\n',b'\xff\n',b'bad\n',b'x'*16385):
   with self.assertRaises(ValueError):snapshot(data,N,ID)
if __name__=='__main__':unittest.main()
