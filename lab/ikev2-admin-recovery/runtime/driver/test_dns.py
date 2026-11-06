import unittest
from offline_evidence import dns_rounds
N='a'*64
def question():
 labels=[b's10',N[:32].encode(),N[32:].encode(),b'r12',b'test']
 return bytes.fromhex('531001000001000000000000')+b''.join(bytes([len(x)])+x for x in labels)+b'\x00\x00\x01\x00\x01'
class Tests(unittest.TestCase):
 def test_valid(self):
  q=question();self.assertEqual(dns_rounds(q,N,False),['12']);self.assertEqual(dns_rounds(len(q).to_bytes(2,'big')+q,N,True),['12'])
 def test_wrong_run(self):self.assertEqual(dns_rounds(question(),'b'*64,False),[])
 def test_invalid(self):
  q=question()
  for b in (q[:-1],q+b'x',q[:12]+b'\xc0\x00',q.replace(b'r12',b'r00')):self.assertEqual(dns_rounds(b,N,False),[])
if __name__=='__main__':unittest.main()
