import struct, unittest
from offline_evidence import assess
N='a'*64
H=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
def packet(t=5,nonce=N,src=b'\xc0\x00\x02\x02'):
    payload=('STEP8-'+nonce+'-ORDINARY-7').encode()
    udp=struct.pack('!HHHH',500,500,8+len(payload),0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(udp),0,0,64,17,0,src,__import__('socket').inet_aton('<LAB_PUBLIC_IP>'))+udp
    p=b'\0'*12+b'\x08\x00'+ip
    return H+struct.pack('<IIII',t,0,len(p),len(p))+p
class Tests(unittest.TestCase):
    def test_candidate(self): self.assertTrue(assess(packet(),N,'4','6')['records'][0]['forbidden_candidate'])
    def test_boundaries(self):
        for t in (4,6): self.assertEqual(assess(packet(t),N,'4','6')['status'],'INCONCLUSIVE')
    def test_nonce(self): self.assertEqual(assess(packet(nonce='b'*64),N,'4','6')['records'][0]['sequences'],[])
    def test_truncated(self):
        for p in (H[:10],H+b'x',packet()[:-1]): self.assertTrue(assess(p,N,'4','6')['limitations'])
    def test_sender(self): self.assertEqual(assess(packet(src=b'\xc0\x00\x02\x03'),N,'4','6')['status'],'INCONCLUSIVE')
    def test_inputs(self):
        for lo,hi in [('NaN','6'),('6','4'),('4','4')]:
            with self.assertRaises(ValueError): assess(H,N,lo,hi)
if __name__=='__main__': unittest.main()
