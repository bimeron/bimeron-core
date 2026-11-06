import unittest
from protected_evidence import check_policy, check_controls, assess_interval, guid

class EvidenceTests(unittest.TestCase):
    def test_guid(self):
        self.assertEqual(guid({'Data1':0,'Data2':0,'Data3':0,'Data4':[0]*8}), '00000000-0000-0000-0000-000000000000')
    def test_missing_policy(self):
        self.assertEqual(check_policy('<root/>','[]')['status'], 'INCONCLUSIVE')
    def test_invalid_policy(self):
        self.assertEqual(check_policy('<','[]')['status'], 'INCONCLUSIVE')
    def test_missing_controls(self):
        self.assertEqual(check_controls(b'', 'a'*64,b'',{})['status'], 'INCONCLUSIVE')
    def test_quiet_not_pass(self):
        self.assertEqual(assess_interval([],b'',b'','a'*64,{},0,300)['status'], 'INCONCLUSIVE')

if __name__ == '__main__': unittest.main()
