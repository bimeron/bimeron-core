"""Raw partial-deployment observations must never substitute for drain proof."""
import unittest

from protected_evidence import check_exact_drain
from protected_transport import encode


class EarlyRawDrainTests(unittest.TestCase):
    def test_raw_no_producer_observation_is_not_drain_pass(self):
        nonce = 'a' * 64
        bundle = dict(
            wrapper=encode(dict(schema='full300-prelaunch-drain-v1', nonce=nonce)),
            admissions=encode(dict(nonce=nonce, sealed=True, entries=[])),
            task=encode(dict(nonce=nonce, state=3, instanceGuids=[])),
            files={'registration.json': encode(dict(xml='raw registration'))},
        )
        result = check_exact_drain(bundle, nonce)
        self.assertNotEqual(result['status'], 'PASS')
        self.assertEqual(set(bundle['files']), {'registration.json'})


if __name__ == '__main__':
    unittest.main()
