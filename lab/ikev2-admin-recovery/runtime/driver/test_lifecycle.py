import concurrent.futures,unittest
from lifecycle import settle_readers
class Tests(unittest.TestCase):
 def test_error_does_not_skip_cleanup(self):
  a=concurrent.futures.Future();a.set_exception(OSError('transport failed'))
  class LaterReader:
   inspected=False
   def result(self):self.inspected=True
  b=LaterReader();failure=settle_readers([a,b])
  self.assertEqual(failure,'transport failed');self.assertTrue(b.inspected)
 def test_first_failure_sticky(self):
  a=concurrent.futures.Future();a.set_exception(ValueError('new'))
  self.assertEqual(settle_readers([a],'original'),'original')
if __name__=='__main__':unittest.main()
