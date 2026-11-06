import json,pathlib,subprocess,sys,tempfile,time,unittest,hashlib
class Tests(unittest.TestCase):
 def test_config_loss_is_sticky_and_original_bound_stop_survives(self):
  evidence=pathlib.Path(__file__).parent/'v2-regression';evidence.mkdir(exist_ok=True)
  root=pathlib.Path(tempfile.mkdtemp(prefix='config-loss-',dir=evidence))
  (root/'supervisor-source.py').write_bytes(pathlib.Path(__file__).with_name('watch-prep.py').read_bytes())
  cfg=dict(nonce='b'*64,capture={'pid':123},cleanup=str(root/'cleanup.json'),captureFinal=str(root/'final.json'),query=[sys.executable,'-c','import json;print(json.dumps(dict(Healthy=True,LiveIdentityHealthy=True,Identity=dict(pid=123))))'])
  config=root/'config.json';raw=json.dumps(cfg).encode();config.write_bytes(raw)
  stdout=(root/'stdout.txt').open('wb');stderr=(root/'stderr.txt').open('wb')
  p=subprocess.Popen([sys.executable,str(pathlib.Path(__file__).with_name('watch-prep.py')),'--config',str(config)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=stdout,stderr=stderr)
  def beats():
   path=root/'independent-heartbeat.jsonl'
   if not path.exists():return []
   return [json.loads(x) for x in path.read_text().splitlines() if x.endswith('}')]
  def advance(count):
   deadline=time.monotonic()+7
   while len(beats())<count and time.monotonic()<deadline:
    self.assertIsNone(p.poll());time.sleep(.05)
   self.assertGreaterEqual(len(beats()),count);self.assertIsNone(p.poll())
  try:
   advance(2);identity=json.loads((root/'host-supervisor-identity.json').read_text())
   config.rename(root/'config.original');count=len(beats());advance(count+2)
   failure=beats()[-1]['failure'];self.assertIn('config unreadable',failure)
   config.mkdir();advance(len(beats())+2);config.rmdir()
   config.write_text(json.dumps(dict(nonce='wrong',query=['must-not-execute'])))
   advance(len(beats())+2)
   config.write_bytes(raw);advance(len(beats())+2)
   self.assertTrue(all(b['failure']==failure for b in beats() if b['failure']))
   self.assertEqual(beats()[-1]['failure'],failure)
   self.assertGreaterEqual(len((root/'independent-capture-health.jsonl').read_text().splitlines()),3)
   final=root/'final.json';final.write_text(json.dumps(dict(ExitCode=0)))
   cleanup=root/'cleanup.json';stop=root/'host-supervisor-stop.json'
   sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
   def decision(cleanup_hash):return dict(identity=identity,cleanupSHA256=cleanup_hash,captureFinalSHA256=sha(final))
   stop.write_text(json.dumps(decision('0'*64)));advance(len(beats())+2)
   self.assertFalse((root/'independent-stop.jsonl').exists())
   cleanup.write_text(json.dumps(dict(rasAbsent=False,ownerAbsent=True,taskReady=True)))
   stop.write_text(json.dumps(decision(sha(cleanup))));advance(len(beats())+2)
   cleanup.write_text(json.dumps(dict(rasAbsent=True,ownerAbsent=True,taskReady=True)))
   advance(len(beats())+2) # Wrong hash still cannot stop.
   stop.write_text('{');advance(len(beats())+2) # Malformed stop cannot kill monitor.
   cleanup.unlink();advance(len(beats())+2)
   self.assertFalse(beats()[-1]['cleanupConfirmed'])
   cleanup.write_text(json.dumps(dict(rasAbsent=True,ownerAbsent=True,taskReady=True)))
   stop.write_text(json.dumps(decision(sha(cleanup))))
   self.assertEqual(p.wait(timeout=8),1)
   stopped=json.loads((root/'independent-stop.jsonl').read_text().splitlines()[-1])
   self.assertEqual(stopped['failure'],failure);self.assertEqual(stopped['identity'],identity)
   (root/'result.json').write_text(json.dumps(dict(passed=True,stickyFailure=failure,originalConfigSHA256=hashlib.sha256(raw).hexdigest(),exit=p.returncode)))
  finally:
   # Only this owned synthetic fixture may be terminated if the regression fails.
   if p.poll() is None:p.terminate();p.wait(timeout=8)
   stdout.close();stderr.close()
 def test_survives_controller_failure_until_verified_stop(self):
  with tempfile.TemporaryDirectory(prefix='s10-watch-') as tmp:
   root=pathlib.Path(tmp);cfg=dict(nonce='a'*64,capture={'pid':123},cleanup=str(root/'cleanup.json'),captureFinal=str(root/'final.json'),query=[sys.executable,'-c','import json;print(json.dumps(dict(Healthy=True,LiveIdentityHealthy=True,Identity=dict(pid=123))))'])
   (root/'config.json').write_text(json.dumps(cfg))
   p=subprocess.Popen([sys.executable,str(pathlib.Path(__file__).with_name('watch-prep.py')),'--config',str(root/'config.json')],creationflags=subprocess.CREATE_NO_WINDOW)
   deadline=time.monotonic()+8
   while not (root/'host-supervisor-identity.json').exists() and time.monotonic()<deadline:time.sleep(.1)
   subprocess.run([sys.executable,'-c','raise SystemExit(17)'],check=False)
   time.sleep(3)
   self.assertIsNone(p.poll());self.assertGreaterEqual(len((root/'independent-heartbeat.jsonl').read_text().splitlines()),3)
   # A cleanup exception/missing evidence does not terminate the independent process.
   self.assertFalse((root/'cleanup.json').exists());time.sleep(1);self.assertIsNone(p.poll())
   (root/'cleanup.json').write_text(json.dumps(dict(rasAbsent=True,ownerAbsent=True,taskReady=True)))
   (root/'final.json').write_text(json.dumps(dict(ExitCode=0)))
   sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
   (root/'host-supervisor-stop.json').write_text(json.dumps(dict(identity=json.loads((root/'host-supervisor-identity.json').read_text()),cleanupSHA256=sha(root/'cleanup.json'),captureFinalSHA256=sha(root/'final.json'))))
   self.assertEqual(p.wait(timeout=8),0)
   self.assertTrue((root/'independent-stop.jsonl').exists())
if __name__=='__main__':unittest.main()
