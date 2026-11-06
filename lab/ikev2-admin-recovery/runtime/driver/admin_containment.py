"""Fresh idle watcher admission before any capture, guest or preparation effect."""
import pathlib
import subprocess
import sys
import time
from admin_recovery import encode,decode,sha,require,same,Hold
from process_handles import ChildHandle


class Containment:
    def __init__(self,root,driver,admission,nonce,config_hash,candidate_hash,manifest):
        self.root=pathlib.Path(root);self.driver=pathlib.Path(driver);self.admission=admission
        self.context=dict(schema='fresh-containment-admission-v1',nonce=nonce,
                          configSHA256=config_hash,candidateSHA256=candidate_hash)
        self.manifest=manifest;self.process=self.handle=None;self.started=False
        self.bound=None

    def publish(self,name,raw):
        from admin_recovery import Journal
        Journal(self.root,self.admission).write(name,raw)

    def start(self,popen=subprocess.Popen,identity=ChildHandle,clock=time.monotonic,pause=time.sleep):
        require(not self.started,'Original containment already started');self.started=True
        self.publish('containment-admission.json',encode(self.context))
        self.publish('containment-sources.json',self.manifest)
        args=[sys.executable,'-I','-S',str(self.driver/'pinned_watcher.py'),
              '--manifest',str(self.root/'containment-sources.json'),'--sha256',sha(self.manifest),
              '--driver',str(self.driver),'--config',str(self.root/'host-supervisor-config.json'),
              '--admission',str(self.root/'containment-admission.json')]
        self.publish('containment-start-reserved.json',encode(dict(context=self.context,argv=args)))
        self.admission.revalidate()
        with (self.root/'independent.stdout').open('xb') as out,(self.root/'independent.stderr').open('xb') as err:
            self.process=popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                shell=False,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self.handle=identity(self.process)
        self.bound=dict(pid=self.process.pid,creationFileTime=str(self.handle.creation),
                        imageSHA256=sha(pathlib.Path(self.handle.exe).read_bytes()))
        deadline=clock()+10
        while not (self.root/'containment-ready.json').is_file() and clock()<deadline:
            require(self.process.poll() is None,'Original containment exited before admission');pause(.05)
        ready=decode((self.root/'containment-ready.json').read_bytes())
        require(same(ready,dict(context=self.context,identity=self.bound)),'Original containment readiness')
        return self

    def abort_idle_bounded(self,seconds=30,clock=time.monotonic,pause=time.sleep):
        """Finite bootstrap abort: positive receipt, or a HOLD keeping the child."""
        deadline=clock()+seconds
        while True:
            try:return self.abort_idle()
            except Exception as error:
                if clock()>=deadline:
                    raise Hold('Idle containment abort unacknowledged; original child retained') from error
                pause(.1)

    def abort_idle(self):
        """Only pre-effect bootstrap abort; positive original acknowledgement required."""
        require(not (self.root/'host-supervisor-config.json').exists(),'Containment already supervising capture')
        self.publish('containment-abort.json',encode(self.context))
        receipt=decode((self.root/'containment-aborted.json').read_bytes())
        require(same(receipt,dict(context=self.context,identity=self.bound)) and self.process.poll()==1,
                'Original idle containment abort not complete')
        return receipt
