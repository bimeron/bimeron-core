"""Reserve and retain the two preparation children before identity/publication."""
import subprocess
import pathlib
from admin_recovery import encode, decode, require, sha, same
from process_handles import ChildHandle
from stock_controller import _stock_child_environment


class OriginalProcesses:
    def __init__(self, owner, popen=subprocess.Popen, identity=ChildHandle,
                 environment=_stock_child_environment):
        self.owner,self.popen,self.identity,self.environment=owner,popen,identity,environment
        self.children={}

    def __call__(self,name,argv,**streams):
        require(name in ('watcher','preparation') and name not in self.children,'Original child one-shot')
        record=dict(state='Reserved',process=None,handle=None,argv=list(argv))
        self.children[name]=record
        if name=='preparation':
            self.owner.resources.setdefault('entryInventory',{})['preparationAttempted']=True
            self.owner.resources['operations']['preparation']=dict(identity=None,submission='Reserved')
            self.owner.resources['operationOwners']['preparation']=self
        self.owner.journal.write(name+'-spawn-reserved.json',encode(dict(binding=self.owner.bound,argv=argv)))
        env=self.environment(argv[0]) if name=='preparation' else None
        record['process']=self.popen(argv,stdin=subprocess.DEVNULL,shell=False,close_fds=True,
            creationflags=subprocess.CREATE_NO_WINDOW,env=env,**streams)
        self.observe_original(name)
        return record['process']

    def observe_original(self,name):
        record=self.children[name]
        require(record['process'] is not None,'Original spawn has no retained process')
        if record['handle'] is None:
            record['handle']=self.identity(record['process'])
        record['state']='Owned'
        handle=record['handle']
        record['identity']=dict(pid=record['process'].pid,creationFileTime=str(handle.creation),
                                imageSHA256=sha(pathlib.Path(handle.exe).read_bytes()))
        if name=='preparation':
            self.owner.resources['waiterIdentity']=record['identity']
            self.owner.resources['operations']['preparation']=dict(identity=record['identity'],submission='Submitted')
            self.owner.resources['operationOwners']['preparation']=self
        return record['process']

    def administrative_closure(self):
        original=self.children['preparation'];identity=original['identity']
        require(type(original['process'].poll()) is int and original['process'].poll() in (0,1),'Original preparation waiter pending')
        raw=(self.owner.journal.root/'preparation-session-closed.json').read_bytes()
        value=decode(raw)
        require(value.get('nonce')==self.owner.bound['nonce'] and
                value.get('host')==dict(pid=identity['pid'],creationFileTime=identity['creationFileTime']),
                'Original preparation closure binding')
        if value.get('schema')=='fresh-preparation-sessions-closed-v1':
            require(type(value['sessions']) is list and bool(value['sessions']) and
                    all(set(item)=={'instanceId','state'} and item['instanceId'] and item['state']=='Closed'
                        for item in value['sessions']),'Original preparation sessions not closed')
        else:
            require(value.get('schema')=='full300-preparation-session-closed-v1' and
                    value.get('stateAfter')=='Closed','Original early preparation closure')
        return dict(identity=identity,submission='Submitted',terminal='Collected',sessionState='Closed',pending=False)
