"""Strict stock administrative companion, never a native cleanup PASS."""
import hashlib,json,pathlib,re,stat
class ReceiptError(ValueError): pass
def require(ok,message):
 if not ok: raise ReceiptError(message)
def exact(obj,keys): require(type(obj) is dict and set(obj)==set(keys),'fields')
def read_bytes_ref(root,ref):
 exact(ref,('name','sha256','length'))
 require(type(ref['name']) is str and re.fullmatch(r'[a-z][a-z0-9-]*\.(json|raw)',ref['name']),'basename')
 require(type(ref['length']) is int and 0<ref['length']<=1048576,'length')
 require(type(ref['sha256']) is str and re.fullmatch('[a-f0-9]{64}',ref['sha256']),'digest')
 p=pathlib.Path(root)/ref['name']
 for part in (p,*p.parents):
  s=part.lstat();require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'reparse')
 b=p.read_bytes();require(len(b)==ref['length'] and hashlib.sha256(b).hexdigest()==ref['sha256'],'reference bytes')
 return b
def read_ref(root,ref):
 b=read_bytes_ref(root,ref)
 def pairs(items):
  d={}
  for k,v in items: require(k not in d,'duplicate key');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs)
def validate(receipt,root,binding,nonce,phase="final"):
 require(phase in ("precleanup","final"),"phase")
 exact(receipt,('schema','nonce','binding','normalCleanupSucceeded','rawUiOutcome','references','journal'))
 require(receipt['schema']==('stock-admin-precleanup-v1' if phase=='precleanup' else 'stock-admin-receipt-v1') and receipt['nonce']==nonce and receipt['binding']==binding,'binding')
 require(receipt['normalCleanupSucceeded'] is False,'normal cleanup forbidden')
 journal=receipt['journal'];require(type(journal) is dict and bool(journal),'journal')
 for ref in journal.values():read_bytes_ref(root,ref)
 refs=receipt['references'];exact(refs,('isolation','stopped','privateExit','taskClosure','restored','nic') if phase=='precleanup' else ('isolation','stopped','privateExit','taskClosure','restored','nic','session','precleanup','c1'))
 docs={k:read_ref(root,v) for k,v in refs.items()}
 for d in docs.values():require(d.get('nonce')==nonce and d.get('binding')==binding,'evidence binding')
 iso=docs['isolation'];require(iso.get('connected') is False and iso.get('mac')=='<LAB_GUEST_MAC_HEX>' and iso.get('id')==r'Microsoft:<LAB_VM_ID_UPPER>\<LAB_VM_NIC_ID>','isolation')
 stopped=docs['stopped'];require(set(stopped.get('services',{}))=={'RasMan','EapHost','IKEEXT'},'stopped set')
 for s in stopped['services'].values():
  require(s.get('state')=='Stopped' and type(s.get('exitCode')) is int and s['exitCode']==0 and type(s.get('serviceSpecificExitCode')) is int and s['serviceSpecificExitCode']==0,'normal stopped')
  require(s.get('identityBefore')==s.get('identityAfter') and type(s.get('identityBefore')) is dict and bool(s['identityBefore']),'service identity')
  require(s.get('dependentsBefore')==s.get('dependentsAfter') and type(s.get('dependentsBefore')) is list,'dependents')
  require(all(x.get('state')=='Stopped' for x in s['dependentsAfter']),'dependent state')
  require(s.get('cohostsBefore')==s.get('cohostsAfter') and type(s.get('cohostsBefore')) is list,'cohosts')
 for d in (stopped,docs['restored'],docs['nic']):
  require(d.get('rasReaderSucceeded') is True and d.get('saReaderSucceeded') is True,'readers')
  require(all(type(d.get(k)) is int and d[k]==0 for k in ('ras','main','quick')),'quiescence')
  require(d.get('bfeBefore')==d.get('bfeAfter') and type(d.get('bfeBefore')) is dict,'BFE')
  require(d.get('policyAgentBefore')==d.get('policyAgentAfter') and type(d.get('policyAgentBefore')) is dict,'PolicyAgent')
 ex=docs['privateExit'];require(ex.get('handleRetainedBeforePermit') is True and ex.get('signalled') is True and ex.get('identityBefore')==ex.get('identityAfter') and type(ex.get('identityBefore')) is dict,'private exit')
 require(type(ex.get('terminateCalls')) is int and ex['terminateCalls'] in (0,1),'retirement count')
 task=docs['taskClosure'];require(task.get('instances')==[] and task.get('registrationDeleted') is True and task.get('registrationBefore')==task.get('registrationAtDelete') and type(task.get('registrationBefore')) is dict and bool(task['registrationBefore']),'task closure')
 restored=docs['restored']
 for k in ('services','context','profile','originalTask','wrapper','policy'):
  require(k+'Before' in restored and restored[k+'Before'] is not None and restored[k+'Before']==restored.get(k+'After'),'restore '+k)
 nic=docs['nic'];require(nic.get('connected') is (phase=='final') and nic.get('id')==iso['id'] and nic.get('mac')==iso['mac'] and nic.get('switchId')==('<LAB_VSWITCH_ID>' if phase=='final' else ''),'NIC restore')
 if phase=='final':
  session=docs['session'];require(session.get('state')=='Closed' and type(session.get('outstandingReads')) is int and session['outstandingReads']==0 and type(session.get('outstandingMutations')) is int and session['outstandingMutations']==0,'session closure')
  validate(docs['precleanup'],root,binding,nonce,'precleanup')
  c1=docs['c1'];require(c1.get('status')=='PASS' and all(c1.get(k) is True for k in ('rasAbsent','ownerAbsent','taskReady')) and type(c1.get('refs')) is dict and bool(c1['refs']),'C1 independent absence')
  evidence=read_ref(root,c1['evidence'])
  def unpack(v):
   if type(v) is dict and set(v)=={'bytes'}:return read_bytes_ref(root,v['bytes'])
   if type(v) is dict:return {k:unpack(x) for k,x in v.items()}
   if type(v) is list:return [unpack(x) for x in v]
   return v
  from protected_evidence import check_independent_absence
  checked=check_independent_absence(unpack(evidence),binding,nonce)
  require(checked['status']=='PASS' and checked['refs']==c1['refs'],'C1 actual evidence')
  native=read_ref(root,c1['nativeStatus'])
  require(native.get('State')=='CLOSED' and native.get('Live',{}).get('NoDial') is True and native['Live'].get('Attempted') is False and native['Live'].get('NativeEntered') is False and native['Live'].get('CleanupSucceeded') is True,'C1 genuine NoDial')
 outcome=receipt['rawUiOutcome'];require(type(outcome) is dict,'outcome')
 if outcome.get('state')=='unknown': exact(outcome,('state',))
 else:
  exact(outcome,('state','BOOL','dwError','result'));require(outcome['state']=='returned' and type(outcome['BOOL']) is int and outcome['BOOL'] in (0,1) and type(outcome['dwError']) is int and 0<=outcome['dwError']<=0xffffffff,'raw outcome')
  raw=read_ref(root,outcome['result']);require(raw.get('nonce')==nonce and raw.get('BOOL')==outcome['BOOL'] and raw.get('dwError')==outcome['dwError'],'raw result')
 return receipt

def validate_no_permit(receipt,root,binding,nonce,phase="final"):
 require(phase in ('precleanup','final'),'phase')
 exact(receipt,('schema','nonce','binding','normalCleanupSucceeded','rawUiOutcome','references','journal'))
 require(receipt['schema']==('stock-no-permit-precleanup-v1' if phase=='precleanup' else 'stock-no-permit-receipt-v1'),'no-permit discriminant')
 require(receipt['nonce']==nonce and receipt['binding']==binding,'no-permit binding')
 require(receipt['normalCleanupSucceeded'] is False and receipt['rawUiOutcome']=={'state':'unknown'},'no-permit outcome')
 require(type(receipt['journal']) is dict and bool(receipt['journal']),'no-permit journal')
 for ref in receipt['journal'].values():read_bytes_ref(root,ref)
 refs=receipt['references']
 exact(refs,('isolation','deployment','taskClosure','restored','nic') if phase=='precleanup' else ('isolation','deployment','taskClosure','restored','nic','session','precleanup','c1'))
 docs={k:read_ref(root,v) for k,v in refs.items()}
 for d in docs.values():require(d.get('nonce')==nonce and d.get('binding')==binding,'no-permit evidence binding')
 deployment=docs['deployment'];ledger=deployment.get('ownerLedger')
 exact(deployment,('nonce','binding','pinAcquisitionNeverInitiated','permitMarkersAbsent','registration','instance','naturalCompletion','restartDisabled','launcherSHA256','configSHA256','baseline','state','ownerLedger'))
 require(deployment['pinAcquisitionNeverInitiated'] is True,'unpinned no-permit branch')
 require(type(deployment['baseline']) is dict and type(deployment['state']) is dict,'no-permit baseline evidence')
 for k in ('services','context','profile','originalTask','wrapper','policy'):
  require(k in deployment['baseline'] and deployment['baseline'][k]==deployment['state'].get(k),'no-permit original baseline '+k)
 require(type(ledger) is dict,'original owner ledger')
 exact(ledger,('permitSubmission','originalDeploymentCollected','originalOperationsReconciled','operations'))
 exact(ledger['operations'],('task-registration','task-start'))
 for operation in ledger['operations'].values():
  exact(operation,('submission','collection','terminal','result','reconciled'))
  require(operation['submission']=='Submitted' and operation['collection']=='Collected' and (operation['terminal']=='Completed' or operation['terminal']=='Failed' and operation['reconciled'] is True),'original terminal deployment evidence')
 require(ledger['operations']['task-registration']['result']==deployment.get('registration') and ledger['operations']['task-start']['result']=={'instance':deployment.get('instance')},'original returned registration and instance bindings')
 require(ledger['permitSubmission']=='NeverInitiated' and ledger['originalDeploymentCollected'] is True and ledger['originalOperationsReconciled'] is True,'permit submission must never have begun')
 require(deployment.get('permitMarkersAbsent') is True and deployment.get('naturalCompletion') is True and deployment.get('restartDisabled') is True,'no-permit natural closure')
 require(type(deployment.get('instance')) is str and bool(deployment['instance']),'returned original instance')
 for k in ('launcherSHA256','configSHA256'):require(type(deployment.get(k)) is str and re.fullmatch('[a-f0-9]{64}',deployment[k]),'deployment byte binding')
 task=docs['taskClosure']
 require(task.get('instances')==[] and task.get('registrationDeleted') is True and task.get('instance')==deployment['instance'],'no-permit task closure')
 require(type(deployment.get('registration')) is dict and bool(deployment['registration']) and deployment['registration']==task.get('registrationBefore')==task.get('registrationAtDelete'),'exact original registration')
 iso=docs['isolation'];nic=docs['nic']
 require(iso.get('connected') is False and iso.get('mac')=='<LAB_GUEST_MAC_HEX>' and iso.get('id')==r'Microsoft:<LAB_VM_ID_UPPER>\<LAB_VM_NIC_ID>','no-permit isolation')
 require(nic.get('connected') is (phase=='final') and nic.get('id')==iso['id'] and nic.get('mac')==iso['mac'] and nic.get('switchId')==('<LAB_VSWITCH_ID>' if phase=='final' else ''),'no-permit NIC')
 for d in (docs['restored'],nic):
  require(d.get('rasReaderSucceeded') is True and d.get('saReaderSucceeded') is True and all(type(d.get(k)) is int and d[k]==0 for k in ('ras','main','quick')),'no-permit zero readers')
  for k in ('bfe','policyAgent'):require(type(d.get(k+'Before')) is dict and d[k+'Before']==d.get(k+'After'),'no-permit protected service')
 restored=docs['restored']
 for k in ('services','context','profile','originalTask','wrapper','policy'):require(k+'Before' in restored and restored[k+'Before'] is not None and restored[k+'Before']==restored.get(k+'After'),'no-permit baseline '+k)
 if phase=='final':
  validate_no_permit(docs['precleanup'],root,binding,nonce,'precleanup')
  session=docs['session'];require(session.get('state')=='Closed' and type(session.get('outstandingReads')) is int and session['outstandingReads']==0 and type(session.get('outstandingMutations')) is int and session['outstandingMutations']==0,'no-permit session closure')
  c1=docs['c1'];require(c1.get('status')=='PASS' and all(c1.get(k) is True for k in ('rasAbsent','ownerAbsent','taskReady')) and type(c1.get('refs')) is dict and bool(c1['refs']),'C1 independent absence')
  evidence=read_ref(root,c1['evidence'])
  def unpack(v):
   if type(v) is dict and set(v)=={'bytes'}:return read_bytes_ref(root,v['bytes'])
   if type(v) is dict:return {k:unpack(x) for k,x in v.items()}
   if type(v) is list:return [unpack(x) for x in v]
   return v
  from protected_evidence import check_independent_absence
  checked=check_independent_absence(unpack(evidence),binding,nonce)
  require(checked['status']=='PASS' and checked['refs']==c1['refs'],'C1 actual evidence')
  native=read_ref(root,c1['nativeStatus'])
  require(native.get('State')=='CLOSED' and native.get('Live',{}).get('NoDial') is True and native['Live'].get('Attempted') is False and native['Live'].get('NativeEntered') is False and native['Live'].get('CleanupSucceeded') is True,'C1 genuine NoDial')
 return receipt
