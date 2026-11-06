import unittest,json,hashlib,copy
from pathlib import Path
import xml.etree.ElementTree as ET
from protected_evidence import check_policy,guid
F=Path(__file__).resolve().parents[2]/'step9-abi/run-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/gate'
class Policy(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.xml=(F/'bfe-bootstrap.xml').read_bytes(); raw=(F/'rules-bootstrap.json').read_bytes()
  assert hashlib.sha256(cls.xml).hexdigest()=='9fff1ab4295e2ba67eb2fe970a6648f3f0efb6afd8dbe50834dd1cb2f5f33e0a'
  assert hashlib.sha256(raw).hexdigest()=='eda8b61152116ec31406273d7423780624b01696dc2d46fc8c228e26fd1c73e0'
  cls.rules=json.loads(raw); cls.owned=[i for i,r in enumerate(cls.rules) if r['Name']=='STEP9 ABI LAB ONLY']
  cls.ledger=['151aba0b-bb73-481c-98b9-61c901fa087e','221dd053-53bc-4930-b8bf-03a1922f2059']+[guid(cls.rules[i]['ID']) for i in cls.owned]
  cls.original_xml=cls.xml; cls.original_rules=copy.deepcopy(cls.rules)
  root=ET.fromstring(cls.xml)
  ale={'c38d57d1-05a7-4c33-904f-7fbceee60e82','e1cd9fe7-f4b5-4273-96c0-592e487b8650'}
  cls.sd_value={'Type':'FWP_SECURITY_DESCRIPTOR_TYPE',
   'BytesHex':'010004800000000000000000000000001400000002001c00010000000000140001000000010100000000000512000000',
   'SDDL':'D:(A;;CC;;;SY)',
   'Semantics':{'Revision':1,'Control':32772,'DACLPresent':True,'ACEType':0,'ACEFlags':0,'Mask':1,'SID':'S-1-5-18'}}
  cls.user_rules=[]
  for i in cls.owned:
   r=cls.rules[i]
   if guid(r['Layer']) in ale and r['Action']==4098:
    cls.user_rules.append(i)
    r['Conditions'].append({'Field':'af043a0a-b34d-4f86-979c-c90371af6e66','Op':0,'Value':copy.deepcopy(cls.sd_value)})
    x=next(x for x in root.findall('layers/item/filters/item') if guid(x.findtext('filterKey'))==guid(r['ID']))
    conditions=x.find('filterCondition')
    conditions.append(ET.fromstring('<item><fieldKey>FWPM_CONDITION_ALE_USER_ID</fieldKey><matchType>FWP_MATCH_EQUAL</matchType><conditionValue><type>FWP_SECURITY_DESCRIPTOR_TYPE</type><sd>D:(A;;CC;;;SY)</sd></conditionValue></item>'))
    conditions.set('numItems',str(len(conditions)))
  assert len(cls.user_rules)==6
  cls.xml=ET.tostring(root)
 def check(self,xml=None,rules=None): return check_policy(self.xml if xml is None else xml,json.dumps(self.rules if rules is None else rules),guids_json=json.dumps(self.ledger))
 def test_candidate_snapshot(self): self.assertEqual(self.check()['status'],'PASS',self.check())
 def test_original_template_rejected(self): self.assertNotEqual(self.check(xml=self.original_xml,rules=self.original_rules)['status'],'PASS')
 def test_go_mutations(self):
  for i in self.owned:
   for key,val in [('Weight',2),('KernelID',0),('Action',4098 if self.rules[i]['Action']==4097 else 4097),('Disabled',True),('HardAction',True),('Persistent',True),('BootTime',True),('PermitIfMissing',True),('ProviderData','x')]:
    with self.subTest(i=i,key=key):
     r=copy.deepcopy(self.rules); r[i][key]=val; self.assertNotEqual(self.check(rules=r)['status'],'PASS')
 def test_xml_mutations(self):
  root=ET.fromstring(self.xml)
  owned=[x for x in root.findall('layers/item/filters/item') if x.findtext('providerKey','').strip('{}')==self.ledger[0]]
  for i in range(len(owned)):
   for path,val in [('weight/type','FWP_UINT32'),('weight/uint64','3'),('effectiveWeight/uint64','3'),('filterId','0'),('rawContext','1'),('action/type','FWP_ACTION_CALLOUT_TERMINATING')]:
    with self.subTest(i=i,path=path):
     old=owned[i].find(path).text; owned[i].find(path).text=val
     self.assertNotEqual(self.check(xml=ET.tostring(root))['status'],'PASS'); owned[i].find(path).text=old
 def test_missing(self):
  r=copy.deepcopy(self.rules); del r[self.owned[0]]; self.assertEqual(self.check(rules=r)['status'],'INCONCLUSIVE')
 def test_reordering(self):
  r=copy.deepcopy(self.rules)
  for i in self.owned:
   if r[i]['Conditions']: r[i]['Conditions'].reverse()
  self.assertEqual(self.check(rules=r)['status'],'PASS')
 def test_sd_mutations(self):
  for i in self.user_rules:
   cases=[None,{},copy.deepcopy(self.sd_value)]
   cases[-1]['Semantics']['Mask']=True
   for key,val in [('Type','FWP_SID'),('SDDL','D:'),('BytesHex','00'),('Semantics',None)]:
    v=copy.deepcopy(self.sd_value);v[key]=val;cases.append(v)
   for offset in range(48):
    v=copy.deepcopy(self.sd_value);raw=bytearray.fromhex(v['BytesHex']);raw[offset]^=1;v['BytesHex']=raw.hex();cases.append(v)
   for v in cases:
    with self.subTest(rule=i,value=v):
     r=copy.deepcopy(self.rules);r[i]['Conditions'][-1]['Value']=v
     self.assertNotEqual(self.check(rules=r)['status'],'PASS')
   for change in ['missing','duplicate','operator']:
    r=copy.deepcopy(self.rules);c=r[i]['Conditions']
    if change=='missing':c.pop()
    elif change=='duplicate':c.append(copy.deepcopy(c[-1]))
    else:c[-1]['Op']=1
    self.assertNotEqual(self.check(rules=r)['status'],'PASS')
 def test_bfe_sd_mutations(self):
  root=ET.fromstring(self.xml)
  nodes=[x.find('conditionValue') for x in root.findall('layers/item/filters/item/filterCondition/item') if x.findtext('fieldKey')=='FWPM_CONDITION_ALE_USER_ID' and x.findtext('conditionValue/sd')=='D:(A;;CC;;;SY)']
  self.assertEqual(len(nodes),6)
  for cv in nodes:
   for sddl in ['', 'D:', 'D:NO_ACCESS_CONTROL','O:SY','D:(A;;CC;;;WD)','D:(A;;GA;;;SY)','D:(A;;CCRC;;;SY)','D:(D;;CC;;;SY)','D:(A;ID;CC;;;SY)','D:(A;;CC;;;SY)(A;;CC;;;WD)','D:(A;;CC;;;SY)junk']:
    cv.find('sd').text=sddl
    self.assertNotEqual(self.check(xml=ET.tostring(root))['status'],'PASS')
   cv.find('sd').text='D:(A;;CC;;;SY)'
   cv.find('sd').tag='securityDescriptor'
   self.assertNotEqual(self.check(xml=ET.tostring(root))['status'],'PASS')
   cv.find('securityDescriptor').tag='sd'
   cv.find('type').text='FWP_BYTE_BLOB_TYPE'
   self.assertNotEqual(self.check(xml=ET.tostring(root))['status'],'PASS')
   cv.find('type').text='FWP_SECURITY_DESCRIPTOR_TYPE'
if __name__=='__main__': unittest.main()
