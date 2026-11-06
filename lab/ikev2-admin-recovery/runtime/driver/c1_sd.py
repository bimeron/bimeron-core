"""Independent, intentionally narrow C1 SD decoder. No Windows/native dependency."""
import re
import struct

SEMANTICS = dict(Revision=1, Control=32772, DACLPresent=True,
                 ACEType=0, ACEFlags=0, Mask=1, SID='S-1-5-18')
CANONICAL = (1, 32772, True, 0, 0, 1, 'S-1-5-18')

def sddl(value):
    # CC is SDDL's symbolic bit 1, used here as FWP_ACTRL_MATCH_FILTER.
    if not isinstance(value, str) or not re.fullmatch(r'D:\(A;;(?:CC|0x0*1);;;(?:SY|S-1-5-18)\)', value):
        raise ValueError('C1 SDDL refused')
    return CANONICAL

def binary(raw):
    if len(raw) != 48:
        raise ValueError('C1 SD size')
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from('<BBHIIII', raw)
    if (revision, reserved, control, owner, group, sacl, dacl) != (1, 0, 0x8004, 0, 0, 0, 20):
        raise ValueError('C1 SD header')
    if struct.unpack_from('<BBHHH', raw, dacl) != (2, 0, 28, 1, 0):
        raise ValueError('C1 DACL')
    if struct.unpack_from('<BBHI', raw, 28) != (0, 0, 20, 1):
        raise ValueError('C1 ACE')
    rev, count = raw[36:38]
    authority = int.from_bytes(raw[38:44], 'big')
    subauthority = struct.unpack_from('<I', raw, 44)[0]
    if (rev, count, authority, subauthority) != (1, 1, 5, 18):
        raise ValueError('C1 SID')
    return CANONICAL

def native(value):
    if not isinstance(value, dict) or set(value) != {'Type','BytesHex','SDDL','Semantics'}:
        raise ValueError('C1 JSON schema')
    if value['Type'] != 'FWP_SECURITY_DESCRIPTOR_TYPE':
        raise ValueError('C1 JSON type')
    text = value['BytesHex']
    if not isinstance(text, str) or not re.fullmatch('[0-9a-f]{96}', text):
        raise ValueError('C1 hex encoding')
    result = binary(bytes.fromhex(text))
    if sddl(value['SDDL']) != result:
        raise ValueError('C1 SDDL mismatch')
    sem = value['Semantics']
    if not isinstance(sem, dict) or set(sem) != set(SEMANTICS) or any(type(sem[k]) is not type(v) or sem[k] != v for k,v in SEMANTICS.items()):
        raise ValueError('C1 semantics mismatch')
    return result

def bfe(cv):
    if cv.attrib or (cv.text or '').strip() or [x.tag for x in cv] != ['type','sd']:
        raise ValueError('Unknown BFE SD encoding: preflight refused')
    for x in cv:
        if x.attrib or list(x) or (x.tail or '').strip():
            raise ValueError('Malformed BFE SD')
    if cv[0].text != 'FWP_SECURITY_DESCRIPTOR_TYPE':
        raise ValueError('Wrong BFE SD type')
    return sddl(cv[1].text)
