"""Fixed transient sink post-stop receipt; pure rendering/validation inputs."""
import hashlib
import json
import re
import shlex


TEMPLATE="""import json,os
value=dict(schema='fresh-sink-exit-v1',nonce=NONCE,unit=UNIT,contractSHA256=CONTRACT,
 invocationId=os.environ['INVOCATION_ID'],result=os.environ['SERVICE_RESULT'],
 exitCode=os.environ.get('EXIT_CODE',''),exitStatus=os.environ.get('EXIT_STATUS',''))
with open('/var/lib/step8/run-'+NONCE+'/sink-exit.json','xb') as stream:
 stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode());stream.flush();os.fsync(stream.fileno())
"""
CONTRACT_SHA256=hashlib.sha256(TEMPLATE.encode()).hexdigest()


def start_command(nonce,source):
    if re.fullmatch('[a-f0-9]{64}',nonce) is None:raise ValueError('Fresh sink nonce')
    if re.fullmatch('/home/lab/step9-[a-f0-9]{64}',source) is None:raise ValueError('Reviewed observer source path')
    unit='step10-prep-'+nonce
    program=('NONCE='+repr(nonce)+';UNIT='+repr(unit+'.service')+';CONTRACT='+repr(CONTRACT_SHA256)+'\n'+TEMPLATE)
    post='/usr/bin/python3 -c "exec(bytes.fromhex(\''+program.encode().hex()+'\'))"'
    argv=['sudo','systemd-run','--unit='+unit,'--collect','--property=Type=exec',
          '--property=KillMode=control-group','--property=SendSIGKILL=no',
          '--property=ExecStopPost='+post,'/usr/bin/python3',source+'/sinks.py']
    return shlex.join(argv)


def retirement_commands(nonce,capture):
    """Exact retirement argv/bytes shared by the normal body and Handoff."""
    if re.fullmatch('[a-f0-9]{64}',nonce) is None:raise ValueError('Fresh retirement nonce')
    confirmation=json.dumps(dict(Nonce=nonce,OwnedRASAbsent=True,WFPOwnerCleaned=True),
                            sort_keys=True,separators=(',',':'))
    program=("import pathlib;pathlib.Path('/var/lib/step8/run-"+nonce+
             "/cleanup-confirmed.json').write_text("+repr(confirmation)+")").encode()
    return {'confirmation':confirmation.encode(),
            'admin-capture-confirm':('sudo python3 -',program),
            'admin-capture-stop':('sudo python3 '+capture+' stop '+nonce,b''),
            'admin-sink-stop':('sudo systemctl stop step10-prep-'+nonce,b'')}
