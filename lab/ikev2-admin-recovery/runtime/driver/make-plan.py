"""Create fresh review configuration only. Never deploys or starts anything."""
import hashlib,json,pathlib,secrets
root=pathlib.Path(__file__).resolve().parent
nonce=secrets.token_hex(32);guest='C:/BimeronStep10Probe/'+nonce
wrapper="param([int]$Seconds)\r\n$ErrorActionPreference='Stop'\r\ntry { & '"+guest+"/probe.ps1' -Nonce '"+nonce+"' -Seconds 900 -Root '"+guest+"/logs'; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }\r\n"
with (root/'planned-wrapper.ps1').open('xb') as f:f.write(wrapper.encode())
plan=dict(Nonce=nonce,VM='<LAB_VM_ID>',Observer='178202f2-50a2-4b98-a0cc-6cbd9df908e7',Peer='<LAB_PUBLIC_IP>',Profile='Bimeron Step8',GateSeconds=300,ProbeSeconds=900,InspectorSeconds=1200,TestReadHoldMs=0,GuestProbeRoot=guest,GuestNativeRoot='C:/BimeronStep10ProbeNative',SHA256=hashlib.sha256((root/'step10-candidate.exe').read_bytes()).hexdigest(),WrapperSHA256=hashlib.sha256(wrapper.encode()).hexdigest(),ExecutionAdmitted=False)
with (root/'planned-run.json').open('x') as f:json.dump(plan,f,indent=2)
print('Review configuration only:',nonce)
