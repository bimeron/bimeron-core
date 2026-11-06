import pathlib,subprocess
here=pathlib.Path(__file__).resolve().parent
p=subprocess.run([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(here/'hash-context.ps1'),'-Nonce','0'*64,'-Mode','provenance'],capture_output=True,timeout=15,env=__import__('windows_powershell').environment())
(here/'hash-context.log').write_bytes(p.stdout+p.stderr)
print((p.stdout+p.stderr).decode(errors='replace'));print('exit=',p.returncode)
