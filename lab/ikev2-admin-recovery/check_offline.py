"""Explicit inert acceptance checks; never execute preparation or native admission."""
import ast
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import uuid

ROOT=pathlib.Path(__file__).resolve().parent
DRIVER=ROOT/'runtime/driver'
SNAPSHOTS=('source','supplement-01')
sys.path.insert(0,str(DRIVER))
import windows_powershell


def digest(raw):return hashlib.sha256(raw).hexdigest()


def preserved():
    result={}
    for name,anchor,count in (
        ('source','3434a394284e919ece57a6217b3affbb7ee97d9989545a6888ed1eb9c6b43991',222),
        ('supplement-01','514500493d4b5a244ed3b13b11af0b889b4d004bfb17bbb93fd0d2046a9a8e08',9)):
        root=ROOT.parent/name;raw=(root/'MANIFEST.json').read_bytes()
        if digest(raw)!=anchor:raise ValueError('Immutable manifest changed: '+name)
        manifest=json.loads(raw);seal=json.loads((root/'SEAL.json').read_bytes())
        if seal['manifestSHA256']!=anchor or seal['immutable'] is not True:raise ValueError('Seal mismatch')
        entries=manifest['entries']
        if len(entries)!=count:raise ValueError('Entry count')
        for entry in entries:
            relative=pathlib.PurePosixPath(entry['snapshotRelativePath'].replace('\\','/'))
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('Snapshot path')
            path=root.joinpath(*relative.parts);data=path.read_bytes()
            if len(data)!=entry['length'] or digest(data)!=entry['sha256']:raise ValueError('Snapshot entry changed: '+str(relative))
            if os.name=='nt' and not path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY:
                raise ValueError('Snapshot entry no longer readonly: '+str(relative))
        bound={}
        for key,filename in [('preservationSHA256','PRESERVATION.json'),('notesSHA256','NOTES.md')]:
            if key in manifest:
                if digest((root/filename).read_bytes())!=manifest[key]:raise ValueError('Bound supplement changed')
                bound[filename]=manifest[key]
        result[name]=dict(manifestSHA256=anchor,entries=count,bound=bound)
    return result


def sealed():
    """True when both sealed snapshots exist; a Git checkout has neither."""
    present=[(ROOT.parent/name).is_dir() for name in SNAPSHOTS]
    if any(present) and not all(present):raise ValueError('Only part of the sealed snapshots is present')
    return all(present)


def main():
    output=ROOT/'validation'/('run-'+uuid.uuid4().hex)
    output.mkdir(parents=True)
    full=sealed()
    result=dict(preservation=preserved() if full else None,checks=[],skipped=[])
    if not full:
        result['skipped']=['sealed snapshot verification (../source, ../supplement-01 absent)',
                           'test_rpc_regression.py (requires the sealed source snapshot)']
    sources=sorted((ROOT/'runtime').glob('*/*.py'))
    for path in sources:ast.parse(path.read_bytes(),filename=str(path))
    result['pythonSyntaxFiles']=len(sources)
    commands=[]
    for optimize in (False,True):
        names=['test_admin_recovery.py','test_admin_handoff.py','test_windows_powershell.py']
        if full:names.append('test_rpc_regression.py')
        for name in names:
            commands.append((name+('-optimized' if optimize else ''),
                [sys.executable,'-B',*(['-O'] if optimize else []),str(DRIVER/name)],None))
        commands.append(('test_dispose_held_run.py'+('-optimized' if optimize else ''),
            [sys.executable,'-B',*(['-O'] if optimize else []),str(ROOT/'runtime/host/test_dispose_held_run.py')],None))
        commands.append(('test_configure_lab.py'+('-optimized' if optimize else ''),
            [sys.executable,'-B',*(['-O'] if optimize else []),str(ROOT/'test_configure_lab.py')],None))
    pwsh=shutil.which('pwsh')
    if not pwsh:raise RuntimeError('Required inert test interpreter absent: pwsh')
    # Windows PowerShell 5.1 gets the fixed machine module path; PowerShell 7 its own default.
    for shell,executable,environment in (
            ('powershell',str(windows_powershell.executable()),windows_powershell.environment()),
            ('pwsh',pwsh,windows_powershell.pwsh_environment())):
        commands.append((shell+'-resident',[executable,'-NoProfile','-NonInteractive',
            *(['-ExecutionPolicy','Bypass'] if shell=='powershell' else []),
            '-File',str(DRIVER/'test-resident-admin.ps1')],environment))
        commands.append((shell+'-resident-strict',[executable,'-NoProfile','-NonInteractive',
            *(['-ExecutionPolicy','Bypass'] if shell=='powershell' else []),
            '-File',str(DRIVER/'test-resident-strict.ps1')],environment))
    # Parser only: none of the operational scripts is invoked or dot-sourced.
    parser="$ErrorActionPreference='Stop'; $count=0; Get-ChildItem -LiteralPath 'runtime' -Recurse -Filter '*.ps1' | ForEach-Object { $tokens=$null; $errors=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors); if($errors.Count){throw ($errors|Out-String)}; $count++ }; Write-Output ('Parsed '+$count+' PowerShell files')"
    commands.append(('powershell-syntax',[str(windows_powershell.executable()),'-NoProfile','-NonInteractive',
        '-Command',parser],windows_powershell.environment()))
    for name,command,environment in commands:
        completed=subprocess.run(command,cwd=ROOT,stdin=subprocess.DEVNULL,env=environment,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        log=output/(name+'.log');log.write_bytes(completed.stdout)
        result['checks'].append(dict(name=name,exitCode=completed.returncode,
            log=log.relative_to(ROOT).as_posix(),sha256=digest(completed.stdout)))
        print(name,completed.returncode,flush=True)
    result['preservationAfter']=preserved() if full else None
    ok=all(item['exitCode']==0 for item in result['checks'])
    # A run without the sealed snapshots is never reported as passed.
    result['status']='failed' if not ok else ('passed' if full else 'partial')
    result['passed']=result['status']=='passed'
    (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    for item in result['skipped']:print('SKIPPED:',item,flush=True)
    print('STATUS:',result['status'],flush=True)
    print(output,flush=True)
    return 1 if result['status']=='failed' else 0


if __name__=='__main__':raise SystemExit(main())
