"""Deterministic child environments for local PowerShell processes.

Every local child that runs Windows PowerShell 5.1 (``powershell.exe``) must be
started with ``environment(executable)``. A parent launched from PowerShell 7
exports a ``PSModulePath`` that lists PowerShell 7 module roots first; Windows
PowerShell 5.1 then autoloads the PowerShell 7 ``Microsoft.PowerShell.Security``
and ``Microsoft.PowerShell.Management`` modules and core cmdlets such as
``Get-Acl`` fail. The returned environment pins ``PSModulePath`` to exactly the
machine Windows PowerShell roots:

* ``%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\Modules``
* ``%ProgramFiles%\\WindowsPowerShell\\Modules``

The per-user ``Documents\\WindowsPowerShell\\Modules`` root is deliberately not
listed: it is user-writable, roams with the profile and would make module
resolution depend on the invoking account. (Windows PowerShell 5.1 may still
append it at startup; the machine roots stay first, so core modules always
resolve from the system directory.)

A child that intentionally runs PowerShell 7 (``pwsh.exe``) uses
``pwsh_environment()`` instead, which removes the inherited ``PSModulePath`` so
PowerShell 7 computes its own default.

Importing this module performs no I/O.
"""
import os
import pathlib

# Variables owned by the parent PowerShell host that must not leak into a child.
# PSExecutionPolicyPreference is intentionally retained: it is honoured by both
# editions and some callers rely on the inherited process scope.
_DROPPED = ('PSMODULEPATH', 'POWERSHELL_DISTRIBUTION_CHANNEL')
_CORE_MODULES = ('Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility',
                 'Microsoft.PowerShell.Management')
_REPARSE = 0x400


class PowerShellEnvironmentError(RuntimeError):
    pass


def _reject_reparse(path):
    """Check lexical components without following aliases before resolving/using."""
    path = pathlib.Path(path)
    if not path.is_absolute():
        raise PowerShellEnvironmentError('Stock path must be absolute')
    for part in (*reversed(path.parents), path):
        try:
            attributes = part.lstat().st_file_attributes
        except OSError:
            raise PowerShellEnvironmentError('Windows PowerShell path unavailable') from None
        if attributes & _REPARSE:
            raise PowerShellEnvironmentError('Reparse Windows PowerShell path')


def windows_home():
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer)):
        raise PowerShellEnvironmentError('Windows directory unavailable')
    return pathlib.Path(buffer.value) / 'System32/WindowsPowerShell/v1.0'


def executable():
    """The only supported Windows PowerShell 5.1 image."""
    return windows_home() / 'powershell.exe'


def module_roots():
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r'SOFTWARE\Microsoft\Windows\CurrentVersion', 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        program_files = pathlib.Path(winreg.QueryValueEx(key, 'ProgramFilesDir')[0])
    return (windows_home() / 'Modules', program_files / 'WindowsPowerShell/Modules')


def _clean(base):
    child = dict(os.environ if base is None else base)
    for key in list(child):
        if key.upper() in _DROPPED:
            del child[key]
    return child


def environment(image=None, base=None, **extra):
    """Validated environment for a Windows PowerShell 5.1 child process."""
    expected = executable()
    image = expected if image is None else pathlib.Path(image)
    _reject_reparse(image)
    _reject_reparse(expected)
    if image.resolve() != expected.resolve() or not expected.is_file():
        raise PowerShellEnvironmentError('Unsupported stock PowerShell executable')
    roots = module_roots()
    for root in roots:
        _reject_reparse(root)
        if not root.is_absolute() or not root.is_dir():
            raise PowerShellEnvironmentError('Windows PowerShell module root unavailable')
    for name in _CORE_MODULES:
        manifest = roots[0] / name / (name + '.psd1')
        _reject_reparse(manifest)
        if not manifest.is_file() or manifest.resolve().parent.parent != roots[0].resolve():
            raise PowerShellEnvironmentError('Windows PowerShell core module unavailable')
        raw = manifest.read_bytes()
        if any('Security.types.ps1xml'.encode(encoding) in raw
               for encoding in ('ascii', 'utf-16-le', 'utf-16-be')):
            raise PowerShellEnvironmentError('Incompatible Windows PowerShell Security module')
    child = _clean(base)
    child['PSModulePath'] = os.pathsep.join(map(str, roots))
    child.update(extra)
    return child


def pwsh_environment(base=None, **extra):
    """Environment for an intentional PowerShell 7 child: no inherited module path."""
    child = _clean(base)
    child.update(extra)
    return child
