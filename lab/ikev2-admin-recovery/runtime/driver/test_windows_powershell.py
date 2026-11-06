"""Windows PowerShell 5.1 child environments: live module resolution and call-site inventory."""
import ast
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import windows_powershell as wp  # noqa: E402

RUNTIME = HERE.parent
CANDIDATE = RUNTIME.parent

SPAWNERS = {'run', 'Popen', 'popen', 'runner', 'check_output', 'check_call', 'call', 'observe'}
HELPERS = {'environment', 'pwsh_environment', '_stock_child_environment', 'powershell_environment',
           '_powershell_environment', 'child_environment'}
PS_NAMES = {'POWERSHELL', 'PS', 'PWSH'}
PS_TEXT = re.compile(r'(?i)(^|[\\/])(powershell|pwsh)(\.exe)?$')

# Every direct local PowerShell spawn, by file and enclosing function.
EXPECTED_DIRECT = {
    'check_offline.py': set(),
    'runtime/driver/barrier.py': {'<module>'},
    'runtime/driver/collect.py': {'<module>'},
    'runtime/driver/hash-context.py': {'<module>'},
    'runtime/driver/protected_transport.py': {'PSDirectRPC._invoke', 'Adapter._ps'},
    'runtime/driver/resident_rpc.py': {'ResidentRPC.__init__'},
    'runtime/driver/stock_controller.py': {'operational_controller'},
    'runtime/driver/test-expected-entry.py': {'run'},
    'runtime/driver/test-file-sha256.py': {'case'},
    'runtime/driver/test_admin_recovery.py': {'Tests.test_every_local_child_image_is_absolute',
        'PrivateRootNameTests.test_driver_scripts_with_cp_root_hermetic'},
    'runtime/driver/test_preparation_early.py': {'EarlyPreparation.start_host'},
    'runtime/driver/test_rejected_launch.py': {'Bridge.__init__'},
    'runtime/host/dispose-held-run.py': {'LiveEffects._powershell', 'read_sddl'},
    'runtime/host/test_dispose_held_run.py': {
        'DisposeTests.test_guest_remove_checks_parent_reparse_chain',
        'DisposeTests.test_helper_refuses_bad_nonce_or_driver_before_any_session'},
}
# The positive control deliberately starts powershell.exe with a polluted inherited environment.
EXEMPT = {('runtime/driver/test_windows_powershell.py', 'LiveModuleResolution.invoke')}
# Generic spawners that receive a PowerShell argv from their callers; each must pass env=.
GENERIC = {
    ('check_offline.py', 'main'),
    ('runtime/driver/cancellation.py', 'Transport.__init__'),
    ('runtime/driver/readiness_diagnostics.py', 'owned_query'),
    ('runtime/driver/admin_processes.py', 'OriginalProcesses.__call__'),
    ('runtime/driver/supervise.py', 'invoke'),
    ('runtime/driver/transport.py', 'Transport.observe'),
}


def _name(node):
    if isinstance(node, ast.Attribute):
        return node.attr
    return getattr(node, 'id', None)


class Scope:
    def __init__(self, qualname, body, parent=None):
        self.qualname, self.parent = qualname, parent
        self.nodes = []
        stack = [n for n in body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        while stack:
            node = stack.pop()
            self.nodes.append(node)
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    stack.append(child)
        self.assigned = {}
        for node in self.nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assigned.setdefault(target.id, []).append(node.value)

    def values(self, name):
        scope = self
        while scope is not None:
            if name in scope.assigned:
                return scope.assigned[name]
            scope = scope.parent
        return []


def scopes(tree):
    module = Scope('<module>', tree.body)
    found = [module]

    def visit(body, prefix):
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + '.')
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append(Scope(prefix + node.name, node.body, module))
                visit(node.body, prefix + node.name + '.')
    visit(tree.body, '')
    return found


def ps_ref(expr, scope, seen=None):
    seen = set() if seen is None else seen
    for node in ast.walk(expr):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and PS_TEXT.search(node.value):
            return True
        if isinstance(node, (ast.Name, ast.Attribute)) and _name(node) in PS_NAMES:
            return True
        if isinstance(node, ast.Call) and _name(node.func) == 'executable' and isinstance(node.func, ast.Attribute):
            return True
        if isinstance(node, ast.Name) and node.id not in seen:
            seen.add(node.id)
            if any(ps_ref(value, scope, seen) for value in scope.values(node.id)):
                return True
    return False


def argv_head(expr, scope, seen=None):
    seen = set() if seen is None else seen
    if isinstance(expr, (ast.List, ast.Tuple)):
        return expr.elts[0] if expr.elts and not isinstance(expr.elts[0], ast.Starred) else None
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return argv_head(expr.left, scope, seen)
    if isinstance(expr, ast.Call) and _name(expr.func) == 'list' and expr.args:
        return argv_head(expr.args[0], scope, seen)
    if isinstance(expr, ast.Name) and expr.id not in seen:
        seen.add(expr.id)
        for value in scope.values(expr.id):
            head = argv_head(value, scope, seen)
            if head is not None:
                return head
    return None


def has_helper(expr, scope, seen=None):
    seen = set() if seen is None else seen
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and _name(node.func) in HELPERS:
            return True
        if isinstance(node, ast.Name) and node.id not in seen:
            seen.add(node.id)
            if any(has_helper(value, scope, seen) for value in scope.values(node.id)):
                return True
    return False


def inventory(source, filename='<source>'):
    """Return (direct, generic, offenders) for one Python source."""
    direct, spawns, offenders = set(), {}, []
    for scope in scopes(ast.parse(source, filename=filename)):
        for node in scope.nodes:
            if not (isinstance(node, ast.Call) and _name(node.func) in SPAWNERS and node.args):
                continue
            env = next((k.value for k in node.keywords if k.arg == 'env'), None)
            spawns.setdefault(scope.qualname, []).append(env)
            head = argv_head(node.args[0], scope)
            if head is None or not ps_ref(head, scope):
                continue
            direct.add(scope.qualname)
            if env is None or (isinstance(env, ast.Constant) and env.value is None) or not has_helper(env, scope):
                offenders.append('%s:%d %s' % (filename, node.lineno, scope.qualname))
    return direct, spawns, offenders


class LiveModuleResolution(unittest.TestCase):
    """Non-stubbed: a real powershell.exe child under a polluted parent PSModulePath."""

    def setUp(self):
        if os.name != 'nt':
            self.skipTest('Windows only')
        self.temporary = tempfile.TemporaryDirectory()
        self.fake = pathlib.Path(self.temporary.name) / 'Modules'
        module = self.fake / 'Microsoft.PowerShell.Security'
        module.mkdir(parents=True)
        (module / 'Microsoft.PowerShell.Security.psm1').write_text(
            "function Get-Acl { 'FAKE-GET-ACL' }\nExport-ModuleMember -Function Get-Acl\n", encoding='utf-8')
        (module / 'Microsoft.PowerShell.Security.psd1').write_text(
            "@{ ModuleVersion='99.0.0.0'; GUID='a94c8c7e-9810-47c0-b8af-65089c13a35a';"
            " RootModule='Microsoft.PowerShell.Security.psm1'; FunctionsToExport=@('Get-Acl');"
            " CmdletsToExport=@(); AliasesToExport=@(); VariablesToExport=@() }\n", encoding='utf-8')
        polluted = [str(self.fake)]
        ps7 = pathlib.Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'PowerShell/7/Modules'
        if ps7.is_dir():
            polluted.append(str(ps7))  # the live failure: PowerShell 7 module roots first
        self.polluted = os.pathsep.join(polluted)
        self.addCleanup(self.temporary.cleanup)

    def invoke(self, env):
        script = ("$ErrorActionPreference='Stop';$a=Get-Acl -LiteralPath $env:SystemRoot;"
                  "$c=Get-Command Get-Acl;"
                  "[Console]::Out.Write([string]$c.Module.ModuleBase+'|'+[string]$a)")
        completed = subprocess.run([str(wp.executable()), '-NoProfile', '-NonInteractive', '-Command', script],
                                   stdin=subprocess.DEVNULL, capture_output=True, timeout=120, env=env,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        return completed.returncode, completed.stdout.decode('utf-8', 'replace').strip(), completed.stderr

    def test_polluted_parent_resolves_fake_module_without_helper(self):
        """Positive control: the pollution is effective when the environment is inherited."""
        with patch.dict(os.environ, {'PSModulePath': self.polluted}):
            code, out, err = self.invoke(dict(os.environ))
        # Either the fake module shadows Get-Acl, or autoload fails exactly as observed live.
        self.assertTrue('FAKE-GET-ACL' in out or (code != 0 and b'CouldNotAutoloadMatchingModule' in err),
                        (code, out, err))

    def test_helper_loads_system_security_module(self):
        with patch.dict(os.environ, {'PSModulePath': self.polluted, 'POWERSHELL_DISTRIBUTION_CHANNEL': 'MSI:test'}):
            env = wp.environment()
            code, out, err = self.invoke(env)
        self.assertEqual(code, 0, err.decode('utf-8', 'replace'))
        base, _, acl = out.partition('|')
        # Windows PowerShell 5.1 reports $PSHOME as the base of its core Security module.
        home = wp.windows_home().resolve()
        self.assertIn(pathlib.Path(base).resolve(), (home, home / 'Modules' / 'Microsoft.PowerShell.Security'))
        self.assertEqual(acl, 'System.Security.AccessControl.DirectorySecurity')
        self.assertNotIn('FAKE-GET-ACL', out)
        self.assertEqual(env['PSModulePath'], os.pathsep.join(map(str, wp.module_roots())))
        self.assertNotIn('POWERSHELL_DISTRIBUTION_CHANNEL', env)


class EnvironmentShape(unittest.TestCase):
    def setUp(self):
        if os.name != 'nt':
            self.skipTest('Windows only')

    def test_inherited_module_path_replaced_case_insensitively(self):
        base = {'psmodulepath': 'X', 'POWERSHELL_DISTRIBUTION_CHANNEL': 'Y', 'KEEP': '1'}
        env = wp.environment(base=base, EXTRA='2')
        self.assertEqual([k for k in env if k.upper() == 'PSMODULEPATH'], ['PSModulePath'])
        roots = env['PSModulePath'].split(os.pathsep)
        self.assertEqual(roots, [str(r) for r in wp.module_roots()])
        self.assertFalse(any('Documents' in r for r in roots))
        self.assertEqual((env['KEEP'], env['EXTRA']), ('1', '2'))
        self.assertEqual(base['psmodulepath'], 'X')

    def test_pwsh_environment_drops_inherited_module_path(self):
        env = wp.pwsh_environment(base={'PSModulePath': 'X', 'KEEP': '1'})
        self.assertEqual(env, {'KEEP': '1'})

    def test_only_the_system_windows_powershell_image(self):
        for image in (sys.executable, r'C:\Program Files\PowerShell\7\pwsh.exe', 'powershell.exe'):
            with self.subTest(image=image), self.assertRaises(wp.PowerShellEnvironmentError):
                wp.environment(image)

    def test_stock_wrapper_maps_to_hold(self):
        import stock_controller
        with self.assertRaises(stock_controller.Hold):
            stock_controller._stock_child_environment(pathlib.Path(sys.executable))
        self.assertEqual(stock_controller._stock_child_environment(wp.executable())['PSModulePath'],
                         wp.environment()['PSModulePath'])


class CallSiteInventory(unittest.TestCase):
    """Static: every powershell.exe/pwsh subprocess passes an environment from the helper."""

    def files(self):
        paths = sorted(RUNTIME.glob('*/*.py')) + [CANDIDATE / 'check_offline.py']
        return {path.relative_to(CANDIDATE).as_posix(): path.read_text(encoding='utf-8') for path in paths}

    def test_every_powershell_spawn_uses_helper(self):
        found, offenders, generic = {}, [], set()
        for name, source in self.files().items():
            direct, spawns, bad = inventory(source, name)
            direct -= {q for f, q in EXEMPT if f == name}
            offenders += [o for o in bad if (name, o.split()[-1]) not in EXEMPT]
            if direct:
                found[name] = direct
            for qualname in spawns:
                if (name, qualname) in GENERIC:
                    generic.add((name, qualname))
                    for env in spawns[qualname]:
                        if env is None or (isinstance(env, ast.Constant) and env.value is None):
                            offenders.append('%s %s: generic spawner without env=' % (name, qualname))
        self.assertEqual(offenders, [])
        self.assertEqual(found, {k: v for k, v in EXPECTED_DIRECT.items() if v})
        self.assertEqual(generic, GENERIC)

    def test_scanner_controls(self):
        bad = ("import subprocess\nPOWERSHELL=r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'\n"
               "def f():\n subprocess.run([POWERSHELL,'-Command','x'])\n"
               "def g():\n cmd=['pwsh.exe','-c','x']\n subprocess.Popen(cmd,env=dict(KEY='1'))\n"
               "def h(exe):\n subprocess.run([exe])\n")
        direct, _, offenders = inventory(bad)
        self.assertEqual(direct, {'f', 'g'})
        self.assertEqual([o.split()[-1] for o in offenders], ['f', 'g'])
        good = ("import subprocess,windows_powershell\n"
                "def f():\n env=windows_powershell.environment()\n"
                " subprocess.run([r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'],env=env)\n")
        self.assertEqual(inventory(good)[2], [])


if __name__ == '__main__':
    unittest.main()
