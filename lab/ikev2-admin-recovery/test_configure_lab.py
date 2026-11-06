"""Inert tests for configure_lab.py: files only, no lab, VM, or network access."""
import json
import pathlib
import tempfile
import unittest

import configure_lab as lab

HERE = pathlib.Path(__file__).resolve().parent
EXAMPLE = HERE / 'lab-config.example.json'


class ConfigureLabTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.base = pathlib.Path(self.temporary.name)

    def config(self, **changes):
        value = json.loads(EXAMPLE.read_bytes()); value.update(changes)
        path = self.base / ('config-%d.json' % len(list(self.base.glob('config-*.json'))))
        path.write_text(json.dumps(value), encoding='utf-8')
        return path

    def test_example_loads(self):
        values = lab.load(EXAMPLE)
        self.assertEqual(set(values), {('<%s>' % key).encode() for key in (*lab.KEYS, *lab.DERIVED)})
        self.assertEqual(values[b'<LAB_PUBLIC_IP>'], b'203.0.113.10')
        self.assertEqual(values[b'<LAB_VM_NIC_ID>'], b'00000000-0000-4000-8000-0000000000A1')
        self.assertEqual(values[b'<LAB_VSWITCH_ID>'], b'00000000-0000-4000-8000-000000000002')

    def test_derived_spellings(self):
        values = lab.load(self.config(LAB_GUEST_NAME='LAB-PC7', LAB_VM_ID='0a1b2c3d-0000-4000-8000-00000000abcd',
                                      LAB_GUEST_MAC='0a:1b:2c:3d:4e:5f'))
        self.assertEqual(values[b'<LAB_GUEST_NAME_LOWER>'], b'lab-pc7')
        self.assertEqual(values[b'<LAB_VM_ID_UPPER>'], b'0A1B2C3D-0000-4000-8000-00000000ABCD')
        self.assertEqual(values[b'<LAB_VM_ID_PREFIX>'], b'0a1b2c3d')
        self.assertEqual(values[b'<LAB_GUEST_MAC_HEX>'], b'0A1B2C3D4E5F')

    def test_refuses_invalid_config(self):
        cases = [dict(LAB_PUBLIC_IP='081.163.0.1'), dict(LAB_PUBLIC_IP='2001:db8::1'),
                 dict(LAB_PUBLIC_IP='lab'), dict(LAB_PRIVATE_ROOT='relative\\root'),
                 dict(LAB_PRIVATE_ROOT='C:\\root\\'), dict(LAB_STEP9_ABI_ROOT="C:/it's"),
                 dict(LAB_STEP9_ABI_ROOT='C:/$env:TEMP'), dict(LAB_USER_PROFILE='C:\\a\nb'),
                 dict(LAB_USER_PROFILE=''), dict(LAB_USER_PROFILE=1), dict(schema='other'), dict(extra='x'),
                 dict(schema='bimeron-lab-config-v1'), dict(LAB_GUEST_NAME='lab-guest'),
                 dict(LAB_GUEST_NAME='LAB-GUEST-NAME-TOO-LONG'), dict(LAB_GUEST_NAME='-LAB'),
                 dict(LAB_GUEST_NAME='1234'), dict(LAB_GUEST_NAME='WRONG-GUEST'), dict(LAB_GUEST_NAME='LAB GUEST'),
                 dict(LAB_GUEST_SID_1001='S-1-5-21-1-2-3-1002'), dict(LAB_GUEST_SID_1002='S-1-5-21-9-2-3-1002'),
                 dict(LAB_GUEST_SID_1001='S-1-5-21-1000000001-1000000002-4294967296-1001'),
                 dict(LAB_GUEST_SID_1001='S-1-5-32-544'), dict(LAB_VM_ID='00000000-0000-4000-8000-00000000000A'),
                 dict(LAB_VM_ID='{00000000-0000-4000-8000-000000000001}'), dict(LAB_GUEST_MAC='00-15-5d-00-00-01'),
                 dict(LAB_GUEST_MAC='00155d000001'), dict(LAB_GUEST_MAC='00:15:5D:00:00:01'),
                 dict(schema='bimeron-lab-config-v2'), dict(LAB_VM_NIC_ID='00000000-0000-4000-8000-0000000000a1'),
                 dict(LAB_VM_NIC_ID='{00000000-0000-4000-8000-0000000000A1}'), dict(LAB_VM_NIC_ID=''),
                 dict(LAB_VSWITCH_ID='00000000-0000-4000-8000-00000000000A'),
                 dict(LAB_VSWITCH_ID='00000000000040008000000000000002')]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError): lab.load(self.config(**case))
        for key in ('LAB_PUBLIC_IP', 'LAB_VM_NIC_ID', 'LAB_VSWITCH_ID'):
            missing = json.loads(EXAMPLE.read_bytes()); del missing[key]
            (self.base / 'missing.json').write_text(json.dumps(missing), encoding='utf-8')
            with self.subTest(missing=key), self.assertRaises(ValueError): lab.load(self.base / 'missing.json')
        duplicate = EXAMPLE.read_bytes().replace(b'{', b'{"schema":"%s",' % lab.SCHEMA.encode(), 1)
        (self.base / 'duplicate.json').write_bytes(duplicate)
        with self.assertRaisesRegex(ValueError, 'Duplicate'): lab.load(self.base / 'duplicate.json')

    def test_render_is_byte_exact(self):
        root = self.base / 'pkg'; (root / 'runtime').mkdir(parents=True); (root / 'validation').mkdir()
        (root / 'runtime' / 'a.ps1').write_bytes(b"$p='<LAB_PUBLIC_IP>'\r\n$q=\"<LAB_STEP9_ABI_ROOT>/x\"\r\n")
        (root / 'README.md').write_bytes(b'`<LAB_PUBLIC_IP>` stays\n')
        (root / 'validation' / 'run.log').write_bytes(b'<LAB_UNKNOWN>')
        (root / 'lab-config.json').write_bytes(b'private')
        values = {b'<LAB_PUBLIC_IP>': b'192.0.2.9', b'<LAB_STEP9_ABI_ROOT>': b'C:/s'}
        self.assertEqual(lab.render(values, self.base / 'out', root), 2)
        self.assertEqual((self.base / 'out/runtime/a.ps1').read_bytes(), b"$p='192.0.2.9'\r\n$q=\"C:/s/x\"\r\n")
        self.assertEqual((self.base / 'out/README.md').read_bytes(), b'`<LAB_PUBLIC_IP>` stays\n')
        self.assertFalse((self.base / 'out/validation').exists())
        self.assertFalse((self.base / 'out/lab-config.json').exists())
        with self.assertRaises(FileExistsError): lab.render(values, self.base / 'out', root)
        with self.assertRaisesRegex(ValueError, 'outside'): lab.render(values, root / 'nested', root)
        (root / 'runtime' / 'b.py').write_bytes(b"x='<LAB_UNKNOWN>'")
        with self.assertRaisesRegex(ValueError, 'LAB_UNKNOWN'): lab.render(values, self.base / 'out2', root)

    def test_package_renders_completely_with_example(self):
        out = self.base / 'rendered'
        lab.render(lab.load(EXAMPLE), out)
        probe = (out / 'runtime/driver/probe.ps1').read_bytes()
        self.assertIn(b'203.0.113.10', probe); self.assertNotIn(b'<LAB_', probe)
        receipt = (out / 'runtime/driver/stock_receipt.py').read_bytes()
        self.assertIn(b'00000000-0000-4000-8000-0000000000A1', receipt)
        self.assertIn(b'00000000-0000-4000-8000-000000000002', receipt)
        for path in out.rglob('*'):
            relative = path.relative_to(out).as_posix()
            if path.is_file() and relative not in lab.VERBATIM:
                self.assertIsNone(lab.TOKEN.search(path.read_bytes()), relative)


if __name__ == '__main__': unittest.main()
