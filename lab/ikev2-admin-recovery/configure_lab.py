"""Render a configured copy of this lab package; never operates the lab.

The published snapshot keeps lab-specific values as <LAB_*> placeholders.
This tool copies the package into a new directory outside the package and
replaces each placeholder with the value from a lab configuration file, or
with a spelling derived from one value (see DERIVED). Substitution is
byte-exact; no other byte changes.

Configuration: --config, else the BIMERON_LAB_CONFIG environment variable,
else lab-config.json beside this file (ignored by Git). See
lab-config.example.json for the schema.
"""
import argparse
import fnmatch
import ipaddress
import json
import os
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent
SCHEMA = 'bimeron-lab-config-v3'
PATH_KEYS = ('LAB_USER_PROFILE', 'LAB_PRIVATE_ROOT', 'LAB_STEP9_ABI_ROOT')
VM_KEYS = ('LAB_GUEST_NAME', 'LAB_GUEST_SID_1001', 'LAB_GUEST_SID_1002', 'LAB_VM_ID', 'LAB_GUEST_MAC',
           'LAB_VM_NIC_ID', 'LAB_VSWITCH_ID')
KEYS = ('LAB_PUBLIC_IP', *PATH_KEYS, *VM_KEYS)
# Placeholders derived from one configured value, in the spelling the files use.
DERIVED = {
    'LAB_GUEST_NAME_LOWER': lambda c: c['LAB_GUEST_NAME'].lower(),
    'LAB_VM_ID_UPPER': lambda c: c['LAB_VM_ID'].upper(),
    'LAB_VM_ID_PREFIX': lambda c: c['LAB_VM_ID'][:8],
    'LAB_GUEST_MAC_HEX': lambda c: c['LAB_GUEST_MAC'].replace(':', '').upper(),
}
# Upper-case NetBIOS computer name; the harness tests reject its lower-case form.
GUEST_NAME = re.compile(r'(?=[A-Z0-9-]*[A-Z])[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?')
SID = re.compile(r'(S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10})-(100[12])')
VM_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
# Hyper-V reports network adapter IDs with an upper-case GUID suffix.
NIC_ID = re.compile(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}')
MAC = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')
TOKEN = re.compile(rb'<LAB_[A-Z0-9_]+>')
# Files that document or implement the placeholders are copied unchanged.
VERBATIM = {'README.md', 'configure_lab.py', 'test_configure_lab.py', 'lab-config.example.json'}
# Generated or private state (see .gitignore) is never copied.
IGNORED = ('__pycache__', 'validation', 'rpc-tests-*', 'test-temporary', '*.pcap', '*.log', 'lab-config.json')
# Values land inside Python and PowerShell string literals and Markdown.
UNSAFE = re.compile(r'[\x00-\x1f\x7f\'"`$<>|*?%;]')
WINDOWS_PATH = re.compile(r'[A-Za-z]:[\\/][^:]*[^\\/]')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate lab config key: ' + key)
        result[key] = value
    return result


def load(path):
    """Return {placeholder bytes: value bytes} from a strict lab config."""
    config = json.loads(pathlib.Path(path).read_bytes(), object_pairs_hook=_unique)
    if not isinstance(config, dict) or set(config) != {'schema', *KEYS} or config['schema'] != SCHEMA:
        raise ValueError('Lab config must contain exactly schema and ' + ', '.join(KEYS))
    for key in KEYS:
        value = config[key]
        if not isinstance(value, str) or not value or UNSAFE.search(value):
            raise ValueError('Unsafe or empty lab config value: ' + key)
    try: address = ipaddress.ip_address(config['LAB_PUBLIC_IP'])
    except ValueError: raise ValueError('LAB_PUBLIC_IP is not an IP address') from None
    if address.version != 4 or str(address) != config['LAB_PUBLIC_IP']:
        raise ValueError('LAB_PUBLIC_IP must be a canonical IPv4 address')
    for key in PATH_KEYS:
        if not WINDOWS_PATH.fullmatch(config[key]):
            raise ValueError('Lab config path must be absolute, without a trailing separator: ' + key)
    if not GUEST_NAME.fullmatch(config['LAB_GUEST_NAME']) or config['LAB_GUEST_NAME'] == 'WRONG-GUEST':
        raise ValueError('LAB_GUEST_NAME must be an upper-case computer name of at most 15 characters')
    domains = set()
    for key in ('LAB_GUEST_SID_1001', 'LAB_GUEST_SID_1002'):
        match = SID.fullmatch(config[key])
        if not match or match.group(2) != key[-4:] or any(int(part) > 0xFFFFFFFF for part in match.group(1).split('-')[4:]):
            raise ValueError(key + ' must be a local account SID ending in -' + key[-4:])
        domains.add(match.group(1))
    if len(domains) != 1:
        raise ValueError('LAB_GUEST_SID_1001 and LAB_GUEST_SID_1002 must share one machine domain')
    if not VM_ID.fullmatch(config['LAB_VM_ID']):
        raise ValueError('LAB_VM_ID must be a lower-case GUID')
    if not MAC.fullmatch(config['LAB_GUEST_MAC']):
        raise ValueError('LAB_GUEST_MAC must be a lower-case colon-separated MAC address')
    if not NIC_ID.fullmatch(config['LAB_VM_NIC_ID']):
        raise ValueError('LAB_VM_NIC_ID must be an upper-case GUID')
    if not VM_ID.fullmatch(config['LAB_VSWITCH_ID']):
        raise ValueError('LAB_VSWITCH_ID must be a lower-case GUID')
    values = {key: config[key] for key in KEYS}
    values.update({key: derive(config) for key, derive in DERIVED.items()})
    return {('<' + key + '>').encode(): value.encode() for key, value in values.items()}


def _ignored(relative):
    return any(fnmatch.fnmatch(part, pattern) for part in relative.parts for pattern in IGNORED)


def render(substitutions, out, root=ROOT):
    """Copy root into the new directory out, substituting every placeholder."""
    root = pathlib.Path(root).resolve(); out = pathlib.Path(out).resolve()
    if out == root or out.is_relative_to(root) or root.is_relative_to(out):
        raise ValueError('Output must be outside the package')
    out.mkdir(parents=True)
    count = 0
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if _ignored(relative): continue
        if path.is_symlink(): raise ValueError('Symbolic link in package: ' + relative.as_posix())
        target = out / relative
        if path.is_dir(): target.mkdir(); continue
        data = path.read_bytes()
        if relative.as_posix() not in VERBATIM:
            for token, value in substitutions.items(): data = data.replace(token, value)
            left = TOKEN.search(data)
            if left: raise ValueError('Unconfigured placeholder %s in %s' % (left.group().decode(), relative.as_posix()))
        with open(target, 'xb') as stream: stream.write(data)
        count += 1
    return count


def default_config():
    return pathlib.Path(os.environ.get('BIMERON_LAB_CONFIG') or ROOT / 'lab-config.json')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--config', type=pathlib.Path, default=None)
    parser.add_argument('--out', type=pathlib.Path, required=True, help='new directory outside the package')
    args = parser.parse_args(argv)
    count = render(load(args.config or default_config()), args.out)
    print('Rendered %d files into %s; no lab action performed.' % (count, args.out))
    return 0


if __name__ == '__main__': raise SystemExit(main())
