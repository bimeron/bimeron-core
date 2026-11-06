"""Branch-B administrative disposition of a held run (one operator use per run).

A held run cannot advance through its original endpoint. This tool disposes it
administratively in four ordered steps. The run (nonce, private root, retained
host processes and which effects the run itself already completed) is derived
from a read-only evidence copy bound to its MANIFEST.json; the operator confirms
it with --approve-nonce and --approve-plan (the planSHA256 printed by dry-run).

Every step runs at most once, needs the previous step proven, snapshots the host
network/VPN state before and after, and stops on the first failure or deviation.
Nothing is retried. A step whose effect the evidence proves complete runs a
read-only confirmation instead of the action; an effect that is only partly
visible in the evidence is refused (never completed or re-sent). The final
record is labelled "administratively disposed, not SETTLED", normalCleanup=false.

  B1  act:     deliver the original reserved seq 1 seal-no-launch (exact bytes),
               then seq 2 exit-supervisor, via protected-guest.ps1 -Operation
               final in a new PS Direct session; fresh guest readback.
               Unreserved-seal variant (no seal was ever reserved: no host
               command, empty guest mailbox, one supervisor whose
               supervisor-once proof equals the evidence): seq 1 and seq 2 are
               built by protected_transport.MailboxClient.command (the owner's
               own path) over the staged owner-transport/config.json and
               delivered the same way; the seal bytes must equal the bytes
               predicted at dry-run (planSHA256 covers the variant and digest).
      confirm: guest has no supervisor/task; owner-transport responses 1 and 2,
               their proofs and task-final.json in the private root equal the
               evidence; fresh guest readback.
  B2  act:     remove exactly C:/BimeronFull300/<nonce> and C:/BimeronStep10Probe/<nonce>.
      confirm: both directories absent.
  B3  act:     observer retirement through sink_contract.retirement_commands; archive.
      confirm: capture ExitCode 0, cleanup-confirmed and sink-exit receipts
               present, unit absent, nft/ethtool/ip equal to the baseline (read-only).
  B4  terminate exactly the listed host processes in role order
      (watcher, resident(s), task helper(s), owner), then the leftover scan.
      A transient owner child that is the owner's capture status monitor query
      (configured absolute ssh.exe, argv equal to host-supervisor-config query)
      is not listed; if still alive after the owner it is a verified
      descendant in the leftover scan. Any other unmarked child is refused.
      Identity: owner and watcher by journaled FILETIME; others by PID,
      creation time (microseconds), image and parent from the process tree,
      verified live on the termination handle (reported as identityBasis).

Usage (dry-run validates the evidence copy only and prints the plan):
  python -I dispose-held-run.py dry-run --evidence <evidence-dir>
  python -I dispose-held-run.py run --step B1 --evidence <dir> --private-root <held root>
         --work <new disposition dir> --approve-nonce <full nonce> --approve-plan <planSHA256>
"""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
DRIVER = HERE.parent / 'driver'
POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
SSH = r'C:\WINDOWS\System32\OpenSSH\ssh.exe'
LABEL = 'administratively disposed, not SETTLED'
STEPS = ('B1', 'B2', 'B3', 'B4')
# Termination order by role; the owner is always last.
ROLES = ('watcher', 'resident', 'task-helper', 'owner')
ROLE_MARKERS = (('pinned_watcher.py', 'watcher'), ('resident-main.ps1', 'resident'),
                ('prepare-task.ps1', 'task-helper'), ('preparation.py', 'owner'))
# Console hosts of the retained processes exit with them; never a listed target.
IGNORED_CHILDREN = ('conhost.exe',)
NETWORK_FIELDS = ('sid', 'adapters', 'adapterLinkSpeeds', 'routes', 'dns', 'vpnUser', 'vpnAllUsers')
# DNS on router-advertised IPv6 interfaces and adapter link speed change on their own: journaled, never compared.
STRICT_NETWORK_FIELDS = ('sid', 'adapters', 'routes', 'vpnUser', 'vpnAllUsers')
HEALTH_POLL_LIMIT = 30
HEALTH_POLL_SECONDS = 1.0
QUIESCENT = re.compile(r'resident-(request|reserved|response)-[0-9]{20}\.json')
REPARSE = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
PERSISTENT_POLICY = ('MachinePolicy', 'UserPolicy', 'CurrentUser', 'LocalMachine')
SERVICES = ('BFE', 'RasMan', 'IKEEXT', 'PolicyAgent')
# B1 act: files staged from the held private root (must equal the evidence).
PRIVATE_FILES = ('owner-transport/commands/00000001.json', 'owner-transport/config.json',
                 'owner-transport/task-registration.json', 'owner-transport/task-instance.json',
                 'host-supervisor-config.json')
# B1 confirm: the run's own completed seal/exit exchange (must equal the evidence).
B1_DONE_FILES = ('owner-transport/config.json', 'owner-transport/task-instance.json',
                 'owner-transport/commands/00000001.json', 'owner-transport/commands/00000002.json',
                 'owner-transport/responses/00000001.json', 'owner-transport/responses/00000002.json',
                 'owner-transport/proofs/no-launch.json', 'owner-transport/proofs/supervisor-exit-ready.json',
                 'owner-transport/task-final.json', 'host-supervisor-config.json')
# B1 act, unreserved-seal variant: staged from the held private root (must equal the evidence).
UNRESERVED_FILES = ('owner-transport/config.json', 'owner-transport/task-registration.json',
                    'owner-transport/task-instance.json', 'owner-transport/proofs/supervisor-once.json',
                    'host-supervisor-config.json')
SEAL_BUILDER = ('protected_transport.MailboxClient.command(seal-no-launch, {}) over owner-transport/config.json; '
                'protected-guest.ps1 -Operation final -Mode submit (Submit-OwnerCommand)')
MONITOR_TRANSPORT = re.compile(r'transport-[0-9]{6}\.json')
OBSERVER_DONE = ('observer/run-health.json', 'observer/run-cleanup-confirmed.json', 'observer/run-sink-exit.json')


class Refusal(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode('utf-8')


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise Refusal('Nonfinite JSON number')
    return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=pairs, parse_constant=invalid)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names), label + ' fields')


def driver_modules():
    """Pure driver helpers; import performs no external operation."""
    if str(DRIVER) not in sys.path:
        sys.path.insert(0, str(DRIVER))
    import sink_contract
    import live_prepare
    import admin_evidence
    return sink_contract, live_prepare, admin_evidence


def powershell_environment(**extra):
    """Environment for every local Windows PowerShell 5.1 child (fixed machine module roots)."""
    if str(DRIVER) not in sys.path:
        sys.path.insert(0, str(DRIVER))
    import windows_powershell
    try:
        return windows_powershell.environment(POWERSHELL, **extra)
    except windows_powershell.PowerShellEnvironmentError as error:
        raise Refusal(str(error)) from None


def filetime(iso):
    """UTC ISO-8601 with up to 7 fractional digits -> FILETIME (100 ns units)."""
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?Z', iso)
    require(match is not None, 'Creation time format')
    base = datetime.datetime.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    whole = (base - epoch) // datetime.timedelta(seconds=1)
    return whole * 10_000_000 + int((match.group(2) or '0').ljust(7, '0'))


def private_root_names(nonce):
    """Both private-root naming schemes: capture-prep-<nonce> (old) and cp-<16 hex> (new)."""
    return ('capture-prep-' + nonce, 'cp-' + nonce[:16])


class Evidence:
    """Read-only evidence copy; every consumed file is bound to MANIFEST.json."""

    def __init__(self, root):
        self.root = pathlib.Path(root).resolve()
        raw = (self.root / 'MANIFEST.json').read_bytes()
        self.manifestSHA256 = sha(raw)
        manifest = strict(raw)
        require(manifest.get('schema') == 'evidence-manifest-v1', 'Evidence manifest schema')
        self.nonce = manifest.get('run')
        require(type(self.nonce) is str and re.fullmatch('[a-f0-9]{64}', self.nonce) is not None,
                'Evidence run nonce')
        self.entries = {e['path']: e for e in manifest['files']}
        require(len(self.entries) == len(manifest['files']), 'Duplicate manifest path')

    def has(self, relative):
        return relative in self.entries

    def read(self, relative):
        entry = self.entries.get(relative)
        require(entry is not None, 'Evidence file not in manifest: ' + relative)
        raw = (self.root / pathlib.PurePosixPath(relative)).read_bytes()
        require(len(raw) == entry['size'] and sha(raw) == entry['sha256'], 'Evidence file changed: ' + relative)
        return raw

    def json(self, relative):
        return strict(self.read(relative))

    def listed(self, prefix):
        return sorted(p for p in self.entries if p.startswith(prefix))


PRIVATE = 'host/private-root/'


# A transient owner status query is tied to the owner's journaled queries by
# creation time: it is the exact journaled identity, or newer than every
# journaled query identity and created at most this long before the tree.
TRANSIENT_QUERY_WINDOW = 60 * 10_000_000  # FILETIME units (60 s)


def monitor_query_binding(evidence, nonce, owner, query):
    """The owner's own journaled capture status queries: argv exactly the configured query.

    Returns the matching record paths and the journaled spawn identities
    (pid, creationFileTime) of those queries that have one in evidence.
    """
    records = [p for p in evidence.listed(PRIVATE + 'transport-') if MONITOR_TRANSPORT.fullmatch(p[len(PRIVATE):])]
    matching, identities = [], []
    for path in records:
        value = evidence.json(path)
        if value.get('argv') != query:
            continue
        bound = value.get('binding') or {}
        require(bound.get('nonce') == nonce and type(bound.get('owner')) is dict and
                bound['owner'].get('pid') == owner['pid'] and
                str(bound['owner'].get('creationFileTime')) == str(owner['creationFileTime']),
                'Monitor query record not bound to the owner: ' + path)
        matching.append(path)
        number = path[len(PRIVATE) + len('transport-'):-len('.json')]
        identity = PRIVATE + 'original-transport-%s/transport-001-original.identity.json' % number
        if evidence.has(identity):
            value = evidence.json(identity)
            require(type(value.get('pid')) is int and type(value.get('creationFileTime')) is int,
                    'Monitor query identity shape: ' + identity)
            identities.append((value['pid'], value['creationFileTime']))
    require(matching, 'No owner capture status query in evidence')
    return matching, identities


def transient_monitor_query(p, query, owner_row, records, identities=(), tree_utc=None):
    """An unmarked owner ssh child that is a transient status query, or None.

    Name, image and command line (when readable) must be the configured query;
    the process is tied to the owner's journaled queries by creation time (see
    TRANSIENT_QUERY_WINDOW), never by PID alone.
    """
    if (p.get('name') or '').lower() != 'ssh.exe':
        return None
    exe, cmd = p.get('exe'), p.get('cmd')
    if exe is not None and os.path.normcase(exe) != os.path.normcase(SSH):
        return None
    if cmd is not None and cmd not in (subprocess.list2cmdline(query),
                                       '"%s" ' % query[0] + subprocess.list2cmdline(query[1:])):
        return None
    created = filetime(p['created'])
    require(created >= filetime(owner_row['created']), 'Monitor query older than owner: %d' % p['pid'])
    exact = [c for pid, c in identities if pid == p['pid'] and c // 10 == created // 10]
    if exact:
        createdBasis = 'journaled owner query identity (pid + creation time)'
    else:
        require(type(tree_utc) is str, 'Monitor query window needs the process tree time: %d' % p['pid'])
        collected = filetime(tree_utc)
        newest = max((c for _, c in identities), default=filetime(owner_row['created']))
        require(newest < created <= collected and collected - created <= TRANSIENT_QUERY_WINDOW,
                'Monitor query outside the owner query window: %d' % p['pid'])
        createdBasis = ('newer than every journaled owner query identity (%d) and created at most %d s '
                        'before the process tree' % (len(identities), TRANSIENT_QUERY_WINDOW // 10_000_000))
    return dict(pid=p['pid'], parent=p['parent'], image=SSH, createdMicro=created // 10,
                argvSHA256=sha(canonical_json(query)),
                imageBasis='process tree' if exe is not None else 'owner transport record argv[0] (tree image unreadable)',
                argvBasis='process tree' if cmd is not None else 'owner transport record argv (tree command line unreadable)',
                createdBasis=createdBasis,
                ownerRecords=len(records), lastOwnerRecord=records[-1][len(PRIVATE):],
                disposal='not terminated in B4 list; if alive after the owner, a verified descendant in the leftover scan')


def process_plan(evidence, nonce, query=None):
    """Retained host processes: the journaled owner and its direct run children, by role."""
    tree = evidence.json('host/process-tree.json')
    require(tree.get('schema') == 'host-process-tree-v1', 'Process tree schema')
    by_pid = {p['pid']: p for p in tree['processes']}
    require(len(by_pid) == len(tree['processes']), 'Duplicate PID in process tree')
    journals = {}
    for key, role in (('journalOwner', 'owner'), ('journalContainment', 'watcher')):
        j = tree.get(key)
        require(type(j) is dict and type(j.get('pid')) is int and
                re.fullmatch('[0-9]+', str(j.get('creationFileTime'))) is not None, 'Journal identity: ' + key)
        journals[role] = j
    created = PRIVATE + 'owner-created.json'
    if evidence.has(created):
        bound = evidence.json(created)['binding']
        require(bound.get('nonce') == nonce, 'Owner claim nonce')
        for role, key in (('owner', 'owner'), ('watcher', 'containmentOwner')):
            require(bound[key]['pid'] == journals[role]['pid'] and
                    str(bound[key]['creationFileTime']) == str(journals[role]['creationFileTime']),
                    'Owner claim / process tree identity: ' + role)
    owner_pid = journals['owner']['pid']
    require(owner_pid in by_pid, 'Owner absent from process tree')
    short = 'cp-' + nonce[:16]
    selected = [by_pid[owner_pid]] + [p for p in tree['processes'] if p['parent'] == owner_pid and
                                      p['pid'] != owner_pid and p['name'].lower() not in IGNORED_CHILDREN]
    identities, transient, records, query_identities = [], [], None, []
    for p in selected:
        roles = [role for marker, role in ROLE_MARKERS if marker in (p.get('cmd') or '')]
        if not roles and p['pid'] != owner_pid and query is not None and (p.get('name') or '').lower() == 'ssh.exe':
            if records is None:
                records, query_identities = monitor_query_binding(evidence, nonce, journals['owner'], query)
            monitor = transient_monitor_query(p, query, by_pid[owner_pid], records, query_identities,
                                              tree.get('utc'))
            if monitor is not None:
                transient.append(monitor)
                continue
        require(len(roles) == 1, 'Process role unknown or ambiguous: %d' % p['pid'])
        role = roles[0]
        require((role == 'owner') == (p['pid'] == owner_pid), 'Owner role/journal mismatch: %d' % p['pid'])
        if role != 'owner':
            require(nonce in p['cmd'] or short in p['cmd'], 'Process not bound to the run: %d' % p['pid'])
        require(pathlib.PureWindowsPath(p['exe']).is_absolute(), 'Process image path')
        micro = filetime(p['created']) // 10
        exact = None
        if role in journals:
            require(journals[role]['pid'] == p['pid'], 'Journal identity: %d' % p['pid'])
            exact = int(journals[role]['creationFileTime'])
            require(exact // 10 == micro, 'Journal/process-tree creation mismatch: %d' % p['pid'])
        identities.append(dict(role=role, pid=p['pid'], image=p['exe'], parent=p['parent'],
                               createdMicro=micro, creationFileTime=exact))
    watchers = [i for i in identities if i['role'] == 'watcher']
    require(len(watchers) == 1 and watchers[0]['pid'] == journals['watcher']['pid'], 'Exactly the journaled watcher')
    identities.sort(key=lambda i: (ROLES.index(i['role']), i['pid']))
    # The watcher argv names the private root it supervises.
    match = re.search(r'--config (\S+)\\host-supervisor-config\.json', by_pid[watchers[0]['pid']]['cmd'])
    root = match.group(1) if match else None
    require(root is None or pathlib.PureWindowsPath(root).name in private_root_names(nonce), 'Watcher private root name')
    # The owner runs one status query at a time.
    require(len(transient) <= 1, 'More than one transient monitor query')
    return identities, root, transient


def guest_dirs_absent(evidence, nonce):
    """True/False from the guest collection; None when the evidence does not say."""
    state = evidence.json('guest/guest-state.json')
    reported = state.get('dirsExist')
    if reported is None:
        present = any(p.startswith(('guest/BimeronFull300/' + nonce + '/', 'guest/BimeronStep10Probe/' + nonce + '/'))
                      for p in evidence.entries)
        return False if present else None
    values = {}
    for item in reported:
        path, _, flag = item.rpartition('=')
        values[path] = flag
    targets = ['C:/BimeronFull300/' + nonce, 'C:/BimeronStep10Probe/' + nonce]
    require(set(values) == set(targets) and all(values[t] in ('True', 'False') for t in targets),
            'Guest directory report')
    if all(values[t] == 'False' for t in targets):
        return True
    return False


def guest_clean(evidence, nonce):
    """Guest evidence: no run-bound process and no owner task."""
    state = evidence.json('guest/guest-state.json')
    bound = [p for p in state['processes'] if nonce in (p.get('cmd') or '') or
             (p.get('name') or '').lower() == 'full300-owner.exe']
    task = state.get('taskState')
    return not bound and state.get('ownerTasks', []) == [] and type(task) is str and task.startswith('ABSENT')


def validate_b1_act(evidence, nonce):
    """The held run's seal was reserved once, failed host-side and never reached the guest."""
    seal = evidence.read(PRIVATE + 'owner-transport/commands/00000001.json')
    config_raw = evidence.read(PRIVATE + 'owner-transport/config.json')
    command = strict(seal)
    fields(command, ('schema', 'nonce', 'configSHA256', 'seq', 'op', 'body'), 'Seal command')
    require(command['schema'] == 'full300-owner-command-v1' and command['nonce'] == nonce and
            command['configSHA256'] == sha(config_raw) and command['seq'] == 1 and
            command['op'] == 'seal-no-launch' and command['body'] == {}, 'Seal command binding')
    require(encode(command) == seal, 'Seal command bytes are not canonical')
    evidence.read(PRIVATE + 'owner-transport/task-registration.json')
    requests = evidence.listed(PRIVATE + 'guest-control/resident-request-')
    require(requests, 'Resident requests missing')
    seals = []
    for path in requests:
        value = evidence.json(path)
        if value.get('operation') == 'seal-no-launch' or value.get('requestSHA256') == sha(seal):
            seals.append((path, value))
    require(len(seals) == 1, 'Exactly one resident seal-no-launch request')
    path, value = seals[0]
    require(value['mode'] == 'submit' and value['requestSHA256'] == sha(seal) and
            value['path'].replace('\\', '/').endswith('/owner-transport/commands/00000001.json'),
            'Resident seal request binding')
    require(path == requests[-1], 'Seal-no-launch is not the last resident request')
    response = evidence.json(path.replace('resident-request-', 'resident-response-'))
    require(response.get('state') == 'Failed' and response.get('output') is None and
            response.get('sequence') == value['sequence'], 'Resident seal response must be Failed')
    guest = 'guest/BimeronFull300/' + nonce + '/transport/'
    require(not [p for p in evidence.entries if p.startswith((guest + 'commands/', guest + 'responses/'))]
            and guest + 'proofs/no-launch.json' not in evidence.entries, 'Guest mailbox not empty in evidence')
    state = evidence.json('guest/guest-state.json')
    listing = [e['path'].replace('/', '\\').lower() for e in state['remoteListing']]
    require(not [p for p in listing if '\\transport\\commands\\' in p or '\\transport\\responses\\' in p],
            'Guest listing shows delivered commands')
    require(state.get('taskState') == 'Running', 'Owner task not running in evidence')
    bound = [p for p in state['processes'] if nonce in (p.get('cmd') or '')]
    require(len(bound) == 1 and 'owner-supervisor.ps1' in bound[0]['cmd'], 'Exactly one guest supervisor in evidence')
    return dict(seal=seal, sealSHA256=sha(seal), supervisorPid=bound[0]['pid'],
                privateFiles={name: sha(evidence.read(PRIVATE + name)) for name in PRIVATE_FILES})


def seal_requests(evidence):
    """Resident requests/reservations naming a seal-no-launch (a reserved seal)."""
    found = []
    for kind in ('resident-request-', 'resident-reserved-'):
        for path in evidence.listed(PRIVATE + 'guest-control/' + kind):
            value = evidence.json(path)
            if value.get('operation') == 'seal-no-launch' or str(value.get('path', '')).replace(
                    '\\', '/').endswith('/owner-transport/commands/00000001.json'):
                found.append(path)
    return found


def predicted_command(nonce, config_raw, op, body):
    """The exact bytes the owner's MailboxClient.command(op, body) freezes as seq 1 (local temp only)."""
    import tempfile
    if str(DRIVER) not in sys.path:
        sys.path.insert(0, str(DRIVER))
    import protected_transport

    class Captured(Exception):
        pass
    captured = {}

    def rpc(mode, path):
        captured.update(mode=mode, name=pathlib.Path(path).name, raw=pathlib.Path(path).read_bytes())
        raise Captured()
    with tempfile.TemporaryDirectory() as temporary:
        client = protected_transport.MailboxClient(pathlib.Path(temporary) / 'ot', nonce, config_raw, rpc)
        try:
            client.command(op, body)
        except Captured:
            pass
    require(captured.get('mode') == 'submit' and captured.get('name') == '00000001.json', 'Seal prediction')
    return captured['raw']


def validate_b1_unreserved(evidence, nonce):
    """No seal was ever reserved: deliver a fresh seq 1 seal built by the owner's own code path."""
    ot = PRIVATE + 'owner-transport/'
    for name in ('commands/', 'responses/', 'receipts/'):
        require(not evidence.listed(ot + name), 'Host owner-transport %s not empty' % name.rstrip('/'))
    require(evidence.listed(ot + 'proofs/') == [ot + 'proofs/supervisor-once.json'],
            'Host owner-transport proofs other than supervisor-once.json')
    config_raw = evidence.read(ot + 'config.json')
    guest = 'guest/BimeronFull300/' + nonce + '/transport/'
    require(not [p for p in evidence.entries if p.startswith((guest + 'commands/', guest + 'responses/'))]
            and guest + 'proofs/no-launch.json' not in evidence.entries, 'Guest mailbox not empty in evidence')
    require(evidence.read(guest + 'config.json') == config_raw, 'Guest transport config differs from host')
    once_raw = evidence.read(ot + 'proofs/supervisor-once.json')
    require(evidence.read(guest + 'proofs/supervisor-once.json') == once_raw,
            'Guest supervisor-once.json differs from the host copy')
    once = strict(once_raw)
    require(once.get('schema') == 'full300-supervisor-once-v1' and once.get('nonce') == nonce and
            once.get('configSHA256') == sha(config_raw) and type(once.get('pid')) is int, 'supervisor-once binding')
    state = evidence.json('guest/guest-state.json')
    listing = [e['path'].replace('/', '\\').lower() for e in state['remoteListing']]
    require(not [p for p in listing if '\\transport\\commands\\' in p or '\\transport\\responses\\' in p],
            'Guest listing shows delivered commands')
    require(state.get('taskState') == 'Running', 'Owner task not running in evidence')
    require(state.get('ownerTasks') == ['BimeronFull300Owner-%s=Running' % nonce], 'Exactly one running owner task')
    bound = [p for p in state['processes'] if nonce in (p.get('cmd') or '')]
    require(len(bound) == 1 and 'owner-supervisor.ps1' in bound[0]['cmd'] and bound[0]['pid'] == once['pid'],
            'Exactly the supervisor named by supervisor-once.json')
    # The resident's preflight returned exactly this proof (Fetch-OwnerReady output).
    import base64
    preflight = []
    for path in evidence.listed(PRIVATE + 'guest-control/resident-request-'):
        value = evidence.json(path)
        if value.get('operation') == 'preflight':
            response = evidence.json(path.replace('resident-request-', 'resident-response-'))
            preflight.append(response.get('state') == 'Collected' and type(response.get('output')) is str and
                             base64.b64decode(response['output'], validate=True) == once_raw)
    require(preflight == [True], 'Resident preflight output is not the supervisor-once proof')
    evidence.read(ot + 'task-registration.json')
    seal = predicted_command(nonce, config_raw, 'seal-no-launch', {})
    command = strict(seal)
    require(command == dict(schema='full300-owner-command-v1', nonce=nonce, configSHA256=sha(config_raw), seq=1,
                            op='seal-no-launch', body={}), 'Predicted seal binding')
    return dict(seal=seal, sealSHA256=sha(seal), supervisorPid=once['pid'], supervisorOnceSHA256=sha(once_raw),
                b1Variant='unreserved-seal',
                privateFiles={name: sha(evidence.read(PRIVATE + name)) for name in UNRESERVED_FILES})


def response_binding(value, nonce, config_sha, seq, command, state):
    fields(value, ('schema', 'nonce', 'configSHA256', 'seq', 'commandSHA256', 'outcome', 'state', 'owner',
                   'refs', 'error'), 'Owner response')
    require(value['schema'] == 'full300-owner-response-v1' and value['nonce'] == nonce and
            value['configSHA256'] == config_sha and value['seq'] == seq and
            value['commandSHA256'] == sha(command) and value['outcome'] == 'accepted' and
            value['state'] == state and value['error'] is None, 'Owner response %d not accepted %s' % (seq, state))
    return {r['name']: r for r in value['refs']}


def check_b1_done(files, nonce, instance_guid):
    """The run's own seal/exit exchange: responses 1 and 2, proofs and final task readback."""
    ot = 'owner-transport/'
    config_sha = sha(files[ot + 'config.json'])
    seal, exit_raw = files[ot + 'commands/00000001.json'], files[ot + 'commands/00000002.json']
    command = strict(seal)
    require(command.get('seq') == 1 and command.get('op') == 'seal-no-launch' and command.get('nonce') == nonce,
            'Seal command binding')
    refs = response_binding(strict(files[ot + 'responses/00000001.json']), nonce, config_sha, 1, seal, 'SEALED_NO_LAUNCH')
    no_launch = files[ot + 'proofs/no-launch.json']
    require(refs.get('no-launch.json', {}).get('sha256') == sha(no_launch), 'no-launch.json reference')
    sealed = strict(no_launch)
    require(sealed.get('nonce') == nonce and sealed.get('sealed') is True and sealed.get('launchAttempted') is False and
            sealed.get('sealCommandSHA256') == sha(seal), 'no-launch.json binding')
    exit_command = strict(exit_raw)
    require(exit_command.get('seq') == 2 and exit_command.get('op') == 'exit-supervisor' and
            exit_command.get('body', {}).get('noLaunch', {}).get('sha256') == sha(no_launch), 'Exit command binding')
    refs = response_binding(strict(files[ot + 'responses/00000002.json']), nonce, config_sha, 2, exit_raw, 'EXIT_READY')
    ready_raw = files[ot + 'proofs/supervisor-exit-ready.json']
    require(refs.get('supervisor-exit-ready.json', {}).get('sha256') == sha(ready_raw), 'supervisor-exit-ready reference')
    ready = strict(ready_raw)
    require(ready.get('reason') == 'sealed-no-launch' and ready.get('exitCommandSHA256') == sha(exit_raw) and
            ready.get('proofSHA256') == sha(no_launch), 'supervisor-exit-ready binding')
    final = strict(files[ot + 'task-final.json'])
    require(final.get('state') == 3 and final.get('instanceGuids') in ([], None) and
            final.get('instanceGuid') == instance_guid, 'task-final.json')
    return dict(sealSHA256=sha(seal), exitSHA256=sha(exit_raw), noLaunchSHA256=sha(no_launch),
                taskFinal=dict(state=final['state'], instanceGuid=final['instanceGuid']))


def b1_mode(evidence, nonce, instance_guid):
    ot = PRIVATE + 'owner-transport/'
    seen = [n for n in ('commands/00000002.json', 'responses/00000001.json', 'responses/00000002.json',
                        'proofs/no-launch.json', 'proofs/supervisor-exit-ready.json', 'task-final.json')
            if evidence.has(ot + n)]
    if not seen:
        reserved = evidence.listed(ot + 'commands/')
        requests = seal_requests(evidence)
        if reserved:
            return 'act', dict(validate_b1_act(evidence, nonce), b1Variant='reserved-seal')
        require(not requests, 'Reserved/unreserved seal ambiguity: resident seal without host command (%s)'
                % ','.join(requests))
        return 'act', validate_b1_unreserved(evidence, nonce)
    require(len(seen) == 6, 'B1 partly completed by the run (%s); refused' % ','.join(seen))
    files = {name: evidence.read(PRIVATE + name) for name in B1_DONE_FILES}
    proof = check_b1_done(files, nonce, instance_guid)
    require(guest_clean(evidence, nonce), 'B1 completed host-side but the guest evidence is not clean; refused')
    return 'confirm', dict(proof=proof, doneFiles={name: sha(raw) for name, raw in files.items()})


def b3_mode(evidence, nonce, capture, baseline, capture_identity):
    """'confirm' only when every retirement effect is visible; 'act' when none is."""
    sink_contract, live_prepare, admin_evidence = driver_modules()
    present = [p for p in OBSERVER_DONE[1:] if evidence.has(p) and evidence.entries[p]['size'] > 0]
    health = evidence.json('observer/run-health.json') if evidence.has('observer/run-health.json') else {}
    if not present and health.get('ExitCode') is None:
        return 'act', None
    require(len(present) == 2 and type(health.get('ExitCode')) is int,
            'B3 partly completed by the run (%s); refused' % ','.join(present))
    require(health['ExitCode'] == 0, 'Capture ExitCode in evidence is not 0')
    commands = sink_contract.retirement_commands(nonce, capture)
    require(strict(evidence.read('observer/run-cleanup-confirmed.json')) == strict(commands['confirmation']),
            'Cleanup confirmation in evidence')
    receipt = strict(evidence.read('observer/run-sink-exit.json'))
    check_receipt(receipt, nonce, sink_contract)
    unit = 'step10-prep-' + nonce + '.service'
    listing = evidence.read('observer/systemctl-list-units.txt') if evidence.has('observer/systemctl-list-units.txt') else b''
    status = evidence.read('observer/systemctl-status.txt.stderr') if evidence.has('observer/systemctl-status.txt.stderr') else b''
    require(listing.strip() == b'' and ('Unit %s could not be found' % unit).encode() in status,
            'Sink unit absence in evidence')
    observed = dict(nft=strict(evidence.read('observer/nft.json')),
                    topology=dict(links=strict(evidence.read('observer/links.json')),
                                  addresses=strict(evidence.read('observer/addresses.json')),
                                  routes=strict(evidence.read('observer/routes.json'))),
                    labnetFeatures=evidence.read('observer/labnetFeatures.txt'),
                    uplinkFeatures=evidence.read('observer/uplinkFeatures.txt'))
    compare_baseline(observed, baseline, live_prepare, admin_evidence)
    capture = dict(identity=evidence.json('observer/run-identity.json'), health=health,
                   pcap=evidence.read('observer/run-ingress.pcap'),
                   log=evidence.read('observer/run-capture.log').decode('utf-8'))
    capture['archiveSHA256'] = admin_evidence.sha(admin_evidence.encode(admin_evidence.pack(capture)))
    admin_evidence.capture_archive(capture, capture_identity)
    return 'confirm', dict(receipt=receipt, health=health)


def check_receipt(receipt, nonce, sink_contract):
    fields(receipt, ('schema', 'nonce', 'unit', 'contractSHA256', 'invocationId', 'result', 'exitCode',
                     'exitStatus'), 'Sink receipt')
    require(receipt['schema'] == 'fresh-sink-exit-v1' and receipt['nonce'] == nonce and
            receipt['unit'] == 'step10-prep-' + nonce + '.service' and
            receipt['contractSHA256'] == sink_contract.CONTRACT_SHA256 and
            type(receipt['invocationId']) is str and re.fullmatch('[a-f0-9]{32}', receipt['invocationId']) and
            receipt['result'] == 'success' and (receipt['exitCode'], receipt['exitStatus']) in
            (('exited', '0'), ('killed', 'TERM')), 'ExecStopPost receipt')


def compare_baseline(observed, baseline, live_prepare, admin_evidence):
    base = admin_evidence.unpack(baseline)
    nft = observed['nft']
    live_prepare.partition(nft, '__admin_no_owned_table__')
    require(live_prepare.canonical(nft) == live_prepare.canonical(base['nft']), 'nft differs from baseline')
    for key, interface in (('labnetFeatures', 'labnet'), ('uplinkFeatures', 'uplink')):
        require(observed[key] == base[key], 'ethtool differs: ' + interface)
    require(live_prepare.stable_topology(observed['topology']) == live_prepare.stable_topology(base['topology']),
            'ip topology differs from baseline')


def validate(evidence):
    """All preconditions provable from the evidence copy. Returns the plan."""
    nonce = evidence.nonce
    config_raw = evidence.read(PRIVATE + 'owner-transport/config.json')
    config = strict(config_raw)
    require(config.get('nonce') == nonce and config.get('taskName') == 'BimeronFull300Owner-' + nonce,
            'Owner configuration binding')
    instance = evidence.json(PRIVATE + 'owner-transport/task-instance.json')
    fields(instance, ('instanceGuid',), 'Task instance')
    require(re.fullmatch(r'\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}', instance['instanceGuid']) is not None,
            'Task instance GUID')
    if evidence.has(PRIVATE + 'nonce.txt'):
        require(evidence.read(PRIVATE + 'nonce.txt').decode('ascii').strip() == nonce, 'Private root nonce.txt')
    # Observer transport, capture identity and baseline.
    supervisor = evidence.json(PRIVATE + 'host-supervisor-config.json')
    require(supervisor.get('nonce') == nonce, 'Host supervisor nonce')
    query = supervisor['query']
    require(type(query) is list and len(query) > 4 and all(type(a) is str for a in query), 'Observer query')
    require(query[0] == SSH and query[1:3] == ['-F', 'none'] and 'BatchMode=yes' in query and
            'StrictHostKeyChecking=yes' in query, 'Observer ssh argv')
    match = re.fullmatch(r'sudo python3 (/home/lab/step9-[a-f0-9]{64}/capture-supervisor\.py) status ' + nonce, query[-1])
    require(match is not None, 'Observer capture path')
    processes, private_root, transient = process_plan(evidence, nonce, query)
    capture = supervisor['capture']
    fields(capture, ('pid', 'start', 'boot', 'command'), 'Capture identity')
    admission = evidence.json('host/admission/config.json')
    baseline_raw = evidence.read('host/admission/baseline.json')
    require(sha(baseline_raw) == admission['baseline']['sha256'], 'Baseline digest')
    baseline = strict(baseline_raw)
    for key in ('nft', 'topology', 'labnetFeatures', 'uplinkFeatures', 'services'):
        require(key in baseline, 'Baseline field: ' + key)
    require(set(baseline['services']) == set(SERVICES), 'Baseline services')
    admission_root = admission.get('admissionRoot')
    require(type(admission_root) is str and pathlib.PureWindowsPath(admission_root).is_absolute() and
            len(admission_root) > 3, 'Admission root path')
    control = PRIVATE + 'guest-control/'
    quiescent = {p[len(control):]: evidence.entries[p]['sha256'] for p in evidence.listed(control)
                 if QUIESCENT.fullmatch(p[len(control):])}
    require(quiescent, 'Guest-control evidence listing')

    b1, b1_detail = b1_mode(evidence, nonce, instance['instanceGuid'])
    absent = guest_dirs_absent(evidence, nonce)
    require(absent is not None, 'Guest directory state not in evidence')
    b2 = 'confirm' if absent else 'act'
    b3, b3_detail = b3_mode(evidence, nonce, match.group(1), baseline, capture)
    plan = dict(nonce=nonce, evidenceManifestSHA256=evidence.manifestSHA256, admissionRoot=admission_root,
                privateRoot=private_root, guestControl=quiescent, config=config_raw, configSHA256=sha(config_raw),
                instanceGuid=instance['instanceGuid'], processes=processes, ssh=query[:-1], capture=match.group(1),
                captureIdentity=capture, baseline=baseline,
                modes=dict(B1=b1, B2=b2, B3=b3, B4='act'), transientMonitorQueries=transient,
                removalTargets=['C:/BimeronFull300/' + nonce, 'C:/BimeronStep10Probe/' + nonce])
    if b1 == 'act':
        plan.update(b1_detail)
    else:
        plan.update(doneFiles=b1_detail['doneFiles'], b1Evidence=b1_detail['proof'])
    if b3 == 'confirm':
        plan['sinkReceipt'] = b3_detail['receipt']
    plan['planSHA256'] = sha(canonical_json(summary(plan)))
    return plan


def identity_basis(plan):
    """How each listed process is identified before termination (report only; covered by processes)."""
    return [dict(role=p['role'], pid=p['pid'], basis=(
        'journal creationFileTime %d (exact 100 ns) + image + parent, verified live' % p['creationFileTime']
        if p['creationFileTime'] is not None else
        'not in journal: PID + creation time %d us + image + parent from process-tree, verified live on the '
        'termination handle before TerminateProcess' % p['createdMicro'])) for p in plan['processes']]


def report(plan):
    value = dict(summary(plan), label=LABEL, valid=True, planSHA256=plan['planSHA256'], steps=list(STEPS),
                 identityBasis=identity_basis(plan), transientMonitorQueries=plan['transientMonitorQueries'])
    if plan['modes']['B1'] == 'act':
        value['b1Variant'] = plan['b1Variant']
    return value


def summary(plan):
    """What the operator approves: run, root, step modes and the exact termination list."""
    unreserved = plan['modes']['B1'] == 'act' and plan.get('b1Variant') == 'unreserved-seal'
    actions = dict(
        B1=('build seq 1 seal-no-launch by the owner MailboxClient path (no seal was reserved), deliver it, '
            'then exit-supervisor (seq 2) and Complete-OwnerFinal') if unreserved else
           'deliver seal-no-launch (seq 1) then exit-supervisor (seq 2)' if plan['modes']['B1'] == 'act' else
           'read-only: guest no supervisor/task; responses 1,2 and task-final equal evidence',
        B2='remove ' + ' and '.join(plan['removalTargets']) if plan['modes']['B2'] == 'act' else
           'read-only: both run directories absent',
        B3='observer retirement (confirm, stop capture if running, stop sink if listed), archive'
           if plan['modes']['B3'] == 'act' else
           'read-only: capture ExitCode 0, cleanup-confirmed and sink-exit receipts, unit absent, nft/ethtool/ip == baseline',
        B4='terminate ' + ' -> '.join('%s %d' % (p['role'], p['pid']) for p in plan['processes']) +
           ', then leftover scan' + ''.join(', transient monitor query %d (verified descendant only)' % t['pid']
                                            for t in plan['transientMonitorQueries']))
    value = dict(schema='held-run-disposition-plan-v2', nonce=plan['nonce'],
                 evidenceManifestSHA256=plan['evidenceManifestSHA256'], privateRoot=plan['privateRoot'],
                 modes=plan['modes'], actions=actions, removalTargets=plan['removalTargets'],
                 processes=plan['processes'], capture=plan['capture'], ssh=plan['ssh'])
    # Present only when used, so plans of runs without them keep their digest.
    if plan['transientMonitorQueries']:
        value['transientMonitorQueries'] = plan['transientMonitorQueries']
    if unreserved:
        value['b1Variant'] = 'unreserved-seal'
        value['unreservedSeal'] = dict(sealSHA256=plan['sealSHA256'], configSHA256=plan['configSHA256'],
                                       supervisorOnceSHA256=plan['supervisorOnceSHA256'],
                                       supervisorPid=plan['supervisorPid'], builder=SEAL_BUILDER)
    return value


class Journal:
    """Create-new disposition journal; nothing is ever overwritten."""

    def __init__(self, root, nonce):
        self.root = pathlib.Path(root)
        self.nonce = nonce
        (self.root / 'journal').mkdir(parents=True, exist_ok=True)
        self.sequence = len(list((self.root / 'journal').iterdir()))

    def write(self, relative, raw):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return sha(raw)

    def record(self, event, value):
        self.sequence += 1
        raw = canonical_json(dict(schema='held-run-disposition-journal-v1', nonce=self.nonce,
                                  sequence=self.sequence, event=event,
                                  utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                  value=value))
        self.write('journal/%04d-%s.json' % (self.sequence, event), raw)
        return sha(raw)

    def exists(self, relative):
        return (self.root / relative).exists()

    def read(self, relative):
        return strict((self.root / relative).read_bytes())


class Disposition:
    def __init__(self, plan, effects, journal):
        self.plan = plan
        self.nonce = plan['nonce']
        self.effects = effects
        self.journal = journal
        require(journal.nonce == self.nonce, 'Journal nonce')
        self.ot = journal.root / 'owner-transport'

    # ---- step framework -------------------------------------------------
    def run(self, step):
        require(step in STEPS, 'Unknown step')
        require(not self.journal.exists('final-record.json'), 'Disposition already finalized; no further step')
        require(not self.journal.exists('steps/%s.attempted.json' % step), step + ' already attempted; no retry')
        for prior in STEPS[:STEPS.index(step)]:
            require(self.journal.exists('steps/%s.proven.json' % prior), prior + ' not proven')
        mode = self.plan['modes'][step]
        require(mode in ('act', 'confirm'), 'Step mode')
        self.journal.write('steps/%s.attempted.json' % step, canonical_json(dict(step=step, nonce=self.nonce, mode=mode)))
        try:
            if step in ('B1', 'B2'):
                self.quiescent(step)
            before = self.network('%s-before' % step)
            proof = getattr(self, ('step_' if mode == 'act' else 'confirm_') + step)()
            proof = dict(proof, mode=mode)
            # Evidence of the performed action (or the read-only confirmation) is persisted first.
            self.journal.record(step + ('-performed' if mode == 'act' else '-confirmed'), proof)
            after = self.network('%s-after' % step)
            dns = canonical_json(before.get('dns')) == canonical_json(after.get('dns'))
            self.journal.record('network-%s-dns' % step, dict(equal=dns, compared=False))
            speeds = canonical_json(before.get('adapterLinkSpeeds')) == canonical_json(after.get('adapterLinkSpeeds'))
            self.journal.record('network-%s-link-speed' % step, dict(equal=speeds, compared=False))
            require(self.comparable(before) == self.comparable(after), 'Host network/VPN deviation during ' + step)
        except Exception as error:
            reason = '%s: %s' % (type(error).__name__, error)
            self.journal.record(step + '-failed', dict(reason=reason))
            self.journal.write('steps/%s.failed.json' % step, canonical_json(dict(step=step, reason=reason)))
            self.final('STOPPED', step, reason)
            raise
        digest = self.journal.record(step + '-proven', proof)
        self.journal.write('steps/%s.proven.json' % step, canonical_json(dict(step=step, mode=mode, journalSHA256=digest)))
        if step == STEPS[-1]:
            self.final('DISPOSED', None, None)
        return proof

    def final(self, status, stopped, reason):
        steps = {s: self.journal.read('steps/%s.proven.json' % s)['journalSHA256']
                 for s in STEPS if self.journal.exists('steps/%s.proven.json' % s)}
        entries = sorted(p.name for p in (self.journal.root / 'journal').iterdir())
        self.journal.write('final-record.json', canonical_json(dict(
            schema='held-run-disposition-final-v2', nonce=self.nonce, label=LABEL, status=status,
            settled=False, normalCleanup=False, stoppedAt=stopped, reason=reason, modes=self.plan['modes'],
            planSHA256=self.plan['planSHA256'], provenSteps=steps, journal=entries)))

    @staticmethod
    def comparable(snapshot):
        return {k: canonical_json(snapshot.get(k)) for k in STRICT_NETWORK_FIELDS}

    def quiescent(self, step):
        """The held resident must not have reserved, requested or answered anything new."""
        listing = self.effects.guest_control()
        require(type(listing) is dict, 'Guest-control listing')
        live = {name: digest for name, digest in listing.items() if QUIESCENT.fullmatch(name)}
        expected = self.plan['guestControl']
        added = sorted(set(live) - set(expected))
        missing = sorted(set(expected) - set(live))
        changed = sorted(n for n in set(live) & set(expected) if live[n] != expected[n])
        self.journal.record('quiescence-' + step, dict(entries=len(live), added=added, missing=missing,
                                                       changed=changed))
        require(not added and not missing and not changed, 'Held owner not quiescent before %s' % step)

    def network(self, label):
        snapshot = self.effects.host_network()
        require(type(snapshot) is dict and snapshot.get('schema') == 'host-network-readonly-v1' and
                all(k in snapshot for k in NETWORK_FIELDS), 'Host network snapshot')
        self.journal.record('network-' + label, snapshot)
        return snapshot

    def guest(self, label):
        state = self.effects.guest_state()
        require(type(state) is dict and state.get('schema') == 'held-run-guest-state-v1' and
                state.get('nonce') == self.nonce and state.get('computer') == '<LAB_GUEST_NAME>', 'Guest readback binding')
        self.journal.record('guest-' + label, state)
        return state

    def guest_restored(self, after):
        require(after['processes'] == [], 'Run processes remain')
        require(after['tasks'] == [], 'Owner task still registered')
        require('No connections' in after['ras'], 'RAS connections present')
        require(after['services'] == self.plan['baseline']['services'], 'Guest services differ from baseline')
        require(after['udp'] == [], 'UDP 500/4500 bound')
        require(all(after['policy'].get(s) == 'Undefined' for s in PERSISTENT_POLICY) and
                set(after['policy']) == set(PERSISTENT_POLICY), 'Persistent execution policy not Undefined')

    # ---- B1 ---------------------------------------------------------------
    def stage_transport(self):
        sources = self.effects.private_files(PRIVATE_FILES)
        for name, digest in self.plan['privateFiles'].items():
            require(sha(sources[name]) == digest, 'Held private root differs from evidence: ' + name)
        for name in ('commands/00000001.json', 'config.json', 'task-registration.json', 'task-instance.json'):
            self.journal.write('owner-transport/' + name, sources['owner-transport/' + name])
        for name in ('responses', 'proofs', 'samples'):
            (self.ot / name).mkdir()
        require((self.ot / 'commands/00000001.json').read_bytes() == self.plan['seal'], 'Seal bytes staged')

    def response(self, seq, command, state):
        raw = (self.ot / 'responses' / ('%08d.json' % seq)).read_bytes()
        refs = response_binding(strict(raw), self.nonce, self.plan['configSHA256'], seq, command, state)
        return raw, refs

    def proof(self, refs, name):
        require(name in refs, 'Response reference missing: ' + name)
        raw = (self.ot / 'proofs' / name).read_bytes()
        require(len(raw) == refs[name]['length'] and sha(raw) == refs[name]['sha256'], 'Archived proof: ' + name)
        return raw

    def deliver(self, seq):
        path = self.ot / 'commands' / ('%08d.json' % seq)
        code, out, err = self.effects.deliver(path)
        self.journal.record('deliver-%d' % seq, dict(exitCode=code, stdoutSHA256=sha(out), stderr=err.decode('utf-8', 'replace')[-4000:]))
        require(code == 0, 'protected-guest.ps1 final failed for seq %d' % seq)

    def step_B1(self):
        if self.plan.get('b1Variant') == 'unreserved-seal':
            return self.step_B1_unreserved()
        before = self.guest('B1-precondition')
        require(before['commands'] == [] and before['responses'] == [], 'Guest transport commands/responses not empty')
        require(before['noLaunch'] is False and before['rootExists'] is True, 'Guest mailbox state')
        tasks = before['tasks']
        require(len(tasks) == 1 and tasks[0]['state'] == 4 and tasks[0]['instances'] == [self.plan['instanceGuid']],
                'Owner task not running its original instance')
        supervisors = [p for p in before['processes'] if 'owner-supervisor.ps1' in (p.get('commandLine') or '')]
        require(len(supervisors) == 1 and len(before['processes']) == 1 and
                supervisors[0].get('pid') == self.plan['supervisorPid'], 'Exactly the original supervisor process')
        self.stage_transport()
        self.deliver(1)
        _, refs = self.response(1, self.plan['seal'], 'SEALED_NO_LAUNCH')
        no_launch = self.proof(refs, 'no-launch.json')
        sealed = strict(no_launch)
        require(sealed.get('schema') == 'full300-no-launch-v1' and sealed.get('nonce') == self.nonce and
                sealed.get('configSHA256') == self.plan['configSHA256'] and
                sealed.get('sealCommandSHA256') == self.plan['sealSHA256'] and
                sealed.get('launchAttempted') is False and sealed.get('sealed') is True, 'no-launch.json binding')
        exit_raw = encode(dict(schema='full300-owner-command-v1', nonce=self.nonce, configSHA256=self.plan['configSHA256'],
                               seq=2, op='exit-supervisor', body=dict(noLaunch=dict(
                                   name='no-launch.json', sha256=sha(no_launch), length=len(no_launch)))))
        self.journal.write('owner-transport/commands/00000002.json', exit_raw)
        self.deliver(2)
        _, refs = self.response(2, exit_raw, 'EXIT_READY')
        ready = strict(self.proof(refs, 'supervisor-exit-ready.json'))
        require(ready.get('schema') == 'full300-supervisor-exit-v1' and ready.get('reason') == 'sealed-no-launch' and
                ready.get('exitCommandSHA256') == sha(exit_raw) and ready.get('proofSHA256') == sha(no_launch) and
                ready.get('supervisorOnceSHA256') == sealed.get('supervisorOnceSHA256'), 'supervisor-exit-ready binding')
        final = strict((self.ot / 'task-final.json').read_bytes())
        require(final.get('state') == 3 and final.get('instanceGuids') in ([], None) and
                final.get('instanceGuid') == self.plan['instanceGuid'], 'task-final.json')
        after = self.guest('B1-readback')
        self.guest_restored(after)
        return dict(sealSHA256=self.plan['sealSHA256'], exitSHA256=sha(exit_raw), noLaunchSHA256=sha(no_launch),
                    supervisorPid=supervisors[0]['pid'], taskFinal=final)

    def b1_precondition(self):
        before = self.guest('B1-precondition')
        require(before['commands'] == [] and before['responses'] == [], 'Guest transport commands/responses not empty')
        require(before['noLaunch'] is False and before['rootExists'] is True, 'Guest mailbox state')
        tasks = before['tasks']
        require(len(tasks) == 1 and tasks[0]['state'] == 4 and tasks[0]['instances'] == [self.plan['instanceGuid']],
                'Owner task not running its original instance')
        supervisors = [p for p in before['processes'] if 'owner-supervisor.ps1' in (p.get('commandLine') or '')]
        require(len(supervisors) == 1 and len(before['processes']) == 1 and
                supervisors[0].get('pid') == self.plan['supervisorPid'], 'Exactly the original supervisor process')
        return supervisors[0]

    def step_B1_unreserved(self):
        """No seal was reserved: the owner's MailboxClient builds seq 1/2; nothing is hand-crafted."""
        if str(DRIVER) not in sys.path:
            sys.path.insert(0, str(DRIVER))
        import protected_transport
        # Live host mailbox must still hold no reserved command or response.
        mailbox = ('owner-transport/commands', 'owner-transport/responses', 'owner-transport/receipts')
        listing = self.effects.private_listing(mailbox)
        self.journal.record('B1-host-mailbox', listing)
        require(type(listing) is dict and all(listing.get(n) in (None, []) for n in mailbox),
                'Host owner-transport holds a reserved command, response or receipt; refused')
        supervisor = self.b1_precondition()
        sources = self.effects.private_files(UNRESERVED_FILES)
        for name, digest in self.plan['privateFiles'].items():
            require(sha(sources[name]) == digest, 'Held private root differs from evidence: ' + name)
        for name in ('config.json', 'task-registration.json', 'task-instance.json', 'proofs/supervisor-once.json'):
            self.journal.write('owner-transport/' + name, sources['owner-transport/' + name])
        for name in ('responses', 'samples'):
            (self.ot / name).mkdir()
        delivered = []

        def rpc(mode, path):
            path = pathlib.Path(path)
            require(mode == 'submit' and path.parent == self.ot / 'commands', 'Mailbox RPC mode/path')
            raw = path.read_bytes()
            seq = int(path.stem)
            require(seq == len(delivered) + 1, 'Mailbox sequence')
            if seq == 1:
                # Refuse before any effect unless the owner path produced exactly the approved seal.
                require(raw == self.plan['seal'], 'Seal bytes differ from the approved plan')
            self.journal.record('command-%d' % seq, dict(sha256=sha(raw), length=len(raw), bytes=raw.decode('utf-8')))
            delivered.append(sha(raw))
            self.deliver(seq)
            return (self.ot / 'responses' / path.name).read_bytes()
        client = protected_transport.MailboxClient(self.ot, self.nonce, sources['owner-transport/config.json'], rpc)
        require(client.config_hash == self.plan['configSHA256'], 'Mailbox configuration digest')
        try:
            client.command('seal-no-launch', {})
        except protected_transport.Hold as error:
            raise Refusal('Seal not accepted: %s' % error) from None
        seal = (self.ot / 'commands/00000001.json').read_bytes()
        _, refs = self.response(1, seal, 'SEALED_NO_LAUNCH')
        no_launch = self.proof(refs, 'no-launch.json')
        sealed = strict(no_launch)
        require(sealed.get('schema') == 'full300-no-launch-v1' and sealed.get('nonce') == self.nonce and
                sealed.get('configSHA256') == self.plan['configSHA256'] and
                sealed.get('sealCommandSHA256') == self.plan['sealSHA256'] and
                sealed.get('supervisorOnceSHA256') == self.plan['supervisorOnceSHA256'] and
                sealed.get('launchAttempted') is False and sealed.get('sealed') is True, 'no-launch.json binding')
        try:
            client.command('exit-supervisor', dict(noLaunch=dict(name='no-launch.json', sha256=sha(no_launch),
                                                                 length=len(no_launch))))
        except protected_transport.Hold as error:
            raise Refusal('Exit-supervisor not accepted: %s' % error) from None
        exit_raw = (self.ot / 'commands/00000002.json').read_bytes()
        _, refs = self.response(2, exit_raw, 'EXIT_READY')
        ready = strict(self.proof(refs, 'supervisor-exit-ready.json'))
        require(ready.get('schema') == 'full300-supervisor-exit-v1' and ready.get('reason') == 'sealed-no-launch' and
                ready.get('exitCommandSHA256') == sha(exit_raw) and ready.get('proofSHA256') == sha(no_launch) and
                ready.get('supervisorOnceSHA256') == self.plan['supervisorOnceSHA256'], 'supervisor-exit-ready binding')
        final = strict((self.ot / 'task-final.json').read_bytes())
        require(final.get('state') == 3 and final.get('instanceGuids') in ([], None) and
                final.get('instanceGuid') == self.plan['instanceGuid'], 'task-final.json')
        after = self.guest('B1-readback')
        self.guest_restored(after)
        return dict(variant='unreserved-seal', sealSHA256=sha(seal), exitSHA256=sha(exit_raw),
                    noLaunchSHA256=sha(no_launch), supervisorPid=supervisor['pid'], taskFinal=final,
                    delivered=delivered)

    def confirm_B1(self):
        """Read-only: the run already sealed and released its supervisor; nothing is delivered."""
        sources = self.effects.private_files(B1_DONE_FILES)
        for name, digest in self.plan['doneFiles'].items():
            require(sha(sources[name]) == digest, 'Held private root differs from evidence: ' + name)
        proof = check_b1_done(sources, self.nonce, self.plan['instanceGuid'])
        state = self.guest('B1-confirm')
        supervisors = [p for p in state['processes'] if 'owner-supervisor.ps1' in (p.get('commandLine') or '')]
        require(not supervisors, 'Guest supervisor still running')
        self.guest_restored(state)
        return dict(proof, guestClean=True, delivered=[])

    # ---- B2 ---------------------------------------------------------------
    def step_B2(self):
        removed = self.effects.guest_remove(self.nonce)
        require(type(removed) is dict and removed.get('targets') == self.plan['removalTargets'], 'Removal targets')
        state = self.guest('B2-absence')
        require(state['rootExists'] is False and state['probeExists'] is False, 'Run directories still present')
        require(state['processes'] == [] and state['tasks'] == [], 'Run processes/task reappeared')
        return dict(removed=removed, absent=True)

    def confirm_B2(self):
        state = self.guest('B2-confirm')
        require(state['rootExists'] is False and state['probeExists'] is False, 'Run directories present; B2 not done')
        require(state['processes'] == [] and state['tasks'] == [], 'Run processes/task reappeared')
        return dict(removed=None, absent=True)

    # ---- B3 ---------------------------------------------------------------
    def ssh(self, key, command, data=b''):
        raw = self.effects.ssh(self.plan['ssh'] + [command], data)
        self.journal.record('ssh-' + key, dict(command=command, stdinSHA256=sha(data), stdoutSHA256=sha(raw),
                                               length=len(raw)))
        return raw

    def remote(self):
        return '/var/lib/step8/run-' + self.nonce + '/'

    def unit_listing(self):
        return 'sudo systemctl list-units --all --plain --no-legend --no-pager step10-prep-' + self.nonce + '.service'

    def archive(self, health):
        _, _, admin_evidence = driver_modules()
        remote = self.remote()
        archive = {name: self.ssh('archive-' + name, 'sudo cat ' + remote + name)
                   for name in ('ingress.pcap', 'capture.log', 'identity.json')}
        for name, raw in archive.items():
            self.journal.write('observer-archive/' + name, raw)
        self.journal.write('observer-archive/health.json', canonical_json(health))
        capture = dict(identity=strict(archive['identity.json']), health=health, pcap=archive['ingress.pcap'],
                       log=archive['capture.log'].decode('utf-8'))
        capture['archiveSHA256'] = admin_evidence.sha(admin_evidence.encode(admin_evidence.pack(capture)))
        admin_evidence.capture_archive(capture, self.plan['captureIdentity'])
        return capture['archiveSHA256']

    def observer_baseline(self):
        _, live_prepare, admin_evidence = driver_modules()
        observed = dict(nft=strict(self.ssh('nft', 'sudo nft -j list ruleset')),
                        labnetFeatures=self.ssh('labnetFeatures', 'sudo ethtool -k labnet'),
                        uplinkFeatures=self.ssh('uplinkFeatures', 'sudo ethtool -k uplink'),
                        topology={name: strict(self.ssh(name, command)) for name, command in
                                  (('links', 'ip -j link show'), ('addresses', 'ip -j address show'),
                                   ('routes', 'ip -j route show table all'))})
        compare_baseline(observed, self.plan['baseline'], live_prepare, admin_evidence)

    def step_B3(self):
        sink_contract, _, _ = driver_modules()
        nonce = self.nonce
        commands = sink_contract.retirement_commands(nonce, self.plan['capture'])
        remote = self.remote()
        unit = 'step10-prep-' + nonce
        command, data = commands['admin-capture-confirm']
        self.ssh('capture-confirm', command, data)
        confirmed = self.ssh('read-confirm', 'sudo cat ' + remote + 'cleanup-confirmed.json')
        require(strict(confirmed) == strict(commands['confirmation']), 'Cleanup confirmation readback')
        health = strict(self.ssh('read-health', 'sudo cat ' + remote + 'health.json'))
        if health.get('ExitCode') is None:
            command, data = commands['admin-capture-stop']
            self.ssh('capture-stop', command, data)
            # stop only signals the supervisor; wait (bounded, read-only) for its recorded exit.
            for attempt in range(1, HEALTH_POLL_LIMIT + 1):
                self.effects.sleep(HEALTH_POLL_SECONDS)
                health = strict(self.ssh('read-health-poll-%02d' % attempt, 'sudo cat ' + remote + 'health.json'))
                if health.get('ExitCode') is not None:
                    break
            require(health.get('ExitCode') is not None,
                    'Capture health ExitCode still null %d s after stop' % (HEALTH_POLL_LIMIT * HEALTH_POLL_SECONDS))
        require(type(health.get('ExitCode')) is int and health['ExitCode'] == 0, 'Capture health ExitCode 0')
        archived = self.archive(health)
        status = self.ssh('sink-status', self.unit_listing()).decode()
        if status.strip():
            require(len(status.splitlines()) == 1 and status.split()[0] == unit + '.service', 'Sink unit listing')
            command, data = commands['admin-sink-stop']
            self.ssh('sink-stop', command, data)
        receipt = strict(self.ssh('sink-receipt', 'sudo cat ' + remote + 'sink-exit.json'))
        check_receipt(receipt, nonce, sink_contract)
        require(self.ssh('sink-status-after', self.unit_listing()).decode().strip() == '', 'Sink unit still listed')
        self.observer_baseline()
        return dict(health=health, archiveSHA256=archived, receipt=receipt, unitAbsent=True,
                    nftEqual=True, ethtoolEqual=True, topologyEqual=True)

    def confirm_B3(self):
        """Read-only: no confirm, stop or sink command is sent."""
        sink_contract, _, _ = driver_modules()
        commands = sink_contract.retirement_commands(self.nonce, self.plan['capture'])
        remote = self.remote()
        confirmed = self.ssh('read-confirm', 'sudo cat ' + remote + 'cleanup-confirmed.json')
        require(strict(confirmed) == strict(commands['confirmation']), 'Cleanup confirmation readback')
        health = strict(self.ssh('read-health', 'sudo cat ' + remote + 'health.json'))
        require(type(health.get('ExitCode')) is int and health['ExitCode'] == 0, 'Capture health ExitCode 0')
        archived = self.archive(health)
        receipt = strict(self.ssh('sink-receipt', 'sudo cat ' + remote + 'sink-exit.json'))
        check_receipt(receipt, self.nonce, sink_contract)
        require(receipt == self.plan['sinkReceipt'], 'Sink receipt differs from evidence')
        require(self.ssh('sink-status', self.unit_listing()).decode().strip() == '', 'Sink unit still listed')
        self.observer_baseline()
        return dict(health=health, archiveSHA256=archived, receipt=receipt, unitAbsent=True,
                    nftEqual=True, ethtoolEqual=True, topologyEqual=True, sent=[])

    # ---- B4 ---------------------------------------------------------------
    def check_identity(self, expected, actual):
        require(type(actual) is dict and actual.get('pid') == expected['pid'], 'Process absent: %d' % expected['pid'])
        require(actual['creationFileTime'] // 10 == expected['createdMicro'] and
                (expected['creationFileTime'] is None or actual['creationFileTime'] == expected['creationFileTime']),
                'Creation time mismatch: %d' % expected['pid'])
        require(os.path.normcase(actual['image']) == os.path.normcase(expected['image']),
                'Image mismatch: %d' % expected['pid'])
        require(actual['parent'] == expected['parent'], 'Parent mismatch: %d' % expected['pid'])

    def step_B4(self):
        expected = self.plan['processes']
        require([p['role'] for p in expected] == sorted((p['role'] for p in expected), key=ROLES.index) and
                expected[-1]['role'] == 'owner', 'Termination role order')
        # Refuse before any effect if any listed identity differs.
        for item in expected:
            actual = self.effects.process_identity(item['pid'])
            self.journal.record('identity-%d' % item['pid'], actual)
            self.check_identity(item, actual)
        # Note only (no effect): a still-live transient status query is left to
        # the leftover scan, which disposes it only as a verified descendant.
        for query in self.plan.get('transientMonitorQueries', []):
            actual = self.effects.process_identity(query['pid'])
            live = (type(actual) is dict and actual.get('pid') == query['pid'] and
                    type(actual.get('creationFileTime')) is int and
                    actual['creationFileTime'] // 10 == query['createdMicro'] and
                    actual.get('parent') == query['parent'])
            self.journal.record('B4-transient-ssh-%d' % query['pid'], dict(
                live=live, observed=actual, planned=query,
                note=('live transient owner ssh query at B4; not in the termination list, disposed only '
                      'as a verified descendant by the leftover scan') if live else
                     'transient owner ssh query not live at B4 (exited or PID reused)'))
        results = []
        for item in expected:
            result = self.effects.terminate(item['pid'], lambda actual, item=item: self.check_identity(item, actual))
            self.journal.record('terminated-%d' % item['pid'], dict(result, role=item['role']))
            require(result.get('terminated') is True and result.get('pid') == item['pid'], 'Termination unproven: %d' % item['pid'])
            results.append(result)
        leftovers = self.leftovers(expected)
        return dict(terminated=[r['pid'] for r in results], roles=[p['role'] for p in expected], leftovers=leftovers)

    def leftovers(self, expected):
        """Find run-bound processes left after B4; kill only verified descendants of the terminated tree."""
        markers = (self.nonce.lower(), ('cp-' + self.nonce[:16]).lower(), self.plan['admissionRoot'].lower())
        scan = self.effects.process_scan()
        require(type(scan) is dict and type(scan.get('processes')) is list and type(scan.get('self')) is int,
                'Process scan shape')
        rows = {p['pid']: p for p in scan['processes']}
        me = os.getpid()
        # This tool, its launcher chain and its own read-only helpers carry the nonce on their command lines.
        own = {me, scan['self']}
        cursor = me
        while cursor in rows and rows[cursor]['parent'] not in own:
            cursor = rows[cursor]['parent']
            own.add(cursor)
        grown = True
        while grown:
            grown = False
            for row in rows.values():
                if row['pid'] not in own and row['parent'] in (me, scan['self']):
                    own.add(row['pid'])
                    grown = True
        found = [row for row in scan['processes'] if row['pid'] not in own and
                 any(m in (row.get('commandLine') or '').lower() for m in markers)]
        self.journal.record('leftover-scan', dict(found=found, excluded=sorted(own)))
        if not found:
            return []
        # Ancestors: the terminated identities, extended by verified children (exact creation order).
        ancestors = {item['pid']: item['creationFileTime'] if item['creationFileTime'] is not None
                     else item['createdMicro'] * 10 for item in expected}
        verified, pending = [], list(found)
        progress = True
        while pending and progress:
            progress = False
            for row in list(pending):
                if row['parent'] not in ancestors:
                    continue
                identity = self.effects.process_identity(row['pid'])
                if identity is None:
                    # Exited by itself between scan and verification: nothing left to dispose.
                    self.journal.record('leftover-gone-%d' % row['pid'], dict(row=row, stage='verify'))
                    pending.remove(row)
                    progress = True
                    continue
                require(type(identity) is dict and identity.get('pid') == row['pid'] and
                        identity.get('parent') == row['parent'], 'Leftover identity changed: %d' % row['pid'])
                # A child is created after its parent; a reused parent PID would be younger than the child.
                if identity['creationFileTime'] > ancestors[row['parent']]:
                    ancestors[row['pid']] = identity['creationFileTime']
                    verified.append(identity)
                    pending.remove(row)
                    progress = True
        self.journal.record('leftover-verdict', dict(verified=verified, unverified=pending))
        require(not pending, 'Unverified leftover run processes: %s' % sorted(r['pid'] for r in pending))
        terminated = []
        for identity in reversed(verified):  # descendants before their parents

            def same(actual, identity=identity):
                require(type(actual) is dict and actual.get('pid') == identity['pid'] and
                        actual.get('creationFileTime') == identity['creationFileTime'] and
                        os.path.normcase(actual.get('image') or '') == os.path.normcase(identity['image']) and
                        actual.get('parent') == identity['parent'], 'Leftover identity changed: %d' % identity['pid'])
            result = self.effects.terminate(identity['pid'], same, gone_ok=True)
            require(type(result) is dict and result.get('pid') == identity['pid'], 'Leftover termination result')
            if result.get('gone') is True:
                # Exited by itself after verification; the rescan below still checks its identity.
                self.journal.record('leftover-gone-%d' % identity['pid'], dict(result, stage='terminate'))
            else:
                self.journal.record('terminated-leftover-%d' % identity['pid'], result)
                require(result.get('terminated') is True, 'Leftover termination unproven: %d' % identity['pid'])
            terminated.append(identity)
        after = self.effects.process_scan()
        require(type(after) is dict and type(after.get('processes')) is list, 'Process rescan shape')

        def same_process(row, identity):
            # CIM creation time has microsecond precision; native FILETIME has 100 ns.
            created = row.get('creationFileTime')
            return row.get('pid') == identity['pid'] and (
                created is None or created // 10 == identity['creationFileTime'] // 10)
        remaining = [row['pid'] for row in after['processes'] if any(same_process(row, i) for i in terminated)]
        terminated = [i['pid'] for i in terminated]
        self.journal.record('leftover-rescan', dict(remaining=remaining))
        require(not remaining, 'Leftover processes still present: %s' % remaining)
        return terminated


class LiveEffects:
    """The only external effects. Absolute images; ssh is -F none."""

    def __init__(self, plan, private_root, driver):
        self.plan = plan
        self.private_root = pathlib.Path(private_root)
        self.driver = pathlib.Path(driver)
        self.helper = HERE / 'dispose-held-run.ps1'

    def private_files(self, names):
        return {name: (self.private_root / pathlib.PurePosixPath(name)).read_bytes() for name in names}

    def private_listing(self, names):
        """Read-only: entry names of private-root directories (None when absent)."""
        result = {}
        for name in names:
            path = self.private_root / pathlib.PurePosixPath(name)
            if not os.path.lexists(path):
                result[name] = None
                continue
            require(path.is_dir() and not reparse(path), 'Private mailbox directory: ' + name)
            result[name] = sorted(os.listdir(path))
        return result

    def _powershell(self, script, args, timeout):
        argv = [POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script), *args]
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                                   env=powershell_environment())
        return completed.returncode, completed.stdout, completed.stderr

    def _helper(self, operation, timeout=180):
        code, out, err = self._powershell(self.helper, ['-Step', operation, '-RunNonce', self.plan['nonce'], '-Driver', str(self.driver)], timeout)
        require(code == 0, 'Helper %s failed: %s' % (operation, err.decode('utf-8', 'replace')[-2000:]))
        lines = [line for line in out.decode('utf-8-sig').splitlines() if line.strip()]
        require(len(lines) == 1, 'Helper %s output shape' % operation)
        return strict(lines[0].encode())

    def host_network(self):
        return self._helper('host-network', 120)

    def process_scan(self):
        return self._helper('host-processes', 120)

    @staticmethod
    def sleep(seconds):
        time.sleep(seconds)

    def guest_control(self):
        """Read-only digest listing of the held resident's guest-control directory."""
        root = self.private_root / 'guest-control'
        require(not reparse(root), 'Guest-control is a reparse point')
        listing = {}
        with os.scandir(root) as entries:
            for entry in entries:
                if not QUIESCENT.fullmatch(entry.name):
                    continue
                info = entry.stat(follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & REPARSE,
                        'Guest-control entry is not a plain file: ' + entry.name)
                listing[entry.name] = sha(pathlib.Path(entry.path).read_bytes())
        return listing

    def guest_state(self):
        return self._helper('guest-state')

    def guest_remove(self, nonce):
        require(nonce == self.plan['nonce'], 'Removal nonce')
        return self._helper('guest-remove')

    def deliver(self, path):
        return self._powershell(self.driver / 'protected-guest.ps1',
                                ['-Operation', 'final', '-Nonce', self.plan['nonce'], '-RequestPath', str(path), '-Mode', 'submit'], 300)

    def ssh(self, argv, data):
        require(argv[0] == SSH and argv[1:3] == ['-F', 'none'], 'ssh argv')
        completed = subprocess.run(argv, input=data, capture_output=True, timeout=120)
        require(completed.returncode == 0, 'ssh failed (%d): %s' % (completed.returncode,
                                                                    completed.stderr.decode('utf-8', 'replace')[-2000:]))
        return completed.stdout

    # Native process identity on one handle (no PID reuse window).
    def _kernel(self):
        from ctypes import wintypes
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
        k.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        k.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
        return k, wintypes

    def _parent(self, k, wintypes, pid):
        class Entry(ctypes.Structure):
            _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ProcessID', wintypes.DWORD),
                        ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', wintypes.DWORD),
                        ('cntThreads', wintypes.DWORD), ('th32ParentProcessID', wintypes.DWORD),
                        ('pcPriClassBase', ctypes.c_long), ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]
        snap = k.CreateToolhelp32Snapshot(2, 0)
        require(snap not in (None, ctypes.c_void_p(-1).value), 'Process snapshot')
        try:
            entry = Entry()
            entry.dwSize = ctypes.sizeof(Entry)
            ok = k.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                if entry.th32ProcessID == pid:
                    return entry.th32ParentProcessID
                ok = k.Process32NextW(snap, ctypes.byref(entry))
        finally:
            k.CloseHandle(snap)
        return None

    def _identity(self, k, wintypes, handle, pid):
        times = [wintypes.FILETIME() for _ in range(4)]
        require(k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]), 'GetProcessTimes')
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        require(k.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)), 'QueryFullProcessImageNameW')
        code = wintypes.DWORD()
        require(k.GetExitCodeProcess(handle, ctypes.byref(code)), 'GetExitCodeProcess')
        created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        return dict(pid=pid, creationFileTime=created, image=buffer.value, parent=self._parent(k, wintypes, pid),
                    alive=code.value == 259)

    def process_identity(self, pid):
        k, wintypes = self._kernel()
        handle = k.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            return self._identity(k, wintypes, handle, pid)
        finally:
            k.CloseHandle(handle)

    def terminate(self, pid, check, gone_ok=False):
        k, wintypes = self._kernel()
        handle = k.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, pid)
        if not handle and gone_ok and ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: no such process
            return dict(pid=pid, terminated=False, gone=True, identity=None)
        require(handle, 'OpenProcess for termination: %d' % pid)
        try:
            identity = self._identity(k, wintypes, handle, pid)
            check(identity)
            if gone_ok and not identity['alive']:
                return dict(pid=pid, terminated=False, gone=True, identity=identity)
            require(identity['alive'], 'Process already exited: %d' % pid)
            require(k.TerminateProcess(handle, 1), 'TerminateProcess: %d' % pid)
            require(k.WaitForSingleObject(handle, 15000) == 0, 'Process did not exit: %d' % pid)
            code = wintypes.DWORD()
            require(k.GetExitCodeProcess(handle, ctypes.byref(code)), 'GetExitCodeProcess after termination')
            return dict(pid=pid, terminated=True, exitCode=code.value, identity=identity)
        finally:
            k.CloseHandle(handle)


# Rights that let a principal alter a directory or its contents.
WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
RIGHT_CODES = dict(GA=0x10000000, GR=0x80000000, GW=0x40000000, GX=0x20000000, FA=0x1F01FF, FR=0x120089,
                   FW=0x120116, FX=0x1200A0, SD=0x10000, RC=0x20000, WD=0x40000, WO=0x80000, CC=0x1, DC=0x2,
                   LC=0x4, SW=0x8, RP=0x10, WP=0x20, DT=0x40, LO=0x80, CR=0x100)
BROAD_SIDS = {'WD', 'AU', 'BU', 'BG', 'IU', 'AN', 'NU', 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546',
              'S-1-5-4', 'S-1-5-7', 'S-1-5-2'}


def broad_write_aces(sddl):
    """Effective allow ACEs in the DACL granting write-type rights to broad principals."""
    require(type(sddl) is str and 'D:' in sddl, 'Directory SDDL')
    dacl = sddl[sddl.index('D:') + 2:]
    if 'S:' in dacl:
        dacl = dacl[:dacl.index('S:')]
    found = []
    for ace in re.findall(r'\(([^)]*)\)', dacl):
        parts = ace.split(';')
        require(len(parts) >= 6, 'ACE shape')
        kind, flags, rights, sid = parts[0], parts[1], parts[2], parts[5]
        if kind not in ('A', 'XA') or 'IO' in re.findall('..', flags):
            continue
        if rights.lower().startswith('0x'):
            mask = int(rights, 16)
        else:
            codes = re.findall('..', rights)
            require(''.join(codes) == rights and all(c in RIGHT_CODES for c in codes), 'Unknown ACE rights: ' + rights)
            mask = 0
            for code in codes:
                mask |= RIGHT_CODES[code]
        if sid in BROAD_SIDS and mask & WRITE_MASK:
            found.append(ace)
    return found


def read_sddl(path):
    """Read-only ACL query."""
    # Windows PowerShell 5.1 folds arguments after -Command into the command text; pass the path by environment.
    argv = [POWERSHELL, '-NoProfile', '-NonInteractive', '-Command',
            '[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);(Get-Acl -LiteralPath $env:BIMERON_ACL_PATH).Sddl']
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
                               env=powershell_environment(BIMERON_ACL_PATH=str(path)))
    require(completed.returncode == 0, 'ACL query failed: ' + str(path))
    return completed.stdout.decode('utf-8-sig').strip()


def reparse(path):
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & REPARSE)


def validate_work(work, step):
    """Refuse an unsafe disposition directory before any external effect."""
    require(work.is_absolute() and work.name != '' and work.parent != work, 'Absolute work directory')
    require(os.path.normcase(os.path.abspath(str(work))) == os.path.normcase(str(work)), 'Normalized work directory')
    for ancestor in work.parents:
        require(ancestor.is_dir(), 'Work ancestor missing: ' + str(ancestor))
        require(not reparse(ancestor), 'Work ancestor is a reparse point: ' + str(ancestor))
    require(not broad_write_aces(read_sddl(work.parent)), 'Work parent is writable by broad principals')
    if step == 'B1':
        require(not os.path.lexists(work), 'Disposition work directory already exists')
        return
    require(work.is_dir() and not reparse(work), 'Existing disposition work directory')
    require(not broad_write_aces(read_sddl(work)), 'Work directory is writable by broad principals')
    for base, dirs, files in os.walk(work):
        for name in dirs + files:
            require(not reparse(os.path.join(base, name)), 'Reparse point inside work directory')


def check_private_root(plan, private_root):
    """Operator --private-root: either naming scheme, equal to the watcher's root, bound to the nonce."""
    nonce = plan['nonce']
    require(private_root.is_absolute() and private_root.name in private_root_names(nonce), 'Held private root path')
    if plan['privateRoot'] is not None:
        require(os.path.normcase(str(private_root)) == os.path.normcase(plan['privateRoot']),
                'Held private root differs from the watcher root in evidence')
    require(private_root.is_dir() and not reparse(private_root), 'Held private root directory')
    marker = private_root / 'nonce.txt'
    if marker.exists():
        require(marker.read_bytes().decode('ascii').strip() == nonce, 'Held private root nonce.txt')
    identity = private_root / 'run-identity.json'
    if identity.exists():
        value = strict(identity.read_bytes())
        require(value.get('nonce') == nonce and value.get('rootName') == private_root.name, 'Held private root run-identity.json')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Administrative branch-B disposition of a held run')
    parser.add_argument('mode', choices=('dry-run', 'run'))
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--step', choices=STEPS)
    parser.add_argument('--private-root')
    parser.add_argument('--work')
    parser.add_argument('--approve-nonce')
    parser.add_argument('--approve-plan')
    parser.add_argument('--driver', default=str(DRIVER))
    args = parser.parse_args(argv)
    try:
        plan = validate(Evidence(args.evidence))
        if args.mode == 'dry-run':
            print(json.dumps(report(plan), indent=1))
            return 0
        require(args.step and args.private_root and args.work and args.approve_nonce and args.approve_plan,
                'run needs --step, --private-root, --work, --approve-nonce, --approve-plan')
        require(args.approve_nonce == plan['nonce'], 'Approval nonce mismatch')
        require(args.approve_plan == plan['planSHA256'], 'Approval plan mismatch; rerun dry-run and review')
        private_root = pathlib.Path(args.private_root)
        check_private_root(plan, private_root)
        work = pathlib.Path(args.work)
        validate_work(work, args.step)
        if args.step == 'B1':
            work.mkdir(parents=False, exist_ok=False)
            require(not reparse(work) and not broad_write_aces(read_sddl(work)), 'New work directory ACL')
        driver = pathlib.Path(args.driver).resolve()
        require((driver / 'protected-guest.ps1').is_file(), 'Fixed driver path')
        disposition = Disposition(plan, LiveEffects(plan, private_root, driver), Journal(work, plan['nonce']))
        disposition.run(args.step)
        print(json.dumps(dict(step=args.step, mode=plan['modes'][args.step], proven=True, label=LABEL), indent=1, default=str))
        return 0
    except Exception as error:
        print(json.dumps(dict(stopped=True, reason='%s: %s' % (type(error).__name__, error), label=LABEL)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
