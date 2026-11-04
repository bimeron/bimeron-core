"""Synthetic Core contract only: no persistence, IPC, OS or network adapters."""
from copy import deepcopy
from dataclasses import dataclass


class Blocked(Exception):
    pass


class Crash(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


@dataclass(frozen=True)
class Identity:
    installation: str
    operation: str
    generation: int
    boot: str
    instance: str
    session: str


@dataclass(frozen=True)
class Receipt:
    target: Identity
    producer: Identity
    recovery: bool = False
    durable: bool = True
    clean: bool = True
    inactive: bool = True


@dataclass(frozen=True)
class Ready:
    binding: Identity
    request: str
    build: str
    capabilities: bool = True
    recovered: bool = True
    inactive: bool = True


class Model:
    def __init__(self, capacity=8):
        require(capacity > 0, 'history capacity')
        self.disk = dict(installation='installation', generation=0, gate=False,
                         dirty=None, history={}, operation=None, receipt=None,
                         phase='idle', binding=None, build=None, requests=())
        self.capacity = capacity
        self.boot, self.instance, self.session = 'boot-1', 'core-1', 'idle'
        self.sealed = False
        self.resources = False
        self.ready = None
        self.exit = None
        self.observer_lost = False
        self.restart_excluded = False
        self.approved = False
        self.events = []

    def snapshot(self):
        return deepcopy(self.disk)

    def crash(self):
        self.ready = self.exit = None
        self.observer_lost = True
        self.restart_excluded = self.approved = False

    def new_instance(self, boot, instance):
        require((boot, instance) != (self.boot, self.instance), 'same process')
        self.crash()
        self.boot, self.instance, self.session = boot, instance, 'idle'
        self.resources = False  # Empty engine is deliberately not cleanup proof.
        self.sealed = False

    def write(self, label, fault=None, **changes):
        require(fault in (None, 'before', 'after'), 'fault boundary')
        if fault == 'before':
            self.crash()
            raise Crash(label + ':before')
        self.disk.update(deepcopy(changes))
        operation = self.disk['operation']
        if operation is not None:
            self.disk['history'][operation]['phase'] = self.disk['phase']
        self.events.append(label)
        if fault == 'after':
            self.crash()
            raise Crash(label + ':after')

    def root(self, uid):
        require(uid == 0, 'symbolic root required')

    def current(self):
        return Identity(self.disk['installation'], self.disk['operation'] or 'session',
                        self.disk['generation'], self.boot, self.instance, self.session)

    def start(self, legacy=False, fault=None):
        require(not self.disk['gate'] and self.disk['dirty'] is None and
                not self.sealed, 'start fenced')
        target = Identity(self.disk['installation'], 'session',
                          self.disk['generation'], self.boot, self.instance, 'active')
        self.write('dirty-intent', fault, dirty=target)
        self.events.append('symbolic-acquire')
        self.resources, self.session = True, 'active'

    def begin(self, operation, generation, target, build, uid=0, fault=None):
        self.root(uid)
        require(bool(operation) and bool(build), 'explicit request fields')
        request = (generation, target, build)
        prior = self.disk['history'].get(operation)
        if prior is not None:
            require(prior['request'] == request, 'conflicting operation reuse')
            return deepcopy(prior)
        require(len(self.disk['history']) < self.capacity, 'history full')
        require(not self.disk['gate'] and self.disk['phase'] in ('idle', 'released'),
                'unresolved operation')
        require(generation == self.disk['generation'] and target == self.current(),
                'stale target')
        history = deepcopy(self.disk['history'])
        history[operation] = dict(request=request, target=target, phase='gated')
        self.write('gate', fault, gate=True, generation=generation + 1,
                   operation=operation, history=history, phase='gated', build=build,
                   receipt=None, binding=None, requests=())
        self.crash()  # Discard all previous volatile evidence.
        self.observer_lost = False  # Synthetic observer armed for the original target.
        return deepcopy(history[operation])

    def query(self, operation):
        require(operation in self.disk['history'], 'unknown operation')
        return deepcopy(self.disk['history'][operation])

    def target(self):
        require(self.disk['operation'] is not None, 'no maintenance')
        original = self.query(self.disk['operation'])['target']
        return Identity(original.installation, self.disk['operation'],
                        self.disk['generation'], original.boot, original.instance,
                        original.session)

    def shutdown(self, target, uid=0, cleanup=True, fault=None):
        self.root(uid)
        require(self.disk['gate'] and target == self.target(), 'wrong operation')
        require((target.boot, target.instance, target.session) ==
                (self.boot, self.instance, self.session), 'wrong process/session')
        self.sealed = True
        self.events.append('seal')
        self.events.append('cleanup')
        if not cleanup:
            self.write('cleanup-failed', fault, phase='cleanup-blocked')
            return
        receipt = Receipt(target, self.current())
        self.write('cleanup-receipt', fault, receipt=receipt, dirty=None)
        self.resources, self.session = False, 'idle'

    def observe_exit(self, target):
        require(not self.observer_lost, 'lost observer requires reboot')
        require(target == self.target() and (target.boot, target.instance) ==
                (self.boot, self.instance), 'wrong exit')
        self.exit = target

    def exclude_restart(self, uid=0):
        self.root(uid)
        self.restart_excluded = True

    def validate_receipt(self, receipt, recovery=False):
        require(receipt is not None and receipt.target == self.target() and
                receipt.durable and receipt.clean and receipt.inactive,
                'missing/scoped cleanup')
        if recovery:
            require(receipt.recovery and receipt.producer == self.current(),
                    'stale recovery producer')
        else:
            require(receipt.producer == receipt.target, 'wrong cleanup producer')

    def commit(self, uid=0, fault=None):
        self.root(uid)
        require(self.disk['gate'] and self.disk['phase'] == 'gated', 'commit phase')
        self.validate_receipt(self.disk['receipt'])
        require(self.exit == self.target() and self.restart_excluded,
                'exit and restart exclusion independently required')
        self.write('commit', fault, phase='committed')

    def reconcile(self, receipt, binding, uid=0, approved=False, fault=None):
        self.root(uid)
        require(approved and self.disk['gate'] and
                self.disk['phase'] in ('committed', 'release-pending'), 'explicit committed approval')
        self.validate_receipt(receipt, recovery=True)
        previous = self.disk['binding'] or self.target()
        require((self.boot, self.instance) == (previous.boot, previous.instance)
                or self.boot != previous.boot, 'same-boot replacement requires reboot')
        require(binding == self.current(), 'fresh current binding required')
        require(self.restart_excluded, 'restart exclusion required')
        self.ready = None
        self.write('reconcile', fault, receipt=receipt, binding=binding, dirty=None)
        self.approved = True

    def readiness(self, ready, uid=0):
        self.root(uid)
        require(self.approved and self.disk['gate'] and
                self.disk['phase'] in ('committed', 'release-pending'), 'reconcile first')
        require(ready.binding == self.current() == self.disk['binding'] and
                ready.build == self.disk['build'] and ready.capabilities and
                ready.recovered and ready.inactive and bool(ready.request),
                'fresh build/capability readiness required')
        require(ready.request not in self.disk['requests'], 'readiness replay')
        self.validate_receipt(self.disk['receipt'], recovery=True)
        self.write('readiness-request', requests=self.disk['requests'] + (ready.request,))
        self.ready = ready

    def release(self, binding, uid=0, fault=None):
        self.root(uid)
        require(self.approved and self.ready is not None and self.restart_excluded,
                'fresh approval/readiness/exclusion required')
        require(binding == self.current() == self.disk['binding'] == self.ready.binding,
                'release binding mismatch')
        self.validate_receipt(self.disk['receipt'], recovery=True)
        history = deepcopy(self.disk['history'])
        history[self.disk['operation']]['phase'] = 'released'
        self.write('release-result', fault, gate=True, phase='release-pending')
        self.write('release-finalize', gate=False, phase='released', history=history)
        self.sealed = False
        self.ready = None
        # Explicit user start is a separate action; release never acquires resources.

    def expire(self):
        self.crash()  # Expiration invalidates authority, never durable fencing.
