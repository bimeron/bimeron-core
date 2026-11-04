import unittest
from dataclasses import replace
from model import Blocked, Crash, Model, Ready, Receipt


class ContractTests(unittest.TestCase):
    def blocked(self, action):
        with self.assertRaises(Blocked):
            action()

    def gated(self, active=False, capacity=8):
        m = Model(capacity)
        if active:
            m.start()
        m.begin('op', 0, m.current(), 'build-2')
        return m

    def committed(self):
        m = self.gated(True)
        target = m.target()
        m.shutdown(target)
        m.observe_exit(target)
        m.exclude_restart()
        m.commit()
        return m

    def reconcile(self, m):
        receipt = Receipt(m.target(), m.current(), recovery=True)
        m.exclude_restart()
        m.reconcile(receipt, m.current(), approved=True)
        return receipt

    def test_gate_precedes_maintenance_and_blocks_both_start_paths(self):
        for legacy in (False, True):
            m = self.gated()
            self.assertEqual(m.events, ['gate'])
            self.blocked(lambda: m.start(legacy=legacy))

    def test_dirty_intent_crashes_before_and_after_acquire(self):
        for boundary in ('before', 'after'):
            m = Model()
            with self.assertRaises(Crash):
                m.start(fault=boundary)
            self.assertFalse(m.resources)
            self.assertNotIn('symbolic-acquire', m.events)
            if boundary == 'after':
                m.new_instance('boot-2', 'core-2')
                self.blocked(m.start)
            else:
                m.start()
                self.assertLess(m.events.index('dirty-intent'),
                                m.events.index('symbolic-acquire'))

    def test_gate_write_crash_boundaries(self):
        for boundary in ('before', 'after'):
            m = Model()
            with self.assertRaises(Crash):
                m.begin('op', 0, m.current(), 'build', fault=boundary)
            self.assertEqual(m.disk['gate'], boundary == 'after')
            if boundary == 'after':
                self.blocked(m.start)

    def test_shutdown_rejects_every_identity_mismatch(self):
        m = self.gated(True)
        t = m.target()
        for field in t.__dataclass_fields__:
            bad = replace(t, **{field: 99 if field == 'generation' else 'wrong'})
            self.blocked(lambda: m.shutdown(bad))
        self.blocked(lambda: m.shutdown(t, uid=501))
        self.assertNotIn('cleanup', m.events)

    def test_cleanup_failure_seals_before_stop_and_expiry_never_unlocks(self):
        m = self.gated(True)
        m.shutdown(m.target(), cleanup=False)
        self.assertLess(m.events.index('seal'), m.events.index('cleanup'))
        self.assertTrue(m.sealed)
        self.assertIsNone(m.disk['receipt'])
        m.expire()
        self.blocked(m.start)
        self.blocked(m.commit)

    def test_exit_never_implies_receipt_and_restart_exclusion_is_independent(self):
        m = self.gated()
        m.observe_exit(m.target())
        m.exclude_restart()
        self.blocked(m.commit)
        m.shutdown(m.target())
        m.crash()
        self.blocked(m.commit)
        self.blocked(lambda: m.observe_exit(m.target()))
        m.exclude_restart()
        self.blocked(m.commit)

    def test_receipt_durability_and_scope(self):
        for field, value in (('durable', False), ('clean', False), ('inactive', False)):
            m = self.gated()
            m.shutdown(m.target())
            m.disk['receipt'] = replace(m.disk['receipt'], **{field: value})
            m.observe_exit(m.target())
            m.exclude_restart()
            self.blocked(m.commit)
        for boundary in ('before', 'after'):
            m = self.gated()
            with self.assertRaises(Crash):
                m.shutdown(m.target(), fault=boundary)
            self.assertEqual(m.disk['receipt'] is not None, boundary == 'after')
            self.blocked(m.commit)

    def test_committed_reboot_requires_approval_current_recovery_binding_and_readiness(self):
        m = self.committed()
        old = m.current()
        m.new_instance('boot-2', 'core-2')
        self.blocked(m.start)
        receipt = Receipt(m.target(), m.current(), recovery=True)
        m.exclude_restart()
        self.blocked(lambda: m.reconcile(receipt, m.current()))
        self.blocked(lambda: m.reconcile(receipt, m.current(), uid=501, approved=True))
        for bad in (replace(receipt, producer=old), replace(receipt, target=old),
                    replace(receipt, recovery=False), replace(receipt, durable=False)):
            self.blocked(lambda: m.reconcile(bad, m.current(), approved=True))
        self.blocked(lambda: m.reconcile(receipt, old, approved=True))
        m.reconcile(receipt, m.current(), approved=True)
        self.blocked(lambda: m.release(m.current()))
        ready = Ready(m.current(), 'fresh', 'build-2')
        for bad in (replace(ready, build='old'), replace(ready, capabilities=False),
                    replace(ready, recovered=False), replace(ready, inactive=False),
                    replace(ready, binding=old)):
            self.blocked(lambda: m.readiness(bad))
        m.readiness(ready)
        self.blocked(lambda: m.release(old))
        m.release(m.current())
        self.assertFalse(m.resources)
        self.assertEqual(m.session, 'idle')
        m.start()

    def test_new_instance_invalidates_old_readiness_and_recovery_producer(self):
        m = self.committed()
        r = self.reconcile(m)
        ready = Ready(m.current(), 'once', 'build-2')
        m.readiness(ready)
        self.blocked(lambda: m.readiness(ready))
        m.new_instance(m.boot, 'replacement')
        self.blocked(lambda: m.release(m.current()))
        m.exclude_restart()
        self.blocked(lambda: m.reconcile(r, m.current(), approved=True))
        self.blocked(lambda: self.reconcile(m))
        m.new_instance('boot-2', 'recovery')
        self.reconcile(m)
        self.blocked(lambda: m.readiness(ready))
        m.readiness(Ready(m.current(), 'new', 'build-2'))
        m.release(m.current())
        self.assertFalse(m.resources)

    def test_committed_reconciliation_retry_keeps_artifacts_and_refreshes_readiness(self):
        m = self.committed()
        self.reconcile(m)
        old = Ready(m.current(), 'old', 'build-2')
        m.readiness(old)
        m.crash()
        self.blocked(lambda: m.release(m.current()))
        self.reconcile(m)
        self.blocked(lambda: m.readiness(old))
        m.readiness(Ready(m.current(), 'fresh', 'build-2'))
        m.release(m.current())
        self.assertEqual(m.disk['generation'], 1)
        self.assertEqual(m.disk['build'], 'build-2')
        self.assertFalse(m.resources)

    def test_same_boot_replacement_after_recovery_also_requires_another_reboot(self):
        m = self.committed()
        m.new_instance('boot-2', 'recovery-1')
        self.reconcile(m)
        m.new_instance('boot-2', 'recovery-2')
        self.blocked(lambda: self.reconcile(m))
        m.new_instance('boot-3', 'recovery-3')
        self.reconcile(m)
        m.readiness(Ready(m.current(), 'fresh', 'build-2'))
        m.release(m.current())

    def test_exact_duplicate_queries_conflicts_and_capacity_preserve_history(self):
        m = self.gated(capacity=1)
        entry = m.query('op')
        generation, target, build = entry['request']
        snapshot = m.snapshot()
        self.assertEqual(m.begin('op', generation, target, build), entry)
        self.assertEqual(m.snapshot(), snapshot)
        self.blocked(lambda: m.begin('op', generation, target, 'conflict'))
        self.blocked(lambda: m.begin('new', m.disk['generation'], m.current(), build))
        m.shutdown(m.target())
        m.observe_exit(m.target())
        m.exclude_restart()
        m.commit()
        self.reconcile(m)
        m.readiness(Ready(m.current(), 'ready', 'build-2'))
        m.release(m.current())
        self.blocked(lambda: m.begin('new', m.disk['generation'], m.current(), build))
        self.assertEqual(m.begin('op', generation, target, build)['phase'], 'released')
        self.assertEqual(len(m.disk['history']), 1)

    def test_root_required_at_all_symbolic_mutation_boundaries(self):
        m = Model()
        self.blocked(lambda: m.begin('op', 0, m.current(), 'b', uid=501))
        m = self.committed()
        self.blocked(lambda: m.exclude_restart(uid=501))
        self.blocked(lambda: m.commit(uid=501))
        self.reconcile(m)
        self.blocked(lambda: m.readiness(Ready(m.current(), 'r', 'build-2'), uid=501))
        self.blocked(lambda: m.release(m.current(), uid=501))

    def test_commit_reconcile_and_release_crash_boundaries(self):
        for boundary in ('before', 'after'):
            m = self.gated()
            m.shutdown(m.target())
            m.observe_exit(m.target())
            m.exclude_restart()
            with self.assertRaises(Crash):
                m.commit(fault=boundary)
            self.blocked(m.start)
            m = self.committed()
            receipt = Receipt(m.target(), m.current(), recovery=True)
            m.exclude_restart()
            with self.assertRaises(Crash):
                m.reconcile(receipt, m.current(), approved=True, fault=boundary)
            self.blocked(lambda: m.release(m.current()))
            self.blocked(m.start)
            m = self.committed()
            self.reconcile(m)
            m.readiness(Ready(m.current(), 'r', 'build-2'))
            with self.assertRaises(Crash):
                m.release(m.current(), fault=boundary)
            self.assertFalse(m.resources)
            self.assertTrue(m.disk['gate'])
            m.new_instance('boot-2', 'core-2')
            self.blocked(m.start)
            self.reconcile(m)
            m.readiness(Ready(m.current(), 'post-crash', 'build-2'))
            m.release(m.current())
            self.assertFalse(m.disk['gate'])


if __name__ == '__main__':
    unittest.main()
