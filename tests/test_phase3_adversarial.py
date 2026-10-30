import unittest
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus,
    AgentBalance
)
from core.engine import RootboundEngine
from core.async_payment_engine import AsyncPaymentEngine, TransferOutcome

class TestPhase3AdversarialAndInvariants(unittest.TestCase):
    """
    Phase 3 Adversarial Test Suite
    Implements Step 10 & Step 11:
    1. Root budget overspending attack
    2. Child budget escalation attack
    3. Unauthorized recipient substitution attack
    4. Simultaneous payment requests (Race condition / Concurrency)
    5. Expired grants attack
    6. Revocation of parents and descendants attack
    7. Replayed requests and duplicate callbacks exploit
    8. Failed transfers and reservation recovery (No fund leakage)
    9. Maximum delegation depth and excessive child creation
    10. Complete invariant verification (Budget conservation, non-expansion, state consistency)
    """

    def setUp(self):
        self.engine = RootboundEngine()
        self.async_engine = AsyncPaymentEngine(self.engine)
        self.org_id = "org_adversarial_suite"
        self.admin = "sec_officer.near"
        self.root_agent_id = "root_vault"
        self.root_budget = 1_000_000
        self.root_expiry = 500_000
        self.allowed_recipients = {
            "vendor_compute_1.near",
            "vendor_compute_2.near",
            "vendor_llm_inference.near",
            "vendor_vector_db.near"
        }
        self.root_max_tx = 300_000

        self.engine.create_organization(
            org_id=self.org_id,
            admin=self.admin,
            escrow_deposit=self.root_budget,
            root_agent_id=self.root_agent_id,
            expires_at=self.root_expiry,
            permitted_recipients=self.allowed_recipients,
            max_per_tx=self.root_max_tx,
            timestamp=1000
        )

    # -------------------------------------------------------------------------
    # Attack 1: Root Budget Overspending Attack
    # -------------------------------------------------------------------------
    def test_attack_01_root_budget_overspending(self):
        """Attacker attempts to pay or withdraw more than root escrow authority."""
        # 1. Direct payment exceeding root available
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller=self.admin,
                org_id=self.org_id,
                agent_id=self.root_agent_id,
                recipient="vendor_compute_1.near",
                amount=self.root_budget + 1,
                request_id="atk_overspend_1",
                nonce=1,
                timestamp=1100
            )
        # Should fail either on transaction limit or insufficient available budget
        self.assertIn(ctx.exception.code, [ErrorCode.ERR_TRANSACTION_LIMIT_EXCEEDED, ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET])

        # 2. Cumulative payments attempting to breach budget
        # Request 1: 300,000 (Success)
        self.engine.authorize_and_reserve_payment(
            caller=self.admin,
            org_id=self.org_id,
            agent_id=self.root_agent_id,
            recipient="vendor_compute_1.near",
            amount=300_000,
            request_id="atk_overspend_2",
            nonce=1,
            timestamp=1100
        )
        self.engine.finalize_payment_success("atk_overspend_2", timestamp=1200)

        # Request 2: 300,000 (Success)
        self.engine.authorize_and_reserve_payment(
            caller=self.admin,
            org_id=self.org_id,
            agent_id=self.root_agent_id,
            recipient="vendor_compute_1.near",
            amount=300_000,
            request_id="atk_overspend_3",
            nonce=2,
            timestamp=1300
        )
        self.engine.finalize_payment_success("atk_overspend_3", timestamp=1400)

        # Request 3: 300,000 (Success, 100,000 remains available)
        self.engine.authorize_and_reserve_payment(
            caller=self.admin,
            org_id=self.org_id,
            agent_id=self.root_agent_id,
            recipient="vendor_compute_1.near",
            amount=300_000,
            request_id="atk_overspend_4",
            nonce=3,
            timestamp=1500
        )
        self.engine.finalize_payment_success("atk_overspend_4", timestamp=1600)

        # Request 4: Attempt 150,000 (Only 100,000 available -> MUST REJECT)
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller=self.admin,
                org_id=self.org_id,
                agent_id=self.root_agent_id,
                recipient="vendor_compute_1.near",
                amount=150_000,
                request_id="atk_overspend_breach",
                nonce=4,
                timestamp=1700
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET)
        self.assertTrue(self.engine.verify_global_invariants(self.org_id))

    # -------------------------------------------------------------------------
    # Attack 2: Child Budget Escalation Attack
    # -------------------------------------------------------------------------
    def test_attack_02_child_budget_escalation(self):
        """Attacker child agent attempts to allocate or spend more than authorized by parent."""
        # Parent PM given 200,000
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # PM attempts to spawn Researcher with 250,000 (escalation attempt) -> REJECTED
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="pm.near",
                org_id=self.org_id,
                parent_agent_id="agent_pm",
                child_agent_id="agent_researcher_greedy",
                child_account="res.near",
                budget=250_000,
                expires_at=350_000,
                permitted_recipients={"vendor_compute_1.near"},
                max_per_tx=50_000,
                timestamp=1100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY)

    # -------------------------------------------------------------------------
    # Attack 3: Unauthorized Recipient Substitution Attack (Prompt Injection)
    # -------------------------------------------------------------------------
    def test_attack_03_unauthorized_recipient_substitution(self):
        """Compromised LLM attempts to divert funds to an unauthorized address."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=400_000,
            permitted_recipients={"vendor_llm_inference.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # Prompt injected: agent attempts to pay "attacker_drain_wallet.near"
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="attacker_drain_wallet.near",
                amount=50_000,
                request_id="atk_substitute_recipient",
                nonce=1,
                timestamp=1100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_RECIPIENT)

    # -------------------------------------------------------------------------
    # Attack 4: Simultaneous / Race-Condition Payment Requests
    # -------------------------------------------------------------------------
    def test_attack_04_simultaneous_spending_attempts(self):
        """Concurrent requests attempting to consume the same available balance simultaneously."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=100_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # Dispatch async request 1 for 70,000 (Available drops to 30,000; Reserved = 70,000)
        p1 = self.async_engine.dispatch_payment_async(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="vendor_compute_1.near",
            amount=70_000,
            request_id="race_req_1",
            nonce=1,
            intended_outcome=TransferOutcome.SUCCESS,
            timestamp=1100
        )
        self.assertIn("promise_race_req_1", self.async_engine.promise_queue)

        # Concurrent Request 2 attempts to spend 60,000 while Request 1 is still in flight -> REJECTED
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.async_engine.dispatch_payment_async(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="vendor_compute_1.near",
                amount=60_000,
                request_id="race_req_2_overdraw",
                nonce=2,
                intended_outcome=TransferOutcome.SUCCESS,
                timestamp=1110
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET)

        # Now settle request 1 successfully
        self.async_engine.settle_promise(p1.promise_id, timestamp=1200)
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.spent, 70_000)
        self.assertEqual(pm.balance.available, 30_000)
        self.assertEqual(pm.balance.reserved, 0)
        pm.balance.assert_conservation_invariant("agent_pm")

    # -------------------------------------------------------------------------
    # Attack 5: Expired Grant Payment Attack
    # -------------------------------------------------------------------------
    def test_attack_05_expired_grant_payment_rejected(self):
        """Attacker attempts to authorize payment after grant expiry timestamp."""
        expiry_time = 2000
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=100_000,
            expires_at=expiry_time,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=50_000,
            timestamp=1000
        )

        # Payment at timestamp 2500 (after expiry)
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="vendor_compute_1.near",
                amount=20_000,
                request_id="atk_expired",
                nonce=1,
                timestamp=2500
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_GRANT_EXPIRED)

    # -------------------------------------------------------------------------
    # Attack 6: Parent and Descendant Cascade Revocation Attack
    # -------------------------------------------------------------------------
    def test_attack_06_revocation_of_parents_and_descendants(self):
        """Revoking an ancestor instantly blocks the entire downstream hierarchy."""
        # Tier 2 (PM)
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=300_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        # Tier 3 (Researcher)
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="res.near",
            budget=100_000,
            expires_at=350_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=50_000,
            timestamp=1000
        )

        # Revoke PM
        self.engine.revoke_grant(caller=self.admin, org_id=self.org_id, agent_id="agent_pm", timestamp=2000)

        # Attempt spend from Researcher (Must be blocked by ancestor check)
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="res.near",
                org_id=self.org_id,
                agent_id="agent_researcher",
                recipient="vendor_compute_1.near",
                amount=10_000,
                request_id="atk_revoked_ancestor",
                nonce=1,
                timestamp=2100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

    # -------------------------------------------------------------------------
    # Attack 7: Replay Attacks and Duplicate Callback Processing
    # -------------------------------------------------------------------------
    def test_attack_07_replay_and_duplicate_callback_attacks(self):
        """Attacker replays payment nonce or triggers duplicated callback execution."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=100_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=50_000,
            timestamp=1000
        )

        # Legitimate Payment
        p = self.async_engine.dispatch_payment_async(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="vendor_compute_1.near",
            amount=20_000,
            request_id="legit_req_1",
            nonce=1,
            timestamp=1100
        )
        self.async_engine.settle_promise(p.promise_id, timestamp=1200)

        # Replay Attack 1: Re-use Nonce 1
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="vendor_compute_1.near",
                amount=20_000,
                request_id="replay_nonce_1",
                nonce=1,
                timestamp=1300
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INVALID_NONCE)

        # Duplicate Callback Attack: Attempting to call callback again on finalized payment
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.finalize_payment_success("legit_req_1", timestamp=1400)
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INVALID_PAYMENT_STATE)

    # -------------------------------------------------------------------------
    # Attack 8: Failed Transfers and Reservation Recovery (Zero Fund Leak)
    # -------------------------------------------------------------------------
    def test_attack_08_failed_transfers_and_reservation_recovery(self):
        """
        Simulate all asynchronous NEAR failure modes:
        RECEIVER_PANIC, OUT_OF_GAS, ACCOUNT_NOT_FOUND.
        Verify that all reservations recover perfectly to Available with zero funds locked.
        """
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=300_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=150_000,
            timestamp=1000
        )

        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.available, 300_000)

        # Failure Case A: Receiver Contract Panicked
        p_panic = self.async_engine.dispatch_payment_async(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="vendor_compute_1.near",
            amount=50_000,
            request_id="fail_panic",
            nonce=1,
            intended_outcome=TransferOutcome.RECEIVER_PANIC,
            timestamp=1100
        )
        self.assertEqual(pm.balance.available, 250_000)
        self.assertEqual(pm.balance.reserved, 50_000)

        # Settle Panic
        self.async_engine.settle_promise(p_panic.promise_id, timestamp=1200)
        # Balance restored!
        self.assertEqual(pm.balance.available, 300_000)
        self.assertEqual(pm.balance.reserved, 0)
        self.assertEqual(pm.balance.spent, 0)

        # Failure Case B: Out Of Gas
        p_gas = self.async_engine.dispatch_payment_async(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="vendor_compute_1.near",
            amount=80_000,
            request_id="fail_gas",
            nonce=2,
            intended_outcome=TransferOutcome.OUT_OF_GAS,
            timestamp=1300
        )
        self.async_engine.settle_promise(p_gas.promise_id, timestamp=1400)
        self.assertEqual(pm.balance.available, 300_000)
        self.assertEqual(pm.balance.reserved, 0)

        # Failure Case C: Account Not Found
        p_acct = self.async_engine.dispatch_payment_async(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="vendor_compute_1.near",
            amount=100_000,
            request_id="fail_acct",
            nonce=3,
            intended_outcome=TransferOutcome.ACCOUNT_NOT_FOUND,
            timestamp=1500
        )
        self.async_engine.settle_promise(p_acct.promise_id, timestamp=1600)
        self.assertEqual(pm.balance.available, 300_000)
        self.assertEqual(pm.balance.reserved, 0)

        pm.balance.assert_conservation_invariant("agent_pm")
        self.assertTrue(self.engine.verify_global_invariants(self.org_id))

    # -------------------------------------------------------------------------
    # Attack 9: Maximum Delegation Depth and Excessive Child Creation
    # -------------------------------------------------------------------------
    def test_attack_09_max_depth_and_excessive_child_creation(self):
        """
        Verify:
        1. Capped at Depth 3 (Depth 4 rejected).
        2. Attempting to create multiple child grants exceeding parent's remaining budget is rejected.
        """
        # Create PM (Depth 2, budget 500,000)
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=500_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=150_000,
            timestamp=1000
        )

        # Child 1 from PM: 300,000
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_res_1",
            child_account="res1.near",
            budget=300_000,
            expires_at=350_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        # PM available balance is now 200,000

        # Excessive Child Creation: Attempting to spawn Child 2 with 250,000 (exceeds remaining 200,000)
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="pm.near",
                org_id=self.org_id,
                parent_agent_id="agent_pm",
                child_agent_id="agent_res_2_excessive",
                child_account="res2.near",
                budget=250_000,
                expires_at=350_000,
                permitted_recipients={"vendor_compute_1.near"},
                max_per_tx=100_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY)

        # Depth 4 attack from res_1
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="res1.near",
                org_id=self.org_id,
                parent_agent_id="agent_res_1",
                child_agent_id="agent_depth_4",
                child_account="d4.near",
                budget=50_000,
                expires_at=300_000,
                permitted_recipients={"vendor_compute_1.near"},
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_EXCEEDED_MAX_DEPTH)

    # -------------------------------------------------------------------------
    # Step 11: Security Invariants Verification
    # -------------------------------------------------------------------------
    def test_step11_global_security_invariants_verification(self):
        """
        Comprehensive mathematical invariant verification across a multi-agent branch:
        1. Total spending cannot exceed root escrow.
        2. Reserved funds cannot be spent twice.
        3. Descendants cannot expand permissions.
        4. Revoked grants cannot authorize payments.
        5. Payment state transitions remain strictly valid.
        """
        # Complex multi-step economy setup:
        # Root (1M) -> PM (500k) -> Researcher (200k)
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=500_000,
            expires_at=400_000,
            permitted_recipients=self.allowed_recipients,
            max_per_tx=200_000,
            timestamp=1000
        )
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="res.near",
            budget=200_000,
            expires_at=350_000,
            permitted_recipients={"vendor_vector_db.near", "vendor_llm_inference.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # PM spends 150k on compute_1
        p_pm = self.async_engine.dispatch_payment_async(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="vendor_compute_1.near",
            amount=150_000,
            request_id="pm_tx_1",
            nonce=1,
            timestamp=1100
        )
        self.async_engine.settle_promise(p_pm.promise_id, timestamp=1200)

        # Researcher spends 80k on vector_db
        p_res = self.async_engine.dispatch_payment_async(
            caller="res.near",
            org_id=self.org_id,
            agent_id="agent_researcher",
            recipient="vendor_vector_db.near",
            amount=80_000,
            request_id="res_tx_1",
            nonce=1,
            timestamp=1300
        )
        self.async_engine.settle_promise(p_res.promise_id, timestamp=1400)

        # Invariant 1: Total Escrow Reconciled
        # Total funds across all nodes strictly equals 1,000,000
        total_spent = sum(g.balance.spent for g in self.engine.grants.values())
        self.assertEqual(total_spent, 230_000)

        root = self.engine.grants[self.root_agent_id]
        pm = self.engine.grants["agent_pm"]
        res = self.engine.grants["agent_researcher"]

        self.assertEqual(root.balance.allocated, 1_000_000)
        self.assertEqual(root.balance.delegated, 500_000)
        self.assertEqual(root.balance.available, 500_000)

        self.assertEqual(pm.balance.allocated, 500_000)
        self.assertEqual(pm.balance.delegated, 200_000)
        self.assertEqual(pm.balance.spent, 150_000)
        self.assertEqual(pm.balance.available, 150_000)

        self.assertEqual(res.balance.allocated, 200_000)
        self.assertEqual(res.balance.delegated, 0)
        self.assertEqual(res.balance.spent, 80_000)
        self.assertEqual(res.balance.available, 120_000)

        # Assert individual and global conservation invariants
        root.balance.assert_conservation_invariant(self.root_agent_id)
        pm.balance.assert_conservation_invariant("agent_pm")
        res.balance.assert_conservation_invariant("agent_researcher")
        self.assertTrue(self.engine.verify_global_invariants(self.org_id))

    # -------------------------------------------------------------------------
    # Attack 11: Cross-Tenant Delegation Exploit
    # -------------------------------------------------------------------------
    def test_attack_11_cross_tenant_delegation(self):
        """Attacker admin of Org 2 attempts to delegate from Org 1's PM agent."""
        # 1. Create legitimate PM in Org 1
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="org1_pm",
            child_account="org1_pm.near",
            budget=400_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # 2. Attacker creates Org 2
        self.engine.create_organization(
            org_id="org_attacker_tenant",
            admin="attacker.near",
            escrow_deposit=100_000,
            root_agent_id="attacker_root",
            expires_at=500_000,
            timestamp=1000
        )

        # 3. Attacker tries to steal Org 1's PM budget into Org 2
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="attacker.near",
                org_id="org_attacker_tenant",
                parent_agent_id="org1_pm",
                child_agent_id="stolen_child",
                child_account="attacker.near",
                budget=200_000,
                expires_at=350_000,
                timestamp=1100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_CALLER)

    # -------------------------------------------------------------------------
    # Attack 12: Cross-Tenant Revocation Exploit
    # -------------------------------------------------------------------------
    def test_attack_12_cross_tenant_revocation(self):
        """Attacker admin of Org 2 attempts to revoke an agent in Org 1."""
        self.engine.create_organization(
            org_id="org_attacker_tenant_2",
            admin="attacker_2.near",
            escrow_deposit=100_000,
            root_agent_id="attacker_root_2",
            expires_at=500_000,
            timestamp=1000
        )

        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.revoke_grant(
                caller="attacker_2.near",
                org_id="org_attacker_tenant_2",
                agent_id=self.root_agent_id,
                timestamp=1100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_CALLER)

    # -------------------------------------------------------------------------
    # Attack 13: Inactive Organization Freeze Exploit
    # -------------------------------------------------------------------------
    def test_attack_13_inactive_org_blocks_payments(self):
        """When an organization is deactivated, all descendant operations are frozen."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="active_pm",
            child_account="active_pm.near",
            budget=300_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # Admin deactivates organization
        self.engine.set_organization_active(self.admin, self.org_id, False)

        # Spend attempt should now fail with ERR_ANCESTOR_REVOKED
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="active_pm.near",
                org_id=self.org_id,
                agent_id="active_pm",
                recipient="vendor_compute_1.near",
                amount=10_000,
                request_id="req_inactive_1",
                nonce=1,
                timestamp=1100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

    # -------------------------------------------------------------------------
    # Feature 14: Fund Reclamation Lifecycle
    # -------------------------------------------------------------------------
    def test_feature_fund_reclamation(self):
        """Parent successfully reclaims uncommitted available funds from child."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="reclaim_pm",
            child_account="reclaim_pm.near",
            budget=400_000,
            expires_at=400_000,
            permitted_recipients={"vendor_compute_1.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        root_before = self.engine.grants[self.root_agent_id]
        self.assertEqual(root_before.balance.available, 600_000)
        self.assertEqual(root_before.balance.delegated, 400_000)

        # Root reclaims 150_000 from reclaim_pm
        self.engine.reclaim_delegated_funds(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="reclaim_pm",
            amount=150_000,
            timestamp=1100
        )

        root_after = self.engine.grants[self.root_agent_id]
        pm_after = self.engine.grants["reclaim_pm"]

        self.assertEqual(root_after.balance.available, 750_000)
        self.assertEqual(root_after.balance.delegated, 250_000)
        self.assertEqual(pm_after.balance.available, 250_000)
        self.assertEqual(pm_after.balance.allocated, 250_000)

        # Invariant check
        root_after.balance.assert_conservation_invariant(self.root_agent_id)
        pm_after.balance.assert_conservation_invariant("reclaim_pm")

    # -------------------------------------------------------------------------
    # Feature 15: Escrow Withdrawal Asynchronous Recovery
    # -------------------------------------------------------------------------
    def test_feature_withdrawal_failure_recovery(self):
        """Failed withdrawal restores funds from reserved back to available."""
        root = self.engine.grants[self.root_agent_id]
        avail_before = root.balance.available

        # Reserve 100_000 for withdrawal
        self.engine.reserve_withdrawal(self.org_id, 100_000, self.admin)
        self.assertEqual(root.balance.available, avail_before - 100_000)
        self.assertEqual(root.balance.reserved, 100_000)

        # Simulate failed cross-contract withdrawal transfer -> Recovery
        self.engine.finalize_withdrawal_failure(self.org_id, 100_000)
        self.assertEqual(root.balance.available, avail_before)
        self.assertEqual(root.balance.reserved, 0)
        root.balance.assert_conservation_invariant(self.root_agent_id)

if __name__ == "__main__":
    unittest.main()
