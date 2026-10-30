import unittest
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus,
    AgentBalance
)
from core.engine import RootboundEngine

class TestPhase1SecurityAndArchitecture(unittest.TestCase):
    """
    Phase 1 Verification Test Suite
    Tests the Security Model, Data Model, Hierarchy Invariants,
    Attenuation Rules, and the 4-State Payment Lifecycle.
    """

    def setUp(self):
        self.engine = RootboundEngine()
        self.org_id = "org_hackathon_demo"
        self.admin = "wahab.near"
        self.root_agent_id = "agent_root"
        self.escrow_amount = 1_000_000  # e.g., 1,000,000 units (yoctoNEAR / test units)
        self.expiry_root = 100_000
        self.allowed_recipients_root = {"service_llm.near", "service_storage.near", "service_compute.near"}
        self.max_per_tx_root = 200_000

        # Initialize Organization and Root Agent (Depth 1)
        self.org = self.engine.create_organization(
            org_id=self.org_id,
            admin=self.admin,
            escrow_deposit=self.escrow_amount,
            root_agent_id=self.root_agent_id,
            expires_at=self.expiry_root,
            permitted_recipients=self.allowed_recipients_root,
            max_per_tx=self.max_per_tx_root,
            timestamp=1000
        )

    # =========================================================================
    # Step 1 Tests: Security Model & Invariants
    # =========================================================================

    def test_invariant_1_budget_conservation_on_root_creation(self):
        """Verify that root agent balance satisfies: Allocated == Available + Reserved + Spent"""
        root = self.engine.grants[self.root_agent_id]
        self.assertEqual(root.balance.allocated, self.escrow_amount)
        self.assertEqual(root.balance.available, self.escrow_amount)
        self.assertEqual(root.balance.reserved, 0)
        self.assertEqual(root.balance.spent, 0)
        root.balance.assert_conservation_invariant(self.root_agent_id)
        self.assertTrue(self.engine.verify_global_invariants(self.org_id))

    def test_invariant_2_attenuation_budget_ceiling(self):
        """Child budget cannot exceed parent available budget."""
        child_budget_excessive = self.escrow_amount + 50_000
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_child_greedy",
                child_account="child_pm.near",
                budget=child_budget_excessive,
                expires_at=50_000,
                permitted_recipients={"service_llm.near"},
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY)

    def test_invariant_2_attenuation_recipient_narrowing(self):
        """Child permitted recipients must be a subset of parent permitted recipients."""
        # Attempt to add an unauthorized recipient not in parent's whitelist
        unauthorized_recipients = {"service_llm.near", "attacker_vault.near"}
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_child_bad_recipient",
                child_account="child_pm.near",
                budget=100_000,
                expires_at=50_000,
                permitted_recipients=unauthorized_recipients,
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_RECIPIENT)

    def test_invariant_2_attenuation_expiry_narrowing(self):
        """Child expiry cannot outlive parent expiry."""
        child_expiry_excessive = self.expiry_root + 10_000
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_child_over_expiry",
                child_account="child_pm.near",
                budget=100_000,
                expires_at=child_expiry_excessive,
                permitted_recipients={"service_llm.near"},
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_EXPIRY_EXCEEDS_PARENT)

    def test_invariant_2_attenuation_max_per_tx_narrowing(self):
        """Child per-transaction limit cannot exceed parent limit."""
        excessive_per_tx = self.max_per_tx_root + 10_000
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_child_over_tx",
                child_account="child_pm.near",
                budget=300_000,
                expires_at=50_000,
                permitted_recipients={"service_llm.near"},
                max_per_tx=excessive_per_tx,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_TRANSACTION_LIMIT_EXCEEDED)

    # =========================================================================
    # Step 2 Tests: Hierarchy Depth Ceiling (Max Depth 3) & Immutable Lineage
    # =========================================================================

    def test_invariant_3_hierarchy_depth_ceiling_3_levels(self):
        """
        Enforce Depth 1 (Root) -> Depth 2 (Child) -> Depth 3 (Grandchild).
        Attempting Depth 4 (Great-Grandchild) must strictly fail with ERR_EXCEEDED_MAX_DEPTH.
        """
        # 1. Create Child Agent (Depth 2: PM)
        pm_grant = self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=400_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near", "service_compute.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        self.assertEqual(pm_grant.depth, 2)

        # 2. Create Grandchild Agent (Depth 3: Researcher)
        researcher_grant = self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=150_000,
            expires_at=70_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=50_000,
            timestamp=1000
        )
        self.assertEqual(researcher_grant.depth, 3)

        # 3. Attempt to Create Great-Grandchild Agent (Depth 4: Sub-purchaser) - MUST FAIL!
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="researcher.near",
                org_id=self.org_id,
                parent_agent_id="agent_researcher",
                child_agent_id="agent_great_grandchild",
                child_account="rogue.near",
                budget=50_000,
                expires_at=60_000,
                permitted_recipients={"service_llm.near"},
                max_per_tx=25_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_EXCEEDED_MAX_DEPTH)

    def test_unauthorized_caller_cannot_delegate(self):
        """An arbitrary caller cannot delegate from an agent they do not control."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="attacker.near",
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_unauthorized_spawn",
                child_account="attacker.near",
                budget=50_000,
                expires_at=50_000,
                permitted_recipients={"service_llm.near"},
                max_per_tx=25_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_CALLER)

    # =========================================================================
    # Step 3 Tests: Payment Lifecycle & 4-State Fund Accounting
    # =========================================================================

    def test_payment_lifecycle_success(self):
        """
        Authorize/Reserve -> Asynchronous Transfer -> Settle Success:
        Available -> Reserved -> Spent.
        """
        # Create PM Agent
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.available, 200_000)
        self.assertEqual(pm.balance.reserved, 0)
        self.assertEqual(pm.balance.spent, 0)

        # 1. Authorize & Reserve 60,000
        payment = self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_llm.near",
            amount=60_000,
            request_id="req_001",
            nonce=1,
            timestamp=1500
        )
        self.assertEqual(payment.status, PaymentStatus.RESERVED)
        self.assertEqual(pm.balance.available, 140_000)
        self.assertEqual(pm.balance.reserved, 60_000)
        self.assertEqual(pm.balance.spent, 0)
        pm.balance.assert_conservation_invariant("agent_pm")

        # 2. Finalize Payment as Success (callback from NEAR)
        finalized = self.engine.finalize_payment_success(request_id="req_001", timestamp=2000)
        self.assertEqual(finalized.status, PaymentStatus.FINALIZED)
        self.assertEqual(pm.balance.available, 140_000)
        self.assertEqual(pm.balance.reserved, 0)
        self.assertEqual(pm.balance.spent, 60_000)
        pm.balance.assert_conservation_invariant("agent_pm")

    def test_payment_lifecycle_failure_and_reservation_recovery(self):
        """
        When asynchronous transfer fails, reservation is safely restored:
        Available -> Reserved -> Restored to Available.
        Zero funds locked or lost.
        """
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # 1. Authorize & Reserve 75,000
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_llm.near",
            amount=75_000,
            request_id="req_fail_test",
            nonce=1,
            timestamp=1500
        )
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.available, 125_000)
        self.assertEqual(pm.balance.reserved, 75_000)

        # 2. Callback reports failure (e.g. out of gas or receiver panics)
        failed_record = self.engine.finalize_payment_failure(
            request_id="req_fail_test",
            reason="Receiver contract panicked: insufficient compute units",
            timestamp=2000
        )
        self.assertEqual(failed_record.status, PaymentStatus.FAILED)
        # Verify complete reservation recovery
        self.assertEqual(pm.balance.reserved, 0)
        self.assertEqual(pm.balance.available, 200_000)
        self.assertEqual(pm.balance.spent, 0)
        pm.balance.assert_conservation_invariant("agent_pm")

    def test_anti_replay_and_nonce_monotonicity(self):
        """Replaying an old nonce or skipping sequential nonces must fail."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # Valid initial payment with Nonce 1
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_llm.near",
            amount=10_000,
            request_id="req_1",
            nonce=1,
            timestamp=1200
        )

        # Replay Attack: Re-use Nonce 1
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="service_llm.near",
                amount=10_000,
                request_id="req_replay",
                nonce=1,
                timestamp=1300
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INVALID_NONCE)

        # Out-of-order Nonce: Skip Nonce 2 and submit Nonce 5
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="service_llm.near",
                amount=10_000,
                request_id="req_skip",
                nonce=5,
                timestamp=1300
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INVALID_NONCE)

    def test_cascade_revocation_blocks_descendant_spending(self):
        """
        When a parent agent is revoked, all descendants are automatically blocked
        from spending, even if their individual grant flags were not explicitly toggled.
        """
        # Create PM (Child)
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=300_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        # Create Researcher (Grandchild)
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=100_000,
            expires_at=70_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=50_000,
            timestamp=1000
        )

        # Revoke PM (Parent)
        self.engine.revoke_grant(caller=self.admin, org_id=self.org_id, agent_id="agent_pm", timestamp=2000)
        self.assertTrue(self.engine.grants["agent_pm"].is_revoked)

        # Grandchild attempts payment -> MUST FAIL with ERR_ANCESTOR_REVOKED
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="researcher.near",
                org_id=self.org_id,
                agent_id="agent_researcher",
                recipient="service_llm.near",
                amount=20_000,
                request_id="req_grandchild_after_revocation",
                nonce=1,
                timestamp=2500
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

    def test_pending_payment_settlement_after_revocation(self):
        """
        In-flight payment already reserved before revocation safely resolves
        without breaking balance conservation.
        """
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # 1. Legitimate payment authorized & reserved
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_llm.near",
            amount=50_000,
            request_id="req_in_flight",
            nonce=1,
            timestamp=1200
        )

        # 2. Agent is revoked while transfer is in flight
        self.engine.revoke_grant(caller=self.admin, org_id=self.org_id, agent_id="agent_pm", timestamp=1500)

        # 3. New payments rejected
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="service_llm.near",
                amount=10_000,
                request_id="req_new_after_revocation",
                nonce=2,
                timestamp=1600
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

        # 4. In-flight transfer confirms success: reservation correctly finalizes as spent
        finalized = self.engine.finalize_payment_success(request_id="req_in_flight", timestamp=1800)
        self.assertEqual(finalized.status, PaymentStatus.FINALIZED)
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.reserved, 0)
        self.assertEqual(pm.balance.spent, 50_000)
        pm.balance.assert_conservation_invariant("agent_pm")

    def test_concurrent_reservations_cannot_exceed_available_budget(self):
        """Simultaneous/Multiple payment reservations cannot overdraw available budget."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=100_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        # Reservation 1: 60,000
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_llm.near",
            amount=60_000,
            request_id="req_c1",
            nonce=1,
            timestamp=1100
        )
        # Reservation 2: 40,000 (Uses remaining available)
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_llm.near",
            amount=40_000,
            request_id="req_c2",
            nonce=2,
            timestamp=1150
        )
        # Reservation 3: 1 unit more -> MUST FAIL
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="service_llm.near",
                amount=1,
                request_id="req_c3_overdraw",
                nonce=3,
                timestamp=1200
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET)

    def test_root_revocation_blocks_entire_tree(self):
        """Revoking root agent immediately paralyzes all children and grandchildren."""
        # Setup Depth 1 (Root) -> Depth 2 (PM) -> Depth 3 (Researcher)
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=300_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=100_000,
            expires_at=70_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=50_000,
            timestamp=1000
        )
        # Revoke Root Agent
        self.engine.revoke_grant(caller=self.admin, org_id=self.org_id, agent_id=self.root_agent_id, timestamp=1500)

        # Both PM and Researcher must be blocked
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="service_llm.near",
                amount=10_000,
                request_id="req_pm_fail",
                nonce=1,
                timestamp=1600
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="researcher.near",
                org_id=self.org_id,
                agent_id="agent_researcher",
                recipient="service_llm.near",
                amount=5_000,
                request_id="req_res_fail",
                nonce=1,
                timestamp=1600
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

    def test_full_three_tier_economy_accounting_and_global_invariants(self):
        """
        Simulate a full 3-tier delegation hierarchy with transactions across all tiers:
        Root delegates to PM, PM delegates to Researcher, both execute payments.
        Verify all individual and global conservation invariants.
        """
        # Tier 2 (PM): Budget 400,000
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=400_000,
            expires_at=80_000,
            permitted_recipients={"service_llm.near", "service_compute.near"},
            max_per_tx=150_000,
            timestamp=1000
        )
        # Tier 3 (Researcher): Budget 150,000 from PM
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=150_000,
            expires_at=75_000,
            permitted_recipients={"service_llm.near"},
            max_per_tx=50_000,
            timestamp=1000
        )

        # PM pays 50,000 for compute
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="service_compute.near",
            amount=50_000,
            request_id="pm_pay_1",
            nonce=1,
            timestamp=1200
        )
        self.engine.finalize_payment_success(request_id="pm_pay_1", timestamp=1300)

        # Researcher pays 30,000 for LLM inference
        self.engine.authorize_and_reserve_payment(
            caller="researcher.near",
            org_id=self.org_id,
            agent_id="agent_researcher",
            recipient="service_llm.near",
            amount=30_000,
            request_id="res_pay_1",
            nonce=1,
            timestamp=1400
        )
        self.engine.finalize_payment_success(request_id="res_pay_1", timestamp=1500)

        # Verify PM balances:
        # allocated=400k, delegated=150k (to researcher), spent=50k, reserved=0, available=200k
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.allocated, 400_000)
        self.assertEqual(pm.balance.delegated, 150_000)
        self.assertEqual(pm.balance.spent, 50_000)
        self.assertEqual(pm.balance.available, 200_000)
        pm.balance.assert_conservation_invariant("agent_pm")

        # Verify Researcher balances:
        # allocated=150k, delegated=0, spent=30k, reserved=0, available=120k
        res = self.engine.grants["agent_researcher"]
        self.assertEqual(res.balance.allocated, 150_000)
        self.assertEqual(res.balance.spent, 30_000)
        self.assertEqual(res.balance.available, 120_000)
        res.balance.assert_conservation_invariant("agent_researcher")

        # Verify Root balances:
        # allocated=1M, delegated=400k, spent=0, reserved=0, available=600k
        root = self.engine.grants[self.root_agent_id]
        self.assertEqual(root.balance.allocated, 1_000_000)
        self.assertEqual(root.balance.delegated, 400_000)
        self.assertEqual(root.balance.available, 600_000)
        root.balance.assert_conservation_invariant(self.root_agent_id)

        # Verify Global Invariants across all nodes in the organization
        self.assertTrue(self.engine.verify_global_invariants(self.org_id))

if __name__ == "__main__":
    unittest.main()
