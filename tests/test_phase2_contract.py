import unittest
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus,
    AgentBalance,
    Organization,
    DelegationGrant,
    PaymentRecord
)
from core.engine import RootboundEngine

class TestPhase2SmartContractAndSecurity(unittest.TestCase):
    """
    Phase 2 Verification Test Suite
    Thoroughly tests Smart Contract & Core Security requirements:
    - Step 4: Organization & Escrow Management
    - Step 5: Delegation Management (Depth 3 Ceiling, Immutable Lineage)
    - Step 6: Policy Engine (Narrowing & Attenuation)
    - Step 7: Budget Reservation & Accounting (5-State Balance Conservation)
    - Step 8: Revocation & Authorization Security (Anti-Replay, Structured Errors)
    """

    def setUp(self):
        self.engine = RootboundEngine()
        self.org_id = "org_enterprise"
        self.admin = "admin.near"
        self.root_agent_id = "agent_root"
        self.initial_deposit = 2_000_000
        self.root_expiry = 200_000
        self.allowed_recipients = {
            "api_near_intents.near",
            "api_openpipe.near",
            "compute_shade.near",
            "compute_phala.near"
        }
        self.root_max_per_tx = 500_000

        self.org = self.engine.create_organization(
            org_id=self.org_id,
            admin=self.admin,
            escrow_deposit=self.initial_deposit,
            root_agent_id=self.root_agent_id,
            expires_at=self.root_expiry,
            permitted_recipients=self.allowed_recipients,
            max_per_tx=self.root_max_per_tx,
            timestamp=1000
        )

    # =========================================================================
    # Step 4: Organization and Escrow Management
    # =========================================================================

    def test_step4_organization_creation_and_accounting(self):
        """Verify organization setup, escrow custody, and root grant balance."""
        org = self.engine.organizations[self.org_id]
        self.assertEqual(org.id, self.org_id)
        self.assertEqual(org.admin, self.admin)
        self.assertEqual(org.escrow_balance, self.initial_deposit)

        root = self.engine.grants[self.root_agent_id]
        self.assertEqual(root.balance.allocated, self.initial_deposit)
        self.assertEqual(root.balance.available, self.initial_deposit)
        self.assertEqual(root.balance.delegated, 0)
        self.assertEqual(root.balance.reserved, 0)
        self.assertEqual(root.balance.spent, 0)
        root.balance.assert_conservation_invariant(self.root_agent_id)

    def test_step4_escrow_deposit_increments_budget(self):
        """Verify escrow deposit adds to treasury and root available balance."""
        deposit_amount = 500_000
        new_balance = self.engine.deposit_escrow(self.org_id, deposit_amount, caller=self.admin)
        self.assertEqual(new_balance, 2_500_000)

        root = self.engine.grants[self.root_agent_id]
        self.assertEqual(root.balance.allocated, 2_500_000)
        self.assertEqual(root.balance.available, 2_500_000)
        root.balance.assert_conservation_invariant(self.root_agent_id)

    def test_step4_unauthorized_deposit_rejected(self):
        """Only the organization admin can deposit escrow funds."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.deposit_escrow(self.org_id, 100_000, caller="stranger.near")
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_CALLER)

    def test_step4_authorized_escrow_withdrawal(self):
        """Admin can withdraw uncommitted available funds from escrow."""
        withdraw_amount = 400_000
        remaining_escrow = self.engine.withdraw_escrow(self.org_id, withdraw_amount, caller=self.admin)
        self.assertEqual(remaining_escrow, 1_600_000)

        root = self.engine.grants[self.root_agent_id]
        self.assertEqual(root.balance.allocated, 1_600_000)
        self.assertEqual(root.balance.available, 1_600_000)
        root.balance.assert_conservation_invariant(self.root_agent_id)

    def test_step4_unauthorized_withdrawal_rejected(self):
        """Non-admin callers cannot withdraw escrow funds."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.withdraw_escrow(self.org_id, 100_000, caller="attacker.near")
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_CALLER)

    def test_step4_withdrawal_cannot_exceed_available_escrow(self):
        """Cannot withdraw funds that are delegated or reserved."""
        # Delegate 1,500,000 to PM (Leaves 500,000 available in root)
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=1_500_000,
            expires_at=150_000,
            permitted_recipients=self.allowed_recipients,
            max_per_tx=200_000,
            timestamp=1000
        )
        root = self.engine.grants[self.root_agent_id]
        self.assertEqual(root.balance.available, 500_000)

        # Attempt to withdraw 600,000 -> MUST FAIL with ERR_WITHDRAWAL_EXCEEDS_AVAILABLE
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.withdraw_escrow(self.org_id, 600_000, caller=self.admin)
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_WITHDRAWAL_EXCEEDS_AVAILABLE)

    # =========================================================================
    # Step 5: Delegation Management
    # =========================================================================

    def test_step5_complete_three_tier_delegation(self):
        """Verify successful creation of Depth 1 -> Depth 2 -> Depth 3 agents."""
        # Tier 2: Child PM Agent
        pm_grant = self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=800_000,
            expires_at=150_000,
            permitted_recipients={"api_near_intents.near", "compute_shade.near"},
            max_per_tx=200_000,
            timestamp=1000
        )
        self.assertEqual(pm_grant.depth, 2)
        self.assertEqual(pm_grant.parent_agent_id, self.root_agent_id)

        # Tier 3: Grandchild Researcher Agent
        res_grant = self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=300_000,
            expires_at=120_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        self.assertEqual(res_grant.depth, 3)
        self.assertEqual(res_grant.parent_agent_id, "agent_pm")

        # Invariant: PM delegated balance is updated to 300,000
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.delegated, 300_000)
        self.assertEqual(pm.balance.available, 500_000)
        pm.balance.assert_conservation_invariant("agent_pm")

    def test_step5_depth_4_strictly_rejected(self):
        """Grandchild (Depth 3) cannot spawn Depth 4 (Great-grandchild)."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=800_000,
            expires_at=150_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=200_000,
            timestamp=1000
        )
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=300_000,
            expires_at=120_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        # Attempt Depth 4 spawn
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="researcher.near",
                org_id=self.org_id,
                parent_agent_id="agent_researcher",
                child_agent_id="agent_purchaser_depth4",
                child_account="purchaser.near",
                budget=50_000,
                expires_at=100_000,
                permitted_recipients={"compute_shade.near"},
                max_per_tx=25_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_EXCEEDED_MAX_DEPTH)

    def test_step5_unauthorized_caller_cannot_delegate(self):
        """Only the designated agent account or organization admin can create child grants."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller="rogue_agent.near",
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_injected",
                child_account="rogue.near",
                budget=100_000,
                expires_at=100_000,
                permitted_recipients={"compute_shade.near"},
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_CALLER)

    # =========================================================================
    # Step 6: Policy Engine
    # =========================================================================

    def test_step6_budget_narrowing_enforced(self):
        """Child budget cannot exceed parent available authority."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_greedy",
                child_account="greedy.near",
                budget=self.initial_deposit + 1,
                expires_at=100_000,
                permitted_recipients={"compute_shade.near"},
                max_per_tx=100_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY)

    def test_step6_recipient_narrowing_enforced(self):
        """Child permitted recipients must be a subset of parent permitted recipients."""
        disallowed_recipients = {"compute_shade.near", "malicious_drainer.near"}
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_bad_recipients",
                child_account="bad.near",
                budget=100_000,
                expires_at=100_000,
                permitted_recipients=disallowed_recipients,
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_UNAUTHORIZED_RECIPIENT)

    def test_step6_expiry_narrowing_enforced(self):
        """Child grant expiry cannot outlive parent expiry."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=self.root_agent_id,
                child_agent_id="agent_over_expiry",
                child_account="exp.near",
                budget=100_000,
                expires_at=self.root_expiry + 1,
                permitted_recipients={"compute_shade.near"},
                max_per_tx=50_000,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_EXPIRY_EXCEEDS_PARENT)

    # =========================================================================
    # Step 7: Budget Reservation and Accounting
    # =========================================================================

    def test_step7_atomic_reservation_and_concurrency_lock(self):
        """
        Reserve funds atomically before dispatching.
        Prevent concurrent requests from double-spending the same available balance.
        """
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=150_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=150_000,
            timestamp=1000
        )
        # Reservation 1: 120,000
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="compute_shade.near",
            amount=120_000,
            request_id="req_res_1",
            nonce=1,
            timestamp=1100
        )
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.available, 80_000)
        self.assertEqual(pm.balance.reserved, 120_000)

        # Concurrent Request: Attempting 100,000 when only 80,000 available -> REJECTED
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="compute_shade.near",
                amount=100_000,
                request_id="req_res_concurrent_overspend",
                nonce=2,
                timestamp=1150
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET)

    def test_step7_safe_failure_recovery_without_locking_funds(self):
        """Confirmed failed transfer restores funds to available. Zero fund deadlocks."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=150_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=150_000,
            timestamp=1000
        )
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="compute_shade.near",
            amount=100_000,
            request_id="req_to_fail",
            nonce=1,
            timestamp=1100
        )
        pm = self.engine.grants["agent_pm"]
        self.assertEqual(pm.balance.reserved, 100_000)
        self.assertEqual(pm.balance.available, 100_000)

        # Finalize Failure
        self.engine.finalize_payment_failure(
            request_id="req_to_fail",
            reason="NEAR Cross-contract transfer failed: Account does not exist",
            timestamp=1200
        )
        self.assertEqual(pm.balance.reserved, 0)
        self.assertEqual(pm.balance.available, 200_000)
        self.assertEqual(pm.balance.spent, 0)
        pm.balance.assert_conservation_invariant("agent_pm")

    # =========================================================================
    # Step 8: Revocation and Authorization Security
    # =========================================================================

    def test_step8_cascade_revocation_and_descendant_rejection(self):
        """Revoking an ancestor immediately rejects future spending through any descendant."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=600_000,
            expires_at=150_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=200_000,
            timestamp=1000
        )
        self.engine.create_delegation_grant(
            caller="pm.near",
            org_id=self.org_id,
            parent_agent_id="agent_pm",
            child_agent_id="agent_researcher",
            child_account="researcher.near",
            budget=200_000,
            expires_at=120_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=100_000,
            timestamp=1000
        )

        # Admin revokes Child PM
        self.engine.revoke_grant(caller=self.admin, org_id=self.org_id, agent_id="agent_pm", timestamp=2000)
        self.assertFalse(self.engine.is_ancestor_chain_valid("agent_researcher"))

        # Grandchild payment authorization MUST fail
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="researcher.near",
                org_id=self.org_id,
                agent_id="agent_researcher",
                recipient="compute_shade.near",
                amount=50_000,
                request_id="req_grandchild_blocked",
                nonce=1,
                timestamp=2100
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

    def test_step8_anti_replay_and_duplicate_callback_protection(self):
        """Prevent replaying payment nonces and duplicate callback finalization."""
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=self.root_agent_id,
            child_agent_id="agent_pm",
            child_account="pm.near",
            budget=200_000,
            expires_at=150_000,
            permitted_recipients={"compute_shade.near"},
            max_per_tx=100_000,
            timestamp=1000
        )
        # Payment 1 with Nonce 1
        self.engine.authorize_and_reserve_payment(
            caller="pm.near",
            org_id=self.org_id,
            agent_id="agent_pm",
            recipient="compute_shade.near",
            amount=50_000,
            request_id="req_uniq_1",
            nonce=1,
            timestamp=1100
        )
        # Duplicate Request ID rejection
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.authorize_and_reserve_payment(
                caller="pm.near",
                org_id=self.org_id,
                agent_id="agent_pm",
                recipient="compute_shade.near",
                amount=50_000,
                request_id="req_uniq_1",
                nonce=2,
                timestamp=1150
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_DUPLICATE_REQUEST)

        # Finalize Success
        self.engine.finalize_payment_success(request_id="req_uniq_1", timestamp=1200)

        # Duplicate Callback processing rejection (Cannot re-finalize or refund already finalized payment)
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.finalize_payment_success(request_id="req_uniq_1", timestamp=1250)
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INVALID_PAYMENT_STATE)

        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.finalize_payment_failure(request_id="req_uniq_1", reason="late revert", timestamp=1250)
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_INVALID_PAYMENT_STATE)

    def test_step4_duplicate_root_agent_rejected(self):
        """Cannot create a second organization with an existing root agent ID."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_organization(
                org_id="org_duplicate_root_test",
                admin=self.admin,
                escrow_deposit=100_000,
                root_agent_id=self.root_agent_id, # Already in grants!
                expires_at=self.root_expiry,
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_DUPLICATE_REQUEST)

    def test_step4_expired_root_creation_rejected(self):
        """Creating an organization with past expiry must be rejected."""
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.create_organization(
                org_id="org_expired_root",
                admin=self.admin,
                escrow_deposit=100_000,
                root_agent_id="agent_root_expired",
                expires_at=500, # Before timestamp 1000!
                timestamp=1000
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_GRANT_EXPIRED)

    def test_step4_inactive_org_operations_rejected(self):
        """Depositing or withdrawing from an inactive organization is rejected."""
        self.engine.organizations[self.org_id].is_active = False
        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.deposit_escrow(self.org_id, 100_000, caller=self.admin)
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

        with self.assertRaises(RootboundSecurityException) as ctx:
            self.engine.withdraw_escrow(self.org_id, 100_000, caller=self.admin)
        self.assertEqual(ctx.exception.code, ErrorCode.ERR_ANCESTOR_REVOKED)

    def test_step7_full_mathematical_escrow_reconciliation(self):
        """Verify strict mathematical escrow reconciliation across tree."""
        self.assertTrue(self.engine.verify_global_invariants(self.org_id))

if __name__ == "__main__":
    unittest.main()
