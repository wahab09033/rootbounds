import unittest
from core.types import (
    ErrorCode,
    PaymentStatus
)
from dashboard.server import DashboardState

class TestPhase4EconomyAndDashboard(unittest.TestCase):
    """
    Phase 4 Verification Test Suite
    Implements Steps 12, 13, and 14:
    - Step 12: Autonomous Agent Economy (PM, Researcher, Purchasing workflow)
    - Step 13: Dashboard State Engine (Hierarchy tree, 5-state balances, audit trail)
    - Step 14: Interactive Attack Simulator Engine (6 distinct attack scenarios)
    """

    def setUp(self):
        self.state = DashboardState()

    # =========================================================================
    # Step 12: Agent Economy
    # =========================================================================
    def test_step12_economy_bootstrapping_and_hierarchy(self):
        """Verify autonomous agent setup across 3 levels (Root -> PM -> Researcher)."""
        data = self.state.get_state()
        self.assertEqual(data["organization"]["id"], "org_rootbound_enterprise")
        self.assertEqual(len(data["grants"]), 3)

        root = next(g for g in data["grants"] if g["depth"] == 1)
        pm = next(g for g in data["grants"] if g["depth"] == 2)
        res = next(g for g in data["grants"] if g["depth"] == 3)

        self.assertEqual(root["agent_id"], "root_treasury")
        self.assertEqual(pm["agent_id"], "agent_pm")
        self.assertEqual(res["agent_id"], "agent_researcher")

        # Invariant: Root allocated 1M, PM allocated 500k, Res allocated 200k
        self.assertEqual(root["allocated"], 1_000_000)
        self.assertEqual(pm["allocated"], 500_000)
        self.assertEqual(res["allocated"], 200_000)
        self.assertTrue(data["invariants_satisfied"])

    def test_step12_legitimate_purchase_flow(self):
        """Verify legitimate multi-agent task execution and payment settlement."""
        res = self.state.execute_legitimate_purchase()
        self.assertTrue(res["success"])

        data = self.state.get_state()
        pm = next(g for g in data["grants"] if g["agent_id"] == "agent_pm")
        researcher = next(g for g in data["grants"] if g["agent_id"] == "agent_researcher")

        # PM spent 15,000 on compute
        self.assertEqual(pm["spent"], 15_000)
        # Researcher spent 8,000 on inference
        self.assertEqual(researcher["spent"], 8_000)

        self.assertTrue(data["invariants_satisfied"])
        self.assertTrue(any("LEGITIMATE_PURCHASE" in log["event_type"] for log in data["audit_log"]))

    # =========================================================================
    # Step 13: Dashboard State & Audit Ledger
    # =========================================================================
    def test_step13_dashboard_state_serialization(self):
        """Verify dashboard state contains inspectable NEAR links and 5-state balances."""
        data = self.state.get_state()
        self.assertIn("organization", data)
        self.assertIn("grants", data)
        self.assertIn("payments", data)
        self.assertIn("audit_log", data)
        self.assertTrue(data["invariants_satisfied"])

        for log in data["audit_log"]:
            self.assertIn("explorer_url", log)
            self.assertTrue(log["explorer_url"].startswith("https://testnet.nearblocks.io/txns/"))

    # =========================================================================
    # Step 14: Interactive Attack Simulator Triggers
    # =========================================================================
    def test_step14_attack_overspending_simulation(self):
        """Attack Simulator: Budget overspending attack is rejected on-chain."""
        res = self.state.execute_attack("overspend")
        self.assertTrue(res["success"])
        self.assertTrue(res["rejected"])
        self.assertEqual(res["error_code"], ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET.value)

        # Audit ledger updated with structured rejection code
        data = self.state.get_state()
        latest_audit = data["audit_log"][0]
        self.assertEqual(latest_audit["outcome"], "REJECTED")
        self.assertEqual(latest_audit["error_code"], ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET.value)

    def test_step14_attack_recipient_substitution_simulation(self):
        """Attack Simulator: Unauthorized recipient substitution attack is rejected."""
        res = self.state.execute_attack("recipient_substitution")
        self.assertTrue(res["success"])
        self.assertTrue(res["rejected"])
        self.assertEqual(res["error_code"], ErrorCode.ERR_UNAUTHORIZED_RECIPIENT.value)

    def test_step14_attack_depth_exhaustion_simulation(self):
        """Attack Simulator: Depth limit breach (Depth 4) is rejected."""
        res = self.state.execute_attack("depth_exhaustion")
        self.assertTrue(res["success"])
        self.assertTrue(res["rejected"])
        self.assertEqual(res["error_code"], ErrorCode.ERR_EXCEEDED_MAX_DEPTH.value)

    def test_step14_attack_replay_nonce_simulation(self):
        """Attack Simulator: Nonce replay attack is rejected."""
        res = self.state.execute_attack("replay_nonce")
        self.assertTrue(res["success"])
        self.assertTrue(res["rejected"])
        self.assertEqual(res["error_code"], ErrorCode.ERR_INVALID_NONCE.value)

    def test_step14_attack_cascade_revocation_simulation(self):
        """Attack Simulator: Cascade revocation blocks descendant spend."""
        res = self.state.execute_attack("cascade_revocation")
        self.assertTrue(res["success"])
        self.assertTrue(res["rejected"])
        self.assertEqual(res["error_code"], ErrorCode.ERR_ANCESTOR_REVOKED.value)

    def test_step14_attack_concurrency_race_simulation(self):
        """Attack Simulator: Concurrent race condition double-spend is rejected."""
        res = self.state.execute_attack("concurrency_race")
        self.assertTrue(res["success"])
        self.assertTrue(res["rejected"])
        self.assertEqual(res["error_code"], ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET.value)

    def test_step14_dashboard_reset_functionality(self):
        """Verify dashboard reset returns treasury and hierarchy to pristine state."""
        # Mutate state with purchases and attacks
        self.state.execute_legitimate_purchase()
        self.state.execute_attack("cascade_revocation")
        
        # Reset
        self.state.reset()
        data = self.state.get_state()
        self.assertTrue(data["invariants_satisfied"])
        pm = next(g for g in data["grants"] if g["agent_id"] == "agent_pm")
        self.assertFalse(pm["is_revoked"])
        self.assertEqual(pm["spent"], 0)

if __name__ == "__main__":
    unittest.main()
