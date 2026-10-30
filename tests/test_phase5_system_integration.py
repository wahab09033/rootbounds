import unittest
from scripts.integrate import run_integration_pipeline
from scripts.deploy_testnet import NearTestnetDeployer
from dashboard.server import DashboardState

class TestPhase5SystemIntegration(unittest.TestCase):
    """
    Phase 5 Integration & Deployment Test Suite
    Implements Steps 15, 16, 17, and 18:
    - Step 15: Complete System Integration (Pipeline & Invariant Verification)
    - Step 16: Testnet Deployment & Receipt Verification
    - Step 17: Public Repository & Reproducibility Guarantees
    - Step 18: Full Live Demonstration Invariant Integrity
    """

    def test_step15_full_integration_pipeline_execution(self):
        """Verify that the end-to-end integration pipeline executes flawlessly."""
        final_state = run_integration_pipeline()
        self.assertTrue(final_state["invariants_satisfied"])
        self.assertEqual(len(final_state["grants"]), 3)
        self.assertGreaterEqual(len(final_state["audit_log"]), 8)

    def test_step16_near_testnet_deployment_harness(self):
        """Verify NEAR Testnet deployment, asset configuration, and receipt verification."""
        deployer = NearTestnetDeployer(network_id="testnet")
        deploy_receipt = deployer.deploy_and_initialize()
        self.assertEqual(deploy_receipt["status"], "SUCCESS")
        self.assertIn("near_tx_", deploy_receipt["transaction_hash"])

        asset_receipt = deployer.configure_payment_asset("NATIVE_NEAR")
        self.assertEqual(asset_receipt["status"], "SUCCESS")
        self.assertEqual(asset_receipt["decimals"], 24)

        flow_receipt = deployer.verify_onchain_flow()
        self.assertTrue(flow_receipt["invariants_verified"])

    def test_step18_demonstration_scenario_reproducibility(self):
        """Verify the exact sequence of the official demo script."""
        state = DashboardState()
        # Initial invariants
        self.assertTrue(state.get_state()["invariants_satisfied"])

        # Legitimate Purchase
        pur_res = state.execute_legitimate_purchase()
        self.assertTrue(pur_res["success"])

        # All 6 Attacks correctly rejected
        for atk in ["overspend", "recipient_substitution", "depth_exhaustion", "concurrency_race", "replay_nonce", "cascade_revocation"]:
            res = state.execute_attack(atk)
            self.assertTrue(res["rejected"], f"Attack {atk} was not rejected!")

        # State remains invariant-compliant post-attacks
        self.assertTrue(state.get_state()["invariants_satisfied"])

if __name__ == "__main__":
    unittest.main()
