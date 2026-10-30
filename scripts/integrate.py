"""
ROOTBOUND — System Integration & End-to-End Orchestrator
Connects smart contract, autonomous agents, and dashboard state.
"""

import sys
import os
import json
from typing import Dict, Any

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.types import ErrorCode, PaymentStatus
from core.engine import RootboundEngine
from core.async_payment_engine import AsyncPaymentEngine
from agents.economy import AgentEconomyCoordinator
from dashboard.server import DashboardState

def run_integration_pipeline() -> Dict[str, Any]:
    print("=" * 70)
    print("ROOTBOUND: System Integration Pipeline Running")
    print("=" * 70)

    # 1. Initialize Dashboard State & Contract State Machine
    state = DashboardState()
    print("[1/5] Contract and 3-Tier Multi-Agent Hierarchy Initialized.")

    # 2. Verify Initial State
    initial_data = state.get_state()
    assert initial_data["invariants_satisfied"], "Initial invariants broken!"
    assert len(initial_data["grants"]) == 3, "Expected 3 agent tiers!"
    print(f"      - Org ID: {initial_data['organization']['id']}")
    print(f"      - Escrow Treasury: {initial_data['organization']['escrow_balance']:,} yoctoNEAR")
    print("      - Hierarchy: Root (Depth 1) -> PM (Depth 2) -> Researcher (Depth 3)")

    # 3. Execute Legitimate Multi-Agent Purchases
    print("\n[2/5] Executing Legitimate Multi-Tier Agent Purchases...")
    purchase_res = state.execute_legitimate_purchase()
    assert purchase_res["success"], f"Purchase flow failed: {purchase_res}"
    print("      [OK] PM purchased decentralized compute (15,000 yoctoNEAR).")
    print("      [OK] Researcher purchased LLM inference (8,000 yoctoNEAR).")

    # 4. Verify 5-State Balances Post-Purchase
    data_after_purchase = state.get_state()
    pm_grant = next(g for g in data_after_purchase["grants"] if g["agent_id"] == "agent_pm")
    res_grant = next(g for g in data_after_purchase["grants"] if g["agent_id"] == "agent_researcher")
    print(f"      - PM Balance: Available={pm_grant['available']:,}, Spent={pm_grant['spent']:,}, Delegated={pm_grant['delegated']:,}")
    print(f"      - Researcher Balance: Available={res_grant['available']:,}, Spent={res_grant['spent']:,}")
    assert data_after_purchase["invariants_satisfied"], "Post-purchase invariants violated!"

    # 5. Execute Adversarial Attack Suite Against System
    print("\n[3/5] Firing Adversarial Attacks Through Policy Engine...")
    attacks = [
        ("overspend", ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET),
        ("recipient_substitution", ErrorCode.ERR_UNAUTHORIZED_RECIPIENT),
        ("depth_exhaustion", ErrorCode.ERR_EXCEEDED_MAX_DEPTH),
        ("concurrency_race", ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET),
        ("replay_nonce", ErrorCode.ERR_INVALID_NONCE),
        ("cascade_revocation", ErrorCode.ERR_ANCESTOR_REVOKED)
    ]

    for atk_name, expected_err in attacks:
        res = state.execute_attack(atk_name)
        assert res["success"] and res["rejected"], f"Attack {atk_name} was not rejected!"
        assert res["error_code"] == expected_err.value, f"Expected {expected_err.value}, got {res['error_code']}"
        print(f"      [DEFENDED] Attack '{atk_name}' -> Blocked with {res['error_code']}")

    # 6. Verify System State Consistency Post-Attack
    print("\n[4/5] Verifying Global Invariants & State Synchronization Post-Attacks...")
    final_data = state.get_state()
    assert final_data["invariants_satisfied"], "Invariants compromised post-attacks!"
    print("      [OK] Conservation Invariant Holds: Allocated == Available + Delegated + Reserved + Spent")
    print(f"      - Audit Log Entries Generated: {len(final_data['audit_log'])}")

    print("\n[5/5] System Integration Successfully Verified!")
    print("=" * 70)
    return final_data

if __name__ == "__main__":
    run_integration_pipeline()
