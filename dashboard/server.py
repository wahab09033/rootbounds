import json
import os
import sys
import time

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus
)
from core.engine import RootboundEngine
from core.async_payment_engine import AsyncPaymentEngine, TransferOutcome
from agents.economy import AgentEconomyCoordinator

class DashboardState:
    def __init__(self, clean: bool = False):
        self.reset(clean=clean)

    def reset(self, clean: bool = False):
        self.engine = RootboundEngine()
        self.async_engine = AsyncPaymentEngine(self.engine)
        self.org_id = "org_rootbound_enterprise"
        self.admin = "admin.near"
        self.coordinator = AgentEconomyCoordinator(
            self.engine, self.async_engine, self.org_id, self.admin
        )
        self.whitelisted_vendors = {
            "vendor_shade_compute.near",
            "vendor_phala_inference.near",
            "vendor_vector_db.near"
        }
        self.audit_log: List[Dict[str, Any]] = []

        if clean:
            # Pure clean state: only root treasury, zero mock child agents, zero mock payments, zero mock spend
            self.engine.create_organization(
                org_id=self.org_id,
                admin=self.admin,
                escrow_deposit=1_000_000,
                root_agent_id="root_treasury",
                expires_at=500_000,
                timestamp=1000
            )
            self.pm = None
            self.researcher = None
            self.log_event("INITIALIZATION", "Organization and Root Treasury vault initialized with 1,000,000 yoctoNEAR.", "SUCCESS")
            return

        # Bootstrap Economy with standard 3-tier agents for tests
        self.coordinator.bootstrap_economy(
            root_agent_id="root_treasury",
            escrow_deposit=1_000_000,
            whitelisted_vendors=self.whitelisted_vendors,
            root_expiry=500_000,
            timestamp=1000
        )
        # Spawn PM (Depth 2, budget 500,000)
        self.pm = self.coordinator.spawn_pm_agent(
            root_agent_id="root_treasury",
            pm_agent_id="agent_pm",
            pm_account="pm.near",
            budget=500_000,
            whitelisted_vendors=self.whitelisted_vendors,
            timestamp=1000
        )
        # Spawn Researcher (Depth 3, budget 200,000)
        self.researcher = self.coordinator.spawn_researcher_agent(
            pm=self.pm,
            res_agent_id="agent_researcher",
            res_account="researcher.near",
            budget=200_000,
            whitelisted_vendors={"vendor_phala_inference.near", "vendor_vector_db.near"},
            timestamp=1000
        )
        self.log_event("INITIALIZATION", "Organization and 3-tier agent hierarchy bootstrapped successfully.", "SUCCESS")

    def log_event(self, event_type: str, details: str, outcome: str, error_code: str = None, tx_id: str = None):
        self.audit_log.insert(0, {
            "timestamp": len(self.audit_log) + 1,
            "event_type": event_type,
            "details": details,
            "outcome": outcome,
            "error_code": error_code,
            "tx_id": tx_id or f"tx_near_{len(self.audit_log)+1:04d}",
            "explorer_url": f"https://testnet.nearblocks.io/txns/{tx_id or f'tx_near_{len(self.audit_log)+1:04d}'}"
        })

    def get_state(self) -> Dict[str, Any]:
        org = self.engine.organizations.get(self.org_id)
        grants_data = []
        for gid, g in sorted(self.engine.grants.items(), key=lambda x: x[1].depth):
            grants_data.append({
                "agent_id": g.agent_id,
                "account": g.agent_account,
                "depth": g.depth,
                "parent_id": g.parent_agent_id,
                "allocated": g.balance.allocated,
                "available": g.balance.available,
                "delegated": g.balance.delegated,
                "reserved": g.balance.reserved,
                "spent": g.balance.spent,
                "permitted_recipients": list(g.permitted_recipients) if g.permitted_recipients else None,
                "max_per_tx": g.max_per_tx,
                "expires_at": g.expires_at,
                "nonce": g.nonce,
                "is_revoked": g.is_revoked,
            })

        payments_data = []
        for pid, p in self.engine.payments.items():
            payments_data.append({
                "request_id": p.request_id,
                "agent_id": p.agent_id,
                "recipient": p.recipient,
                "amount": p.amount,
                "status": p.status.value,
                "nonce": p.nonce,
                "failure_reason": p.failure_reason,
            })

        invariants_ok = True
        try:
            self.engine.verify_global_invariants(self.org_id)
        except Exception:
            invariants_ok = False

        return {
            "organization": {
                "id": org.id,
                "admin": org.admin,
                "escrow_balance": org.escrow_balance,
                "is_active": org.is_active
            },
            "grants": grants_data,
            "payments": payments_data,
            "invariants_satisfied": invariants_ok,
            "audit_log": self.audit_log[:25]
        }

    def ensure_test_agents(self):
        if not hasattr(self, "pm") or self.pm is None or "agent_pm" not in self.engine.grants:
            self.pm = self.coordinator.spawn_pm_agent(
                root_agent_id="root_treasury",
                pm_agent_id="agent_pm",
                pm_account="pm.near",
                budget=500_000,
                whitelisted_vendors=self.whitelisted_vendors,
                timestamp=1000
            )
            self.researcher = self.coordinator.spawn_researcher_agent(
                pm=self.pm,
                res_agent_id="agent_researcher",
                res_account="researcher.near",
                budget=200_000,
                whitelisted_vendors={"vendor_phala_inference.near", "vendor_vector_db.near"},
                timestamp=1000
            )

    def execute_legitimate_purchase(self) -> Dict[str, Any]:
        try:
            self.ensure_test_agents()
            req_id_1 = f"req_legit_pm_{len(self.engine.payments)+1}"
            self.pm.request_service_payment(
                recipient="vendor_shade_compute.near",
                amount=15_000,
                request_id=req_id_1,
                timestamp=1000 + len(self.audit_log)
            )
            self.log_event("LEGITIMATE_PURCHASE", "PM purchased Shade Compute (15,000 yoctoNEAR)", "SUCCESS", tx_id=req_id_1)

            req_id_2 = f"req_legit_res_{len(self.engine.payments)+1}"
            self.researcher.request_service_payment(
                recipient="vendor_phala_inference.near",
                amount=8_000,
                request_id=req_id_2,
                timestamp=1010 + len(self.audit_log)
            )
            self.log_event("LEGITIMATE_PURCHASE", "Researcher purchased Phala LLM Inference (8,000 yoctoNEAR)", "SUCCESS", tx_id=req_id_2)

            return {"success": True, "message": "Legitimate multi-agent purchases executed successfully on-chain."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_attack(self, attack_type: str) -> Dict[str, Any]:
        """Executes an attack against contract policies to demonstrate guaranteed onchain rejection."""
        try:
            self.ensure_test_agents()
            if attack_type == "overspend":
                # Attempt to spend more than available
                pm_grant = self.pm.get_grant()
                amount_excess = pm_grant.balance.available + 50_000
                self.engine.authorize_and_reserve_payment(
                    caller=self.pm.account_id,
                    org_id=self.org_id,
                    agent_id=self.pm.agent_id,
                    recipient="vendor_shade_compute.near",
                    amount=amount_excess,
                    request_id=f"atk_over_{len(self.audit_log)}",
                    nonce=pm_grant.nonce + 1,
                    timestamp=2000
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            elif attack_type == "recipient_substitution":
                # Attempt to divert funds to unauthorized recipient
                pm_grant = self.pm.get_grant()
                self.engine.authorize_and_reserve_payment(
                    caller=self.pm.account_id,
                    org_id=self.org_id,
                    agent_id=self.pm.agent_id,
                    recipient="unauthorized_hacker_drain.near",
                    amount=10_000,
                    request_id=f"atk_rec_{len(self.audit_log)}",
                    nonce=pm_grant.nonce + 1,
                    timestamp=2000
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            elif attack_type == "depth_exhaustion":
                # Researcher (Depth 3) attempts to spawn Depth 4
                self.engine.create_delegation_grant(
                    caller=self.researcher.account_id,
                    org_id=self.org_id,
                    parent_agent_id=self.researcher.agent_id,
                    child_agent_id=f"rogue_depth_4_{len(self.audit_log)}",
                    child_account="rogue.near",
                    budget=10_000,
                    expires_at=200_000,
                    permitted_recipients={"vendor_phala_inference.near"},
                    max_per_tx=5_000,
                    timestamp=2000
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            elif attack_type == "replay_nonce":
                # Ensure a payment has occurred first so a valid nonce is in used_nonces
                if self.pm.get_grant().nonce == 0:
                    self.pm.request_service_payment(
                        recipient="vendor_shade_compute.near",
                        amount=1_000,
                        request_id=f"legit_pre_replay_{len(self.audit_log)}",
                        timestamp=2000
                    )
                # Replay the already-used nonce
                stale_nonce = self.pm.get_grant().nonce
                self.engine.authorize_and_reserve_payment(
                    caller=self.pm.account_id,
                    org_id=self.org_id,
                    agent_id=self.pm.agent_id,
                    recipient="vendor_shade_compute.near",
                    amount=1_000,
                    request_id=f"atk_rep_{len(self.audit_log)}",
                    nonce=stale_nonce,
                    timestamp=2010
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            elif attack_type == "cascade_revocation":
                # Revoke PM, then attempt spend from Researcher
                self.engine.revoke_grant(self.admin, self.org_id, "agent_pm", timestamp=2000)
                self.log_event("POLICY_REVOCATION", "PM Grant revoked by Admin. Descendant branch paralyzed.", "ENFORCED")
                
                res_grant = self.researcher.get_grant()
                self.engine.authorize_and_reserve_payment(
                    caller=self.researcher.account_id,
                    org_id=self.org_id,
                    agent_id=self.researcher.agent_id,
                    recipient="vendor_phala_inference.near",
                    amount=5_000,
                    request_id=f"atk_rev_{len(self.audit_log)}",
                    nonce=res_grant.nonce + 1,
                    timestamp=2050
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            elif attack_type == "concurrency_race":
                # Two payments competing for remaining balance
                avail = self.pm.get_grant().balance.available
                half = (avail // 2) + 10_000
                
                # First reservation takes > half
                p1 = self.async_engine.dispatch_payment_async(
                    caller=self.pm.account_id,
                    org_id=self.org_id,
                    agent_id=self.pm.agent_id,
                    recipient="vendor_shade_compute.near",
                    amount=half,
                    request_id=f"race_1_{len(self.audit_log)}",
                    nonce=self.pm.get_grant().nonce + 1,
                    timestamp=2000
                )
                try:
                    # Second concurrent request tries to also take half with next sequential nonce -> REJECTED
                    self.async_engine.dispatch_payment_async(
                        caller=self.pm.account_id,
                        org_id=self.org_id,
                        agent_id=self.pm.agent_id,
                        recipient="vendor_shade_compute.near",
                        amount=half,
                        request_id=f"race_2_{len(self.audit_log)}",
                        nonce=self.pm.get_grant().nonce + 1,
                        timestamp=2001
                    )
                    return {"success": False, "error": "Attack succeeded unexpectedly!"}
                finally:
                    # Clean up first in-flight promise so balance does not stay permanently locked in Reserved
                    if p1.promise_id in self.async_engine.promise_queue:
                        self.async_engine.settle_promise(p1.promise_id, timestamp=2005)

            elif attack_type == "cross_org_delegation":
                # Rogue admin attempts to delegate from this org's PM agent into their own rogue org
                if "org_rogue_adversary" not in self.engine.organizations:
                    self.engine.create_organization(
                        org_id="org_rogue_adversary",
                        admin="attacker.near",
                        escrow_deposit=100_000,
                        root_agent_id="root_rogue",
                        expires_at=500_000,
                        timestamp=2000
                    )
                self.engine.create_delegation_grant(
                    caller="attacker.near",
                    org_id="org_rogue_adversary",
                    parent_agent_id="agent_pm", # Belongs to org_rootbound_enterprise!
                    child_agent_id="agent_stolen",
                    child_account="attacker.near",
                    budget=50_000,
                    expires_at=300_000,
                    timestamp=2000
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            elif attack_type == "cross_org_revocation":
                # Rogue admin attempts to revoke this org's PM agent
                if "org_rogue_adversary_2" not in self.engine.organizations:
                    self.engine.create_organization(
                        org_id="org_rogue_adversary_2",
                        admin="attacker_2.near",
                        escrow_deposit=100_000,
                        root_agent_id="root_rogue_2",
                        expires_at=500_000,
                        timestamp=2000
                    )
                self.engine.revoke_grant(
                    caller="attacker_2.near",
                    org_id="org_rogue_adversary_2",
                    agent_id="agent_pm", # Belongs to org_rootbound_enterprise!
                    timestamp=2000
                )
                return {"success": False, "error": "Attack succeeded unexpectedly!"}

            else:
                return {"success": False, "error": f"Unknown attack type {attack_type}"}

        except RootboundSecurityException as sec_err:
            self.log_event(
                f"ATTACK_REJECTED [{attack_type.upper()}]",
                f"Contract intercepted attack: {sec_err.message}",
                "REJECTED",
                error_code=sec_err.code.value
            )
            return {
                "success": True,
                "rejected": True,
                "error_code": sec_err.code.value,
                "message": sec_err.message
            }

    def execute_revocation(self, agent_id: str) -> Dict[str, Any]:
        try:
            now = 1000 + len(self.audit_log)
            self.engine.revoke_grant(self.admin, self.org_id, agent_id, timestamp=now)
            self.log_event("POLICY_REVOCATION", f"Agent {agent_id} grant revoked by Admin.", "SUCCESS")
            return {"success": True, "message": f"Agent {agent_id} successfully revoked."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_reclaim(self, parent_agent_id: str, child_agent_id: str, amount: int) -> Dict[str, Any]:
        try:
            now = 1000 + len(self.audit_log)
            self.engine.reclaim_delegated_funds(self.admin, self.org_id, parent_agent_id, child_agent_id, amount, timestamp=now)
            self.log_event("FUND_RECLAMATION", f"Reclaimed {amount:,} yoctoNEAR from {child_agent_id} back to {parent_agent_id}.", "SUCCESS")
            return {"success": True, "message": f"Successfully reclaimed {amount:,} to {parent_agent_id}."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_create_agent(
        self,
        parent_agent_id: str,
        child_agent_id: str,
        child_account: str,
        budget: int,
        permitted_recipients: Any = None,
        max_per_tx: Any = None,
        expires_at: Any = None
    ) -> Dict[str, Any]:
        try:
            parent = self.engine.grants.get(parent_agent_id)
            if not parent:
                return {"success": False, "error": f"Parent agent {parent_agent_id} not found."}

            now = 1000 + len(self.audit_log)
            exp = int(expires_at) if (expires_at and int(expires_at) > now and int(expires_at) <= parent.expires_at) else parent.expires_at
            recipients_set = set(permitted_recipients) if (permitted_recipients and len(permitted_recipients) > 0) else (
                parent.permitted_recipients.copy() if parent.permitted_recipients else None
            )
            limit = int(max_per_tx) if (max_per_tx and int(max_per_tx) > 0) else parent.max_per_tx

            grant = self.engine.create_delegation_grant(
                caller=self.admin,
                org_id=self.org_id,
                parent_agent_id=parent_agent_id,
                child_agent_id=child_agent_id,
                child_account=child_account,
                budget=budget,
                expires_at=exp,
                permitted_recipients=recipients_set,
                max_per_tx=limit,
                timestamp=now
            )
            self.log_event("AGENT_DEPLOYED", f"Created agent {child_agent_id} (Depth {grant.depth}) under {parent_agent_id} with budget {budget:,} yoctoNEAR.", "SUCCESS")
            return {"success": True, "message": f"Agent {child_agent_id} successfully deployed.", "agent_id": child_agent_id}
        except RootboundSecurityException as sec_err:
            self.log_event(f"DEPLOYMENT_REJECTED", f"Policy prevented grant creation: {sec_err.message}", "REJECTED", error_code=sec_err.code.value)
            return {"success": False, "error": sec_err.message, "error_code": sec_err.code.value}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_custom_payment(
        self,
        agent_id: str,
        recipient: str,
        amount: int,
        request_id: Any = None
    ) -> Dict[str, Any]:
        try:
            grant = self.engine.grants.get(agent_id)
            if not grant:
                return {"success": False, "error": f"Agent {agent_id} not found."}

            now = 1000 + len(self.audit_log)
            req_id = request_id if request_id else f"req_{agent_id}_{now}_{grant.nonce + 1}"
            promise = self.async_engine.dispatch_payment_async(
                caller=grant.agent_account,
                org_id=self.org_id,
                agent_id=agent_id,
                recipient=recipient,
                amount=amount,
                request_id=req_id,
                nonce=grant.nonce + 1,
                timestamp=now
            )
            # Settle callback on NEAR
            self.async_engine.settle_promise(promise.promise_id, timestamp=now + 1)
            self.log_event("PAYMENT_SETTLED", f"Agent {agent_id} transferred {amount:,} yoctoNEAR to {recipient}.", "SUCCESS", tx_id=req_id)
            return {"success": True, "message": f"Payment {req_id} settled successfully.", "tx_id": req_id}
        except RootboundSecurityException as sec_err:
            self.log_event(f"PAYMENT_REJECTED", f"Policy intercepted spend: {sec_err.message}", "REJECTED", error_code=sec_err.code.value)
            return {"success": False, "rejected": True, "error": sec_err.message, "error_code": sec_err.code.value}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_deposit_escrow(self, amount: int) -> Dict[str, Any]:
        try:
            new_bal = self.engine.deposit_escrow(self.org_id, amount, self.admin)
            self.log_event("ESCROW_DEPOSIT", f"Deposited {amount:,} yoctoNEAR into {self.org_id} vault.", "SUCCESS")
            return {"success": True, "message": f"Successfully deposited {amount:,} yoctoNEAR.", "escrow_balance": new_bal}
        except RootboundSecurityException as sec_err:
            return {"success": False, "error": sec_err.message, "error_code": sec_err.code.value}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_withdraw_escrow(self, amount: int) -> Dict[str, Any]:
        try:
            new_bal = self.engine.withdraw_escrow(self.org_id, amount, self.admin)
            self.log_event("ESCROW_WITHDRAWAL", f"Withdrew {amount:,} yoctoNEAR from {self.org_id} vault.", "SUCCESS")
            return {"success": True, "message": f"Successfully withdrew {amount:,} yoctoNEAR.", "escrow_balance": new_bal}
        except RootboundSecurityException as sec_err:
            return {"success": False, "error": sec_err.message, "error_code": sec_err.code.value}
        except Exception as e:
            return {"success": False, "error": str(e)}

STATE = DashboardState(clean=True)

class DashboardRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            static_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
            if os.path.exists(static_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(static_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path == "/demo_video.html" or self.path == "/demo":
            static_path = os.path.join(os.path.dirname(__file__), "static", "demo_video.html")
            if os.path.exists(static_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(static_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path.startswith("/docs/"):
            doc_file = os.path.basename(self.path)
            doc_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", doc_file)
            if os.path.exists(doc_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.end_headers()
                with open(doc_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(STATE.get_state()).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if self.path == "/api/action/legitimate-purchase":
            res = STATE.execute_legitimate_purchase()
            self._send_json(res)
        elif self.path == "/api/action/attack":
            attack_type = payload.get("attack_type", "overspend")
            res = STATE.execute_attack(attack_type)
            self._send_json(res)
        elif self.path == "/api/action/reset":
            STATE.reset(clean=True)
            self._send_json({"success": True, "message": "State reset successfully"})
        elif self.path == "/api/action/revoke":
            agent_id = payload.get("agent_id")
            res = STATE.execute_revocation(agent_id)
            self._send_json(res)
        elif self.path == "/api/action/reclaim":
            parent_id = payload.get("parent_agent_id")
            child_id = payload.get("child_agent_id")
            amount = int(payload.get("amount", 0))
            res = STATE.execute_reclaim(parent_id, child_id, amount)
            self._send_json(res)
        elif self.path == "/api/action/create-agent":
            res = STATE.execute_create_agent(
                parent_agent_id=payload.get("parent_agent_id"),
                child_agent_id=payload.get("child_agent_id"),
                child_account=payload.get("child_account"),
                budget=int(payload.get("budget", 0)),
                permitted_recipients=payload.get("permitted_recipients"),
                max_per_tx=payload.get("max_per_tx"),
                expires_at=payload.get("expires_at")
            )
            self._send_json(res)
        elif self.path == "/api/action/payment":
            res = STATE.execute_custom_payment(
                agent_id=payload.get("agent_id"),
                recipient=payload.get("recipient"),
                amount=int(payload.get("amount", 0)),
                request_id=payload.get("request_id")
            )
            self._send_json(res)
        elif self.path == "/api/action/deposit":
            amount = int(payload.get("amount", 0))
            res = STATE.execute_deposit_escrow(amount)
            self._send_json(res)
        elif self.path == "/api/action/withdraw":
            amount = int(payload.get("amount", 0))
            res = STATE.execute_withdraw_escrow(amount)
            self._send_json(res)
        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: Dict[str, Any]):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress noisy standard stdout logging
        pass

def start_dashboard_server(port: int = 8080):
    server = HTTPServer(("0.0.0.0", port), DashboardRequestHandler)
    print(f"ROOTBOUND Dashboard Server running at http://localhost:{port}")
    return server

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = start_dashboard_server(port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
