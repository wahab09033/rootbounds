import time
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from enum import Enum
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus,
    PaymentRecord
)
from core.engine import RootboundEngine
from core.async_payment_engine import AsyncPaymentEngine, TransferOutcome

class AgentRole(str, Enum):
    PROJECT_MANAGER = "PROJECT_MANAGER"
    RESEARCHER = "RESEARCHER"
    PURCHASING = "PURCHASING"

@dataclass
class TaskProposal:
    task_id: str
    proposer_agent_id: str
    target_role: AgentRole
    description: str
    budget_required: int
    recipient: str
    is_approved: bool = False
    is_executed: bool = False

class BaseAutonomousAgent:
    def __init__(
        self,
        agent_id: str,
        account_id: str,
        role: AgentRole,
        engine: RootboundEngine,
        async_engine: AsyncPaymentEngine,
        org_id: str
    ):
        self.agent_id = agent_id
        self.account_id = account_id
        self.role = role
        self.engine = engine
        self.async_engine = async_engine
        self.org_id = org_id

    def get_balance(self):
        return self.engine.grants[self.agent_id].balance

    def get_grant(self):
        return self.engine.grants[self.agent_id]

    def request_service_payment(
        self,
        recipient: str,
        amount: int,
        request_id: str,
        timestamp: int = 0
    ) -> PaymentRecord:
        """Submits a payment request governed strictly by ROOTBOUND contract policies."""
        grant = self.get_grant()
        next_nonce = grant.nonce + 1
        
        promise = self.async_engine.dispatch_payment_async(
            caller=self.account_id,
            org_id=self.org_id,
            agent_id=self.agent_id,
            recipient=recipient,
            amount=amount,
            request_id=request_id,
            nonce=next_nonce,
            intended_outcome=TransferOutcome.SUCCESS,
            timestamp=timestamp
        )
        # Settle the asynchronous transfer
        return self.async_engine.settle_promise(promise.promise_id, timestamp=timestamp + 10)

class ProjectManagerAgent(BaseAutonomousAgent):
    """Tier 2: Direct child of Root. Orchestrates projects and sub-delegates to researchers."""
    def __init__(self, agent_id: str, account_id: str, engine: RootboundEngine, async_engine: AsyncPaymentEngine, org_id: str):
        super().__init__(agent_id, account_id, AgentRole.PROJECT_MANAGER, engine, async_engine, org_id)

    def delegate_to_researcher(
        self,
        researcher_agent_id: str,
        researcher_account: str,
        sub_budget: int,
        expires_at: int,
        permitted_recipients: Set[str],
        max_per_tx: int,
        timestamp: int = 0
    ):
        return self.engine.create_delegation_grant(
            caller=self.account_id,
            org_id=self.org_id,
            parent_agent_id=self.agent_id,
            child_agent_id=researcher_agent_id,
            child_account=researcher_account,
            budget=sub_budget,
            expires_at=expires_at,
            permitted_recipients=permitted_recipients,
            max_per_tx=max_per_tx,
            timestamp=timestamp
        )

class ResearchAgent(BaseAutonomousAgent):
    """Tier 3: Child of PM. Conducts market/AI research and delegates purchasing tasks or pays for data."""
    def __init__(self, agent_id: str, account_id: str, engine: RootboundEngine, async_engine: AsyncPaymentEngine, org_id: str):
        super().__init__(agent_id, account_id, AgentRole.RESEARCHER, engine, async_engine, org_id)

class PurchasingAgent(BaseAutonomousAgent):
    """Specialized service or purchasing agent paying permitted vendors."""
    def __init__(self, agent_id: str, account_id: str, engine: RootboundEngine, async_engine: AsyncPaymentEngine, org_id: str):
        super().__init__(agent_id, account_id, AgentRole.PURCHASING, engine, async_engine, org_id)

class AgentEconomyCoordinator:
    """
    Coordinates multi-agent workflows, autonomous task proposals,
    and contract-enforced payments.
    """
    def __init__(self, engine: RootboundEngine, async_engine: AsyncPaymentEngine, org_id: str, admin: str):
        self.engine = engine
        self.async_engine = async_engine
        self.org_id = org_id
        self.admin = admin
        self.agents: Dict[str, BaseAutonomousAgent] = {}
        self.task_proposals: List[TaskProposal] = []

    def bootstrap_economy(
        self,
        root_agent_id: str,
        escrow_deposit: int,
        whitelisted_vendors: Set[str],
        root_expiry: int = 500_000,
        timestamp: int = 1000
    ):
        """Sets up the organization treasury and root grant."""
        self.engine.create_organization(
            org_id=self.org_id,
            admin=self.admin,
            escrow_deposit=escrow_deposit,
            root_agent_id=root_agent_id,
            expires_at=root_expiry,
            permitted_recipients=whitelisted_vendors,
            max_per_tx=escrow_deposit,
            timestamp=timestamp
        )

    def spawn_pm_agent(
        self,
        root_agent_id: str,
        pm_agent_id: str,
        pm_account: str,
        budget: int,
        whitelisted_vendors: Set[str],
        timestamp: int = 1000
    ) -> ProjectManagerAgent:
        """Spawns Depth 2 PM agent from Root."""
        root_grant = self.engine.grants[root_agent_id]
        self.engine.create_delegation_grant(
            caller=self.admin,
            org_id=self.org_id,
            parent_agent_id=root_agent_id,
            child_agent_id=pm_agent_id,
            child_account=pm_account,
            budget=budget,
            expires_at=root_grant.expires_at - 10_000,
            permitted_recipients=whitelisted_vendors,
            max_per_tx=budget,
            timestamp=timestamp
        )
        pm = ProjectManagerAgent(pm_agent_id, pm_account, self.engine, self.async_engine, self.org_id)
        self.agents[pm_agent_id] = pm
        return pm

    def spawn_researcher_agent(
        self,
        pm: ProjectManagerAgent,
        res_agent_id: str,
        res_account: str,
        budget: int,
        whitelisted_vendors: Set[str],
        timestamp: int = 1000
    ) -> ResearchAgent:
        """PM spawns Depth 3 Research agent."""
        pm_grant = pm.get_grant()
        pm.delegate_to_researcher(
            researcher_agent_id=res_agent_id,
            researcher_account=res_account,
            sub_budget=budget,
            expires_at=pm_grant.expires_at - 10_000,
            permitted_recipients=whitelisted_vendors,
            max_per_tx=budget,
            timestamp=timestamp
        )
        researcher = ResearchAgent(res_agent_id, res_account, self.engine, self.async_engine, self.org_id)
        self.agents[res_agent_id] = researcher
        return researcher

    def execute_end_to_end_purchase_flow(self, timestamp: int = 1000) -> Dict[str, Any]:
        """
        Demonstrates a complete legitimate multi-tier purchase workflow:
        1. PM proposes infrastructure compute purchase.
        2. PM pays for compute through contract validation.
        3. Researcher proposes AI model dataset indexing.
        4. Researcher pays for dataset inference through contract validation.
        5. Balances update accurately and conservation invariant is proven.
        """
        pm: ProjectManagerAgent = self.agents.get("agent_pm") # type: ignore
        res: ResearchAgent = self.agents.get("agent_researcher") # type: ignore

        # 1. PM Purchase (Compute infrastructure: 15,000 yoctoNEAR)
        pm_tx = pm.request_service_payment(
            recipient="vendor_shade_compute.near",
            amount=15_000,
            request_id="tx_pm_compute_01",
            timestamp=timestamp + 100
        )

        # 2. Researcher Purchase (LLM Inference: 8,000 yoctoNEAR)
        res_tx = res.request_service_payment(
            recipient="vendor_phala_inference.near",
            amount=8_000,
            request_id="tx_res_inference_01",
            timestamp=timestamp + 200
        )

        return {
            "pm_transaction": pm_tx,
            "researcher_transaction": res_tx,
            "pm_balance": pm.get_balance(),
            "researcher_balance": res.get_balance(),
            "invariants_verified": self.engine.verify_global_invariants(self.org_id)
        }
