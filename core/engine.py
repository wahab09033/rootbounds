from typing import Dict, Optional, Set, List
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus,
    AgentBalance,
    Organization,
    DelegationGrant,
    PaymentRecord
)

class RootboundEngine:
    """
    ROOTBOUND Reference State Machine & Invariant Enforcement Engine.
    Implements all security guarantees, delegation hierarchy rules,
    attenuation validation, and 4-state payment accounting.
    """
    def __init__(self):
        self.organizations: Dict[str, Organization] = {}
        self.grants: Dict[str, DelegationGrant] = {}  # agent_id -> DelegationGrant
        self.payments: Dict[str, PaymentRecord] = {}  # request_id -> PaymentRecord
        self.used_nonces: Dict[str, Set[int]] = {}   # agent_id -> set of used nonces

    # -------------------------------------------------------------------------
    # 1. Organization & Escrow Vault Management
    # -------------------------------------------------------------------------
    def create_organization(
        self,
        org_id: str,
        admin: str,
        escrow_deposit: int,
        root_agent_id: str,
        expires_at: int,
        permitted_recipients: Optional[Set[str]] = None,
        max_per_tx: Optional[int] = None,
        timestamp: int = 0
    ) -> Organization:
        if org_id in self.organizations:
            raise RootboundSecurityException(
                ErrorCode.ERR_DUPLICATE_REQUEST, f"Organization {org_id} already exists"
            )
        if root_agent_id in self.grants:
            raise RootboundSecurityException(
                ErrorCode.ERR_DUPLICATE_REQUEST, f"Grant for root agent {root_agent_id} already exists"
            )
        if escrow_deposit <= 0:
            raise RootboundSecurityException(
                ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET, "Escrow deposit must be positive"
            )
        if expires_at <= timestamp:
            raise RootboundSecurityException(
                ErrorCode.ERR_GRANT_EXPIRED, "Root grant expiry must be in the future"
            )

        org = Organization(
            id=org_id,
            admin=admin,
            root_agent_id=root_agent_id,
            escrow_balance=escrow_deposit,
            created_at=timestamp,
            is_active=True
        )
        self.organizations[org_id] = org

        # Create Root Agent Delegation Grant (Depth 1)
        root_balance = AgentBalance(
            allocated=escrow_deposit,
            available=escrow_deposit,
            reserved=0,
            spent=0
        )
        root_grant = DelegationGrant(
            grant_id=f"grant_{root_agent_id}",
            org_id=org_id,
            agent_id=root_agent_id,
            agent_account=admin,
            parent_agent_id=None,
            depth=1,
            balance=root_balance,
            permitted_recipients=permitted_recipients,
            max_per_tx=max_per_tx,
            expires_at=expires_at,
            nonce=0,
            is_revoked=False,
            created_at=timestamp
        )
        self.grants[root_agent_id] = root_grant
        self.used_nonces[root_agent_id] = set()

        root_balance.assert_conservation_invariant(root_agent_id)
        return org

    def deposit_escrow(self, org_id: str, amount: int, caller: str) -> int:
        if org_id not in self.organizations:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        org = self.organizations[org_id]
        if not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")
        if org.admin != caller:
            raise RootboundSecurityException(ErrorCode.ERR_UNAUTHORIZED_CALLER, "Only admin can deposit escrow")
        if amount <= 0:
            raise RootboundSecurityException(ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET, "Amount must be positive")

        org.escrow_balance += amount
        root_grant = self.grants[org.root_agent_id]
        root_grant.balance.allocated += amount
        root_grant.balance.available += amount
        root_grant.balance.assert_conservation_invariant(org.root_agent_id)
        return org.escrow_balance

    def withdraw_escrow(self, org_id: str, amount: int, caller: str) -> int:
        if org_id not in self.organizations:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        org = self.organizations[org_id]
        if not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")
        if org.admin != caller:
            raise RootboundSecurityException(ErrorCode.ERR_UNAUTHORIZED_CALLER, "Only admin can withdraw escrow")
        if amount <= 0:
            raise RootboundSecurityException(ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET, "Amount must be positive")

        root_grant = self.grants[org.root_agent_id]
        if amount > root_grant.balance.available:
            raise RootboundSecurityException(
                ErrorCode.ERR_WITHDRAWAL_EXCEEDS_AVAILABLE,
                f"Withdrawal amount {amount} exceeds available uncommitted balance {root_grant.balance.available}"
            )

        org.escrow_balance -= amount
        root_grant.balance.available -= amount
        root_grant.balance.allocated -= amount
        root_grant.balance.assert_conservation_invariant(org.root_agent_id)
        return org.escrow_balance

    def reserve_withdrawal(self, org_id: str, amount: int, caller: str) -> int:
        if org_id not in self.organizations:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        org = self.organizations[org_id]
        if not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")
        if org.admin != caller:
            raise RootboundSecurityException(ErrorCode.ERR_UNAUTHORIZED_CALLER, "Only admin can withdraw escrow")
        if amount <= 0:
            raise RootboundSecurityException(ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET, "Amount must be positive")

        root_grant = self.grants[org.root_agent_id]
        if amount > root_grant.balance.available:
            raise RootboundSecurityException(
                ErrorCode.ERR_WITHDRAWAL_EXCEEDS_AVAILABLE,
                f"Withdrawal amount {amount} exceeds available uncommitted balance {root_grant.balance.available}"
            )

        root_grant.balance.available -= amount
        root_grant.balance.reserved += amount
        root_grant.balance.assert_conservation_invariant(org.root_agent_id)
        return root_grant.balance.reserved

    def finalize_withdrawal_success(self, org_id: str, amount: int) -> int:
        org = self.organizations[org_id]
        root_grant = self.grants[org.root_agent_id]
        if amount > root_grant.balance.reserved:
            raise RootboundSecurityException(ErrorCode.ERR_INVALID_PAYMENT_STATE, "Amount exceeds reserved withdrawal")
        root_grant.balance.reserved -= amount
        root_grant.balance.allocated -= amount
        org.escrow_balance -= amount
        root_grant.balance.assert_conservation_invariant(org.root_agent_id)
        return org.escrow_balance

    def finalize_withdrawal_failure(self, org_id: str, amount: int) -> int:
        org = self.organizations[org_id]
        root_grant = self.grants[org.root_agent_id]
        if amount > root_grant.balance.reserved:
            raise RootboundSecurityException(ErrorCode.ERR_INVALID_PAYMENT_STATE, "Amount exceeds reserved withdrawal")
        root_grant.balance.reserved -= amount
        root_grant.balance.available += amount
        root_grant.balance.assert_conservation_invariant(org.root_agent_id)
        return root_grant.balance.available

    # -------------------------------------------------------------------------
    # 2. Delegation Hierarchy & Attenuation Engine
    # -------------------------------------------------------------------------
    def create_delegation_grant(
        self,
        caller: str,
        org_id: str,
        parent_agent_id: str,
        child_agent_id: str,
        child_account: str,
        budget: int,
        expires_at: int,
        permitted_recipients: Optional[Set[str]] = None,
        max_per_tx: Optional[int] = None,
        timestamp: int = 0
    ) -> DelegationGrant:
        if child_agent_id in self.grants:
            raise RootboundSecurityException(
                ErrorCode.ERR_DUPLICATE_REQUEST, f"Grant for {child_agent_id} already exists"
            )
        if parent_agent_id not in self.grants:
            raise RootboundSecurityException(
                ErrorCode.ERR_PAYMENT_NOT_FOUND, f"Parent agent {parent_agent_id} does not exist"
            )
        
        parent = self.grants[parent_agent_id]
        
        # Verify Caller is parent or org admin
        org = self.organizations.get(org_id)
        if not org:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        if not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")
        if parent.org_id != org_id:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_CALLER, f"Parent agent {parent_agent_id} does not belong to organization {org_id}"
            )
        if caller != parent.agent_account and caller != org.admin:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_CALLER, "Only parent agent or admin can delegate"
            )

        # Invariant 5: Ancestor Chain Validity (no ancestor may be revoked)
        if not self.is_ancestor_chain_valid(parent_agent_id):
            raise RootboundSecurityException(
                ErrorCode.ERR_ANCESTOR_REVOKED, f"Parent {parent_agent_id} or ancestor is revoked"
            )

        # Invariant 3: Maximum Hierarchy Depth Ceiling (Max Depth = 3)
        child_depth = parent.depth + 1
        if child_depth > 3:
            raise RootboundSecurityException(
                ErrorCode.ERR_EXCEEDED_MAX_DEPTH,
                f"Delegation depth {child_depth} exceeds maximum allowable depth of 3"
            )

        # Invariant 2.1: Budget Ceiling (child budget cannot exceed parent available)
        if budget <= 0 or budget > parent.balance.available:
            raise RootboundSecurityException(
                ErrorCode.ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY,
                f"Requested budget {budget} exceeds parent available authority {parent.balance.available}"
            )

        # Invariant 2.2: Recipient Narrowing (Child recipients must be subset of Parent)
        if parent.permitted_recipients is not None:
            if permitted_recipients is None:
                raise RootboundSecurityException(
                    ErrorCode.ERR_UNAUTHORIZED_RECIPIENT,
                    "Child cannot have unconstrained recipients when parent is restricted"
                )
            if not permitted_recipients.issubset(parent.permitted_recipients):
                diff = permitted_recipients - parent.permitted_recipients
                raise RootboundSecurityException(
                    ErrorCode.ERR_UNAUTHORIZED_RECIPIENT,
                    f"Child recipient set expands parent authority. Unauthorized: {diff}"
                )

        # Invariant 2.3: Temporal Bounding (Child expiry <= Parent expiry)
        if expires_at > parent.expires_at:
            raise RootboundSecurityException(
                ErrorCode.ERR_EXPIRY_EXCEEDS_PARENT,
                f"Child expiry ({expires_at}) exceeds parent expiry ({parent.expires_at})"
            )
        if expires_at <= timestamp:
            raise RootboundSecurityException(
                ErrorCode.ERR_GRANT_EXPIRED, "Grant expiry must be in the future"
            )

        # Invariant 2.4: Transaction Ceiling (Child max_per_tx <= Parent max_per_tx)
        if parent.max_per_tx is not None:
            if max_per_tx is None or max_per_tx > parent.max_per_tx:
                raise RootboundSecurityException(
                    ErrorCode.ERR_TRANSACTION_LIMIT_EXCEEDED,
                    f"Child per-transaction limit exceeds parent limit {parent.max_per_tx}"
                )

        # Deduct budget from parent available and add to parent delegated
        parent.balance.available -= budget
        parent.balance.delegated += budget
        parent.balance.assert_conservation_invariant(parent_agent_id)

        # Initialize Child Grant
        child_balance = AgentBalance(
            allocated=budget,
            available=budget,
            delegated=0,
            reserved=0,
            spent=0
        )
        grant = DelegationGrant(
            grant_id=f"grant_{child_agent_id}",
            org_id=org_id,
            agent_id=child_agent_id,
            agent_account=child_account,
            parent_agent_id=parent_agent_id,
            depth=child_depth,
            balance=child_balance,
            permitted_recipients=permitted_recipients,
            max_per_tx=max_per_tx,
            expires_at=expires_at,
            nonce=0,
            is_revoked=False,
            created_at=timestamp
        )
        self.grants[child_agent_id] = grant
        self.used_nonces[child_agent_id] = set()

        child_balance.assert_conservation_invariant(child_agent_id)
        return grant

    # -------------------------------------------------------------------------
    # 3. Ancestor Traversal & Revocation Management
    # -------------------------------------------------------------------------
    def is_ancestor_chain_valid(self, agent_id: str) -> bool:
        curr_id: Optional[str] = agent_id
        while curr_id is not None:
            grant = self.grants.get(curr_id)
            if not grant or grant.is_revoked:
                return False
            org = self.organizations.get(grant.org_id)
            if not org or not org.is_active:
                return False
            curr_id = grant.parent_agent_id
        return True

    def revoke_grant(self, caller: str, org_id: str, agent_id: str, timestamp: int = 0) -> bool:
        if agent_id not in self.grants:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Agent grant not found")
        
        target = self.grants[agent_id]
        org = self.organizations.get(org_id)
        if not org:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        if not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")
        if target.org_id != org_id:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_CALLER, f"Target agent {agent_id} does not belong to organization {org_id}"
            )

        # Authorization check: only admin, self, or an ancestor can revoke
        is_authorized = (caller == org.admin) or (caller == target.agent_account)
        if not is_authorized and target.parent_agent_id:
            parent = self.grants.get(target.parent_agent_id)
            if parent and parent.agent_account == caller:
                is_authorized = True

        if not is_authorized:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_CALLER, "Caller not authorized to revoke this grant"
            )

        target.is_revoked = True
        return True

    def set_organization_active(self, caller: str, org_id: str, is_active: bool) -> bool:
        if org_id not in self.organizations:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        org = self.organizations[org_id]
        if caller != org.admin:
            raise RootboundSecurityException(ErrorCode.ERR_UNAUTHORIZED_CALLER, "Only admin can toggle organization active state")
        org.is_active = is_active
        return is_active

    def reclaim_delegated_funds(
        self,
        caller: str,
        org_id: str,
        parent_agent_id: str,
        child_agent_id: str,
        amount: int,
        timestamp: int = 0
    ) -> DelegationGrant:
        """
        Reclaims uncommitted available funds from a child grant back to the parent.
        Can only reclaim up to child.balance.available.
        """
        if org_id not in self.organizations:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Organization not found")
        org = self.organizations[org_id]
        if not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")
            
        if parent_agent_id not in self.grants or child_agent_id not in self.grants:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Grant not found")
            
        parent = self.grants[parent_agent_id]
        child = self.grants[child_agent_id]
        
        if parent.org_id != org_id or child.org_id != org_id:
            raise RootboundSecurityException(ErrorCode.ERR_UNAUTHORIZED_CALLER, "Grants do not belong to organization")
        if child.parent_agent_id != parent_agent_id:
            raise RootboundSecurityException(ErrorCode.ERR_IMMUTABLE_PARENT, "Child does not belong to specified parent")
            
        if caller != parent.agent_account and caller != org.admin:
            raise RootboundSecurityException(ErrorCode.ERR_UNAUTHORIZED_CALLER, "Only parent agent or admin can reclaim funds")
            
        if amount <= 0:
            raise RootboundSecurityException(ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET, "Reclaim amount must be positive")
        if amount > child.balance.available:
            raise RootboundSecurityException(
                ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET,
                f"Requested reclaim amount {amount} exceeds child available balance {child.balance.available}"
            )
        if amount > parent.balance.delegated:
            raise RootboundSecurityException(
                ErrorCode.ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY,
                f"Requested reclaim amount {amount} exceeds parent delegated balance {parent.balance.delegated}"
            )
            
        child.balance.available -= amount
        child.balance.allocated -= amount
        child.balance.assert_conservation_invariant(child_agent_id)
        
        parent.balance.delegated -= amount
        parent.balance.available += amount
        parent.balance.assert_conservation_invariant(parent_agent_id)
        
        return child

    # -------------------------------------------------------------------------
    # 4. Asynchronous Payment Lifecycle Engine
    # -------------------------------------------------------------------------
    def authorize_and_reserve_payment(
        self,
        caller: str,
        org_id: str,
        agent_id: str,
        recipient: str,
        amount: int,
        request_id: str,
        nonce: int,
        timestamp: int = 0
    ) -> PaymentRecord:
        if request_id in self.payments:
            raise RootboundSecurityException(
                ErrorCode.ERR_DUPLICATE_REQUEST, f"Payment request {request_id} already exists"
            )
        if agent_id not in self.grants:
            raise RootboundSecurityException(
                ErrorCode.ERR_PAYMENT_NOT_FOUND, f"Agent {agent_id} grant not found"
            )
        
        agent = self.grants[agent_id]
        if agent.org_id != org_id:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_CALLER, f"Agent {agent_id} does not belong to organization {org_id}"
            )
        org = self.organizations.get(org_id)
        if not org or not org.is_active:
            raise RootboundSecurityException(ErrorCode.ERR_ANCESTOR_REVOKED, "Organization is inactive")

        # Caller authentication
        if caller != agent.agent_account:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_CALLER, f"Caller {caller} is not agent account {agent.agent_account}"
            )

        # Invariant 5: Ancestor Validity Check (No revoked ancestors)
        if not self.is_ancestor_chain_valid(agent_id):
            raise RootboundSecurityException(
                ErrorCode.ERR_ANCESTOR_REVOKED, f"Agent {agent_id} or ancestor in hierarchy is revoked"
            )

        # Invariant 2.3: Expiration Check
        if timestamp > agent.expires_at:
            raise RootboundSecurityException(
                ErrorCode.ERR_GRANT_EXPIRED, f"Grant for {agent_id} expired at {agent.expires_at}"
            )

        # Invariant 6: Anti-Replay & Nonce Monotonicity
        expected_nonce = agent.nonce + 1
        if nonce != expected_nonce or nonce in self.used_nonces[agent_id]:
            raise RootboundSecurityException(
                ErrorCode.ERR_INVALID_NONCE,
                f"Invalid nonce {nonce}. Expected next sequential nonce: {expected_nonce}"
            )

        # Invariant 2.2: Recipient Narrowing
        if agent.permitted_recipients is not None and recipient not in agent.permitted_recipients:
            raise RootboundSecurityException(
                ErrorCode.ERR_UNAUTHORIZED_RECIPIENT,
                f"Recipient {recipient} is not permitted for agent {agent_id}"
            )

        # Invariant 2.4: Transaction Ceiling Check
        if agent.max_per_tx is not None and amount > agent.max_per_tx:
            raise RootboundSecurityException(
                ErrorCode.ERR_TRANSACTION_LIMIT_EXCEEDED,
                f"Payment amount {amount} exceeds per-transaction limit of {agent.max_per_tx}"
            )

        # Invariant 1: Sufficient Available Budget
        if amount <= 0 or amount > agent.balance.available:
            raise RootboundSecurityException(
                ErrorCode.ERR_INSUFFICIENT_AVAILABLE_BUDGET,
                f"Requested amount {amount} exceeds available balance {agent.balance.available}"
            )

        # --- Phase 1: Atomic Reservation ---
        agent.balance.available -= amount
        agent.balance.reserved += amount
        agent.nonce = nonce
        self.used_nonces[agent_id].add(nonce)

        agent.balance.assert_conservation_invariant(agent_id)

        payment = PaymentRecord(
            request_id=request_id,
            org_id=org_id,
            agent_id=agent_id,
            recipient=recipient,
            amount=amount,
            status=PaymentStatus.RESERVED,
            nonce=nonce,
            created_at=timestamp
        )
        self.payments[request_id] = payment
        return payment

    def finalize_payment_success(self, request_id: str, timestamp: int = 0) -> PaymentRecord:
        """Callback handler when asynchronous transfer confirms success on NEAR."""
        if request_id not in self.payments:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Payment record not found")
        payment = self.payments[request_id]
        if payment.status != PaymentStatus.RESERVED:
            raise RootboundSecurityException(
                ErrorCode.ERR_INVALID_PAYMENT_STATE,
                f"Cannot finalize payment in state {payment.status}. Must be RESERVED"
            )

        agent = self.grants[payment.agent_id]
        # Transition: Reserved -> Spent
        agent.balance.reserved -= payment.amount
        agent.balance.spent += payment.amount
        agent.balance.assert_conservation_invariant(payment.agent_id)

        payment.status = PaymentStatus.FINALIZED
        payment.resolved_at = timestamp
        return payment

    def finalize_payment_failure(self, request_id: str, reason: str, timestamp: int = 0) -> PaymentRecord:
        """Callback handler when asynchronous transfer fails or reverts on NEAR."""
        if request_id not in self.payments:
            raise RootboundSecurityException(ErrorCode.ERR_PAYMENT_NOT_FOUND, "Payment record not found")
        payment = self.payments[request_id]
        if payment.status != PaymentStatus.RESERVED:
            raise RootboundSecurityException(
                ErrorCode.ERR_INVALID_PAYMENT_STATE,
                f"Cannot refund payment in state {payment.status}. Must be RESERVED"
            )

        agent = self.grants[payment.agent_id]
        # Invariant 7: Safe Recovery. Transition: Reserved -> Available
        agent.balance.reserved -= payment.amount
        agent.balance.available += payment.amount
        agent.balance.assert_conservation_invariant(payment.agent_id)

        payment.status = PaymentStatus.FAILED
        payment.failure_reason = reason
        payment.resolved_at = timestamp
        return payment

    # -------------------------------------------------------------------------
    # 5. Global Invariant Verification
    # -------------------------------------------------------------------------
    def verify_global_invariants(self, org_id: str):
        """Mathematically verifies all core invariants across the entire organization tree."""
        org = self.organizations[org_id]
        root_agent = self.grants[org.root_agent_id]

        # Root allocated must match organization escrow balance
        assert root_agent.balance.allocated == org.escrow_balance, (
            f"Root allocated {root_agent.balance.allocated} != org escrow {org.escrow_balance}"
        )

        # For every parent, delegated balance must strictly equal sum of child allocations
        for gid, grant in self.grants.items():
            if grant.org_id == org_id:
                children = [c for c in self.grants.values() if c.parent_agent_id == gid and c.org_id == org_id]
                expected_delegated = sum(c.balance.allocated for c in children)
                assert grant.balance.delegated == expected_delegated, (
                    f"Delegated balance mismatch for {gid}: recorded {grant.balance.delegated} != sum of children {expected_delegated}"
                )

        # Total active assets (available + reserved + spent) across all nodes must reconcile with org escrow
        total_active = sum(g.balance.available + g.balance.reserved + g.balance.spent for g in self.grants.values() if g.org_id == org_id)
        assert total_active == org.escrow_balance, (
            f"Total active balance mismatch: {total_active} != escrow {org.escrow_balance}"
        )

        # Verify 5-state conservation on every individual grant
        for gid, grant in self.grants.items():
            if grant.org_id == org_id:
                grant.balance.assert_conservation_invariant(gid)
                # Verify max depth limit
                assert grant.depth <= 3, f"Agent {gid} exceeds max depth 3 (depth: {grant.depth})"
                # Verify recipient narrowing
                if grant.parent_agent_id:
                    parent = self.grants[grant.parent_agent_id]
                    if parent.permitted_recipients is not None:
                        assert grant.permitted_recipients is not None
                        assert grant.permitted_recipients.issubset(parent.permitted_recipients)
                    assert grant.expires_at <= parent.expires_at
                    if parent.max_per_tx is not None:
                        assert grant.max_per_tx is not None
                        assert grant.max_per_tx <= parent.max_per_tx

        return True
