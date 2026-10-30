from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Set, List, Dict, Any

class ErrorCode(str, Enum):
    # Hierarchy & Depth
    ERR_EXCEEDED_MAX_DEPTH = "ERR_EXCEEDED_MAX_DEPTH"
    ERR_IMMUTABLE_PARENT = "ERR_IMMUTABLE_PARENT"
    ERR_UNAUTHORIZED_CALLER = "ERR_UNAUTHORIZED_CALLER"
    
    # Budget & Conservation
    ERR_INSUFFICIENT_AVAILABLE_BUDGET = "ERR_INSUFFICIENT_AVAILABLE_BUDGET"
    ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY = "ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY"
    ERR_TRANSACTION_LIMIT_EXCEEDED = "ERR_TRANSACTION_LIMIT_EXCEEDED"
    ERR_BUDGET_ALREADY_RESERVED = "ERR_BUDGET_ALREADY_RESERVED"
    ERR_WITHDRAWAL_EXCEEDS_AVAILABLE = "ERR_WITHDRAWAL_EXCEEDS_AVAILABLE"
    
    # Policy & Narrowing
    ERR_UNAUTHORIZED_RECIPIENT = "ERR_UNAUTHORIZED_RECIPIENT"
    ERR_EXPIRY_EXCEEDS_PARENT = "ERR_EXPIRY_EXCEEDS_PARENT"
    ERR_GRANT_EXPIRED = "ERR_GRANT_EXPIRED"
    ERR_ANCESTOR_REVOKED = "ERR_ANCESTOR_REVOKED"
    
    # Anti-Replay & Nonce
    ERR_INVALID_NONCE = "ERR_INVALID_NONCE"
    ERR_DUPLICATE_REQUEST = "ERR_DUPLICATE_REQUEST"
    
    # Payment State Machine
    ERR_PAYMENT_NOT_FOUND = "ERR_PAYMENT_NOT_FOUND"
    ERR_INVALID_PAYMENT_STATE = "ERR_INVALID_PAYMENT_STATE"

class RootboundSecurityException(Exception):
    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message

class PaymentStatus(str, Enum):
    RESERVED = "RESERVED"
    FINALIZED = "FINALIZED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

@dataclass
class AgentBalance:
    allocated: int  # Total budget granted to this agent
    available: int  # Balance currently free to spend or delegate
    delegated: int = 0  # Sub-budgets delegated downward to child agents
    reserved: int = 0   # Balance locked in-flight for pending transactions
    spent: int = 0      # Balance confirmed finalized

    def assert_conservation_invariant(self, agent_id: str = ""):
        """Verifies Allocated == Available + Delegated + Reserved + Spent"""
        total = self.available + self.delegated + self.reserved + self.spent
        if total != self.allocated:
            raise AssertionError(
                f"Conservation invariant broken for {agent_id}: "
                f"allocated={self.allocated} != available({self.available}) + delegated({self.delegated}) + reserved({self.reserved}) + spent({self.spent}) (total: {total})"
            )

@dataclass
class Organization:
    id: str
    admin: str
    root_agent_id: str
    escrow_balance: int
    created_at: int
    is_active: bool = True

@dataclass
class DelegationGrant:
    grant_id: str
    org_id: str
    agent_id: str
    agent_account: str
    parent_agent_id: Optional[str]  # None for Root Agent
    depth: int                      # 1 = Root, 2 = Child, 3 = Grandchild
    balance: AgentBalance
    permitted_recipients: Optional[Set[str]]  # None = unconstrained, Set = whitelist
    max_per_tx: Optional[int]
    expires_at: int
    nonce: int = 0                  # Monotonically increasing payment nonce
    is_revoked: bool = False
    created_at: int = 0

@dataclass
class PaymentRecord:
    request_id: str
    org_id: str
    agent_id: str
    recipient: str
    amount: int
    status: PaymentStatus
    nonce: int
    created_at: int
    resolved_at: Optional[int] = None
    failure_reason: Optional[str] = None
