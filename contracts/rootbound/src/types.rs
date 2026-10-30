use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, Balance, Timestamp};
use std::collections::HashSet;

pub type OrgId = String;
pub type AgentId = String;
pub type RequestId = String;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub enum PaymentStatus {
    Reserved,
    Finalized,
    Failed,
    Cancelled,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct AgentBalance {
    pub allocated: Balance, // Total grant authority issued
    pub available: Balance, // Currently free to spend or delegate
    pub delegated: Balance, // Allocated downward to children
    pub reserved: Balance,  // In-flight locks committed to active transfers
    pub spent: Balance,     // Confirmed transferred funds
}

impl AgentBalance {
    pub fn new(allocated: Balance) -> Self {
        Self {
            allocated,
            available: allocated,
            delegated: 0,
            reserved: 0,
            spent: 0,
        }
    }

    pub fn assert_conservation(&self, agent_id: &str) {
        let total = self.available
            .checked_add(self.delegated).expect("overflow")
            .checked_add(self.reserved).expect("overflow")
            .checked_add(self.spent).expect("overflow");
        assert_eq!(
            total, self.allocated,
            "Conservation invariant violated for {}: allocated={} != available({}) + delegated({}) + reserved({}) + spent({})",
            agent_id, self.allocated, self.available, self.delegated, self.reserved, self.spent
        );
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Organization {
    pub id: OrgId,
    pub admin: AccountId,
    pub root_agent_id: AgentId,
    pub escrow_balance: Balance,
    pub created_at: Timestamp,
    pub is_active: bool,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct DelegationGrant {
    pub grant_id: String,
    pub org_id: OrgId,
    pub agent_id: AgentId,
    pub agent_account: AccountId,
    pub parent_agent_id: Option<AgentId>,
    pub depth: u8,
    pub balance: AgentBalance,
    pub permitted_recipients: Option<HashSet<AccountId>>,
    pub max_per_tx: Option<Balance>,
    pub expires_at: Timestamp,
    pub nonce: u64,
    pub is_revoked: bool,
    pub created_at: Timestamp,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct PaymentRecord {
    pub request_id: RequestId,
    pub org_id: OrgId,
    pub agent_id: AgentId,
    pub recipient: AccountId,
    pub amount: Balance,
    pub status: PaymentStatus,
    pub nonce: u64,
    pub created_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub failure_reason: Option<String>,
}

// Structured Error Code constants for NEAR Panic / Return
pub const ERR_EXCEEDED_MAX_DEPTH: &str = "ERR_EXCEEDED_MAX_DEPTH";
pub const ERR_IMMUTABLE_PARENT: &str = "ERR_IMMUTABLE_PARENT";
pub const ERR_UNAUTHORIZED_CALLER: &str = "ERR_UNAUTHORIZED_CALLER";
pub const ERR_INSUFFICIENT_AVAILABLE_BUDGET: &str = "ERR_INSUFFICIENT_AVAILABLE_BUDGET";
pub const ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY: &str = "ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY";
pub const ERR_TRANSACTION_LIMIT_EXCEEDED: &str = "ERR_TRANSACTION_LIMIT_EXCEEDED";
pub const ERR_BUDGET_ALREADY_RESERVED: &str = "ERR_BUDGET_ALREADY_RESERVED";
pub const ERR_UNAUTHORIZED_RECIPIENT: &str = "ERR_UNAUTHORIZED_RECIPIENT";
pub const ERR_EXPIRY_EXCEEDS_PARENT: &str = "ERR_EXPIRY_EXCEEDS_PARENT";
pub const ERR_GRANT_EXPIRED: &str = "ERR_GRANT_EXPIRED";
pub const ERR_ANCESTOR_REVOKED: &str = "ERR_ANCESTOR_REVOKED";
pub const ERR_INVALID_NONCE: &str = "ERR_INVALID_NONCE";
pub const ERR_DUPLICATE_REQUEST: &str = "ERR_DUPLICATE_REQUEST";
pub const ERR_PAYMENT_NOT_FOUND: &str = "ERR_PAYMENT_NOT_FOUND";
pub const ERR_INVALID_PAYMENT_STATE: &str = "ERR_INVALID_PAYMENT_STATE";
pub const ERR_WITHDRAWAL_EXCEEDS_AVAILABLE: &str = "ERR_WITHDRAWAL_EXCEEDS_AVAILABLE";
