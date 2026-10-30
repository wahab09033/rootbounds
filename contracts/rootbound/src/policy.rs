use crate::types::*;
use near_sdk::{env, AccountId, Balance, Timestamp};
use std::collections::{HashMap, HashSet};

pub struct PolicyEngine;

impl PolicyEngine {
    /// Validates authority attenuation when creating a child or grandchild grant.
    pub fn validate_delegation(
        parent: &DelegationGrant,
        budget: Balance,
        expires_at: Timestamp,
        permitted_recipients: &Option<HashSet<AccountId>>,
        max_per_tx: &Option<Balance>,
        current_time: Timestamp,
    ) -> Result<u8, &'static str> {
        // Invariant 3: Hierarchy Depth Limit (Max depth 3)
        let child_depth = parent.depth.checked_add(1).ok_or(ERR_EXCEEDED_MAX_DEPTH)?;
        if child_depth > 3 {
            return Err(ERR_EXCEEDED_MAX_DEPTH);
        }

        // Invariant 2.1: Budget Ceiling
        if budget == 0 || budget > parent.balance.available {
            return Err(ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY);
        }

        // Invariant 2.2: Recipient Narrowing
        if let Some(parent_recipients) = &parent.permitted_recipients {
            match permitted_recipients {
                None => return Err(ERR_UNAUTHORIZED_RECIPIENT),
                Some(child_recipients) => {
                    if !child_recipients.is_subset(parent_recipients) {
                        return Err(ERR_UNAUTHORIZED_RECIPIENT);
                    }
                }
            }
        }

        // Invariant 2.3: Temporal Expiry Narrowing
        if expires_at > parent.expires_at {
            return Err(ERR_EXPIRY_EXCEEDS_PARENT);
        }
        if expires_at <= current_time {
            return Err(ERR_GRANT_EXPIRED);
        }

        // Invariant 2.4: Per-Transaction Ceiling Narrowing
        if let Some(parent_limit) = parent.max_per_tx {
            match max_per_tx {
                None => return Err(ERR_TRANSACTION_LIMIT_EXCEEDED),
                Some(child_limit) => {
                    if *child_limit > parent_limit {
                        return Err(ERR_TRANSACTION_LIMIT_EXCEEDED);
                    }
                }
            }
        }

        Ok(child_depth)
    }

    /// Validates a payment request against agent grant policies.
    pub fn validate_payment(
        grant: &DelegationGrant,
        recipient: &AccountId,
        amount: Balance,
        nonce: u64,
        current_time: Timestamp,
    ) -> Result<(), &'static str> {
        // Expiry check
        if current_time > grant.expires_at {
            return Err(ERR_GRANT_EXPIRED);
        }

        // Nonce check (strict sequential monotonic nonce)
        let expected_nonce = grant.nonce.checked_add(1).ok_or(ERR_INVALID_NONCE)?;
        if nonce != expected_nonce {
            return Err(ERR_INVALID_NONCE);
        }

        // Recipient whitelist check
        if let Some(recipients) = &grant.permitted_recipients {
            if !recipients.contains(recipient) {
                return Err(ERR_UNAUTHORIZED_RECIPIENT);
            }
        }

        // Transaction ceiling check
        if let Some(limit) = grant.max_per_tx {
            if amount > limit {
                return Err(ERR_TRANSACTION_LIMIT_EXCEEDED);
            }
        }

        // Available balance check
        if amount == 0 || amount > grant.balance.available {
            return Err(ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        }

        Ok(())
    }

    /// Verifies the full ancestor lineage from agent up to Root using a grant lookup closure.
    /// If any ancestor is revoked or missing, returns Err(ERR_ANCESTOR_REVOKED).
    pub fn verify_ancestor_chain<F>(
        agent_id: &AgentId,
        lookup: F,
    ) -> Result<(), &'static str>
    where
        F: Fn(&AgentId) -> Option<DelegationGrant>,
    {
        let mut curr_id = Some(agent_id.clone());
        while let Some(id) = curr_id {
            let grant = lookup(&id).ok_or(ERR_ANCESTOR_REVOKED)?;
            if grant.is_revoked {
                return Err(ERR_ANCESTOR_REVOKED);
            }
            curr_id = grant.parent_agent_id.clone();
        }
        Ok(())
    }
}
