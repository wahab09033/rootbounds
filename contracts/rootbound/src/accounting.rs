use crate::types::*;
use near_sdk::Balance;

pub struct AccountingEngine;

impl AccountingEngine {
    /// Deposits funds into organization escrow and credits the Root Agent.
    pub fn deposit(org: &mut Organization, root_grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount > 0, "{}", ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        org.escrow_balance = org.escrow_balance.checked_add(amount).expect("escrow overflow");
        root_grant.balance.allocated = root_grant.balance.allocated.checked_add(amount).expect("alloc overflow");
        root_grant.balance.available = root_grant.balance.available.checked_add(amount).expect("avail overflow");
        root_grant.balance.assert_conservation(&root_grant.agent_id);
    }

    /// Withdraws uncommitted funds from root available balance back to org admin.
    pub fn withdraw(org: &mut Organization, root_grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount > 0, "{}", ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        assert!(amount <= root_grant.balance.available, "{}", ERR_WITHDRAWAL_EXCEEDS_AVAILABLE);

        org.escrow_balance = org.escrow_balance.checked_sub(amount).expect("escrow underflow");
        root_grant.balance.available = root_grant.balance.available.checked_sub(amount).expect("avail underflow");
        root_grant.balance.allocated = root_grant.balance.allocated.checked_sub(amount).expect("alloc underflow");
        root_grant.balance.assert_conservation(&root_grant.agent_id);
    }

    /// Allocates budget from parent available to child delegated.
    pub fn delegate(parent: &mut DelegationGrant, budget: Balance) {
        assert!(budget <= parent.balance.available, "{}", ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY);
        parent.balance.available = parent.balance.available.checked_sub(budget).expect("avail underflow");
        parent.balance.delegated = parent.balance.delegated.checked_add(budget).expect("delegated overflow");
        parent.balance.assert_conservation(&parent.agent_id);
    }

    /// Reserves available funds for an in-flight payment request.
    pub fn reserve(grant: &mut DelegationGrant, amount: Balance, nonce: u64) {
        assert!(amount <= grant.balance.available, "{}", ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        grant.balance.available = grant.balance.available.checked_sub(amount).expect("avail underflow");
        grant.balance.reserved = grant.balance.reserved.checked_add(amount).expect("reserved overflow");
        grant.nonce = nonce;
        grant.balance.assert_conservation(&grant.agent_id);
    }

    /// Reclaims uncommitted available funds from a child grant back to the parent.
    /// Can only reclaim up to child.balance.available.
    pub fn reclaim(parent: &mut DelegationGrant, child: &mut DelegationGrant, amount: Balance) {
        assert!(amount > 0, "{}", ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        assert!(amount <= child.balance.available, "{}", ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        assert!(amount <= parent.balance.delegated, "{}", ERR_BUDGET_EXCEEDS_PARENT_AUTHORITY);

        child.balance.available = child.balance.available.checked_sub(amount).expect("avail underflow");
        child.balance.allocated = child.balance.allocated.checked_sub(amount).expect("alloc underflow");
        child.balance.assert_conservation(&child.agent_id);

        parent.balance.delegated = parent.balance.delegated.checked_sub(amount).expect("delegated underflow");
        parent.balance.available = parent.balance.available.checked_add(amount).expect("avail overflow");
        parent.balance.assert_conservation(&parent.agent_id);
    }

    /// Reserves escrow funds for withdrawal to admin.
    pub fn reserve_withdrawal(root_grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount > 0, "{}", ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        assert!(amount <= root_grant.balance.available, "{}", ERR_WITHDRAWAL_EXCEEDS_AVAILABLE);

        root_grant.balance.available = root_grant.balance.available.checked_sub(amount).expect("avail underflow");
        root_grant.balance.reserved = root_grant.balance.reserved.checked_add(amount).expect("reserved overflow");
        root_grant.balance.assert_conservation(&root_grant.agent_id);
    }

    /// Finalizes a successful withdrawal: moves funds from root reserved to debited.
    pub fn finalize_withdrawal_success(org: &mut Organization, root_grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount <= root_grant.balance.reserved, "{}", ERR_INVALID_PAYMENT_STATE);
        assert!(amount <= org.escrow_balance, "{}", ERR_WITHDRAWAL_EXCEEDS_AVAILABLE);

        root_grant.balance.reserved = root_grant.balance.reserved.checked_sub(amount).expect("reserved underflow");
        root_grant.balance.allocated = root_grant.balance.allocated.checked_sub(amount).expect("alloc underflow");
        org.escrow_balance = org.escrow_balance.checked_sub(amount).expect("escrow underflow");

        root_grant.balance.assert_conservation(&root_grant.agent_id);
    }

    /// Recovers from a failed withdrawal: restores funds from root reserved back to available.
    pub fn finalize_withdrawal_failure(root_grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount <= root_grant.balance.reserved, "{}", ERR_INVALID_PAYMENT_STATE);
        root_grant.balance.reserved = root_grant.balance.reserved.checked_sub(amount).expect("reserved underflow");
        root_grant.balance.available = root_grant.balance.available.checked_add(amount).expect("avail overflow");
        root_grant.balance.assert_conservation(&root_grant.agent_id);
    }

    /// Finalizes a successful transfer: moves funds from reserved to spent.
    pub fn finalize_success(grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount <= grant.balance.reserved, "{}", ERR_INVALID_PAYMENT_STATE);
        grant.balance.reserved = grant.balance.reserved.checked_sub(amount).expect("reserved underflow");
        grant.balance.spent = grant.balance.spent.checked_add(amount).expect("spent overflow");
        grant.balance.assert_conservation(&grant.agent_id);
    }

    /// Finalizes a failed transfer: restores funds from reserved back to available.
    pub fn finalize_failure(grant: &mut DelegationGrant, amount: Balance) {
        assert!(amount <= grant.balance.reserved, "{}", ERR_INVALID_PAYMENT_STATE);
        grant.balance.reserved = grant.balance.reserved.checked_sub(amount).expect("reserved underflow");
        grant.balance.available = grant.balance.available.checked_add(amount).expect("avail overflow");
        grant.balance.assert_conservation(&grant.agent_id);
    }
}
