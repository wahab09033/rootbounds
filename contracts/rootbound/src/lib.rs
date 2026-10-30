use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap};
use near_sdk::{
    env, near_bindgen, require, AccountId, Balance, PanicOnDefault, Promise, PromiseError,
    PromiseResult, Timestamp,
};
use std::collections::{HashMap, HashSet};

mod accounting;
mod policy;
pub mod types;

#[cfg(test)]
mod tests;

use accounting::AccountingEngine;
use policy::PolicyEngine;
use types::*;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct RootboundContract {
    pub contract_owner: AccountId,
    pub organizations: UnorderedMap<OrgId, Organization>,
    pub grants: UnorderedMap<AgentId, DelegationGrant>,
    pub payments: UnorderedMap<RequestId, PaymentRecord>,
}

#[near_bindgen]
impl RootboundContract {
    #[init]
    pub fn new() -> Self {
        require!(!env::state_exists(), "Already initialized");
        Self {
            contract_owner: env::predecessor_account_id(),
            organizations: UnorderedMap::new(b"o"),
            grants: UnorderedMap::new(b"g"),
            payments: UnorderedMap::new(b"p"),
        }
    }

    // -------------------------------------------------------------------------
    // Step 4: Organization & Escrow Management
    // -------------------------------------------------------------------------

    #[payable]
    pub fn create_organization(
        &mut self,
        org_id: OrgId,
        root_agent_id: AgentId,
        expires_at: Timestamp,
        permitted_recipients: Option<HashSet<AccountId>>,
        max_per_tx: Option<Balance>,
    ) -> Organization {
        let deposit = env::attached_deposit();
        require!(deposit > 0, ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        require!(self.organizations.get(&org_id).is_none(), ERR_DUPLICATE_REQUEST);
        require!(self.grants.get(&root_agent_id).is_none(), ERR_DUPLICATE_REQUEST);

        let admin = env::predecessor_account_id();
        let now = env::block_timestamp();

        let org = Organization {
            id: org_id.clone(),
            admin: admin.clone(),
            root_agent_id: root_agent_id.clone(),
            escrow_balance: deposit,
            created_at: now,
            is_active: true,
        };
        self.organizations.insert(&org_id, &org);

        // Create Depth 1 Root Grant
        let root_balance = AgentBalance::new(deposit);
        let root_grant = DelegationGrant {
            grant_id: format!("grant_{}", root_agent_id),
            org_id: org_id.clone(),
            agent_id: root_agent_id.clone(),
            agent_account: admin,
            parent_agent_id: None,
            depth: 1,
            balance: root_balance,
            permitted_recipients,
            max_per_tx,
            expires_at,
            nonce: 0,
            is_revoked: false,
            created_at: now,
        };
        self.grants.insert(&root_agent_id, &root_grant);

        org
    }

    #[payable]
    pub fn deposit_escrow(&mut self, org_id: OrgId) -> Balance {
        let deposit = env::attached_deposit();
        require!(deposit > 0, ERR_INSUFFICIENT_AVAILABLE_BUDGET);
        
        let mut org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(env::predecessor_account_id() == org.admin, ERR_UNAUTHORIZED_CALLER);

        let mut root_grant = self.grants.get(&org.root_agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        AccountingEngine::deposit(&mut org, &mut root_grant, deposit);

        self.organizations.insert(&org_id, &org);
        self.grants.insert(&org.root_agent_id, &root_grant);

        org.escrow_balance
    }

    pub fn withdraw_escrow(&mut self, org_id: OrgId, amount: Balance) -> Promise {
        let org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        let caller = env::predecessor_account_id();
        require!(caller == org.admin, ERR_UNAUTHORIZED_CALLER);
        require!(org.is_active, ERR_ANCESTOR_REVOKED);

        let mut root_grant = self.grants.get(&org.root_agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        AccountingEngine::reserve_withdrawal(&mut root_grant, amount);

        self.grants.insert(&org.root_agent_id, &root_grant);

        Promise::new(org.admin.clone())
            .transfer(amount)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(near_sdk::Gas::from_tgas(15))
                    .on_withdraw_settled(org_id, amount)
            )
    }

    #[private]
    pub fn on_withdraw_settled(
        &mut self,
        org_id: OrgId,
        amount: Balance,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> Balance {
        let mut org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        let mut root_grant = self.grants.get(&org.root_agent_id).expect(ERR_PAYMENT_NOT_FOUND);

        match result {
            Ok(()) => {
                AccountingEngine::finalize_withdrawal_success(&mut org, &mut root_grant, amount);
            }
            Err(_) => {
                AccountingEngine::finalize_withdrawal_failure(&mut root_grant, amount);
            }
        }

        self.organizations.insert(&org_id, &org);
        self.grants.insert(&org.root_agent_id, &root_grant);
        org.escrow_balance
    }

    // -------------------------------------------------------------------------
    // Steps 5 & 6: Delegation Management & Policy Engine
    // -------------------------------------------------------------------------

    pub fn create_delegation_grant(
        &mut self,
        org_id: OrgId,
        parent_agent_id: AgentId,
        child_agent_id: AgentId,
        child_account: AccountId,
        budget: Balance,
        expires_at: Timestamp,
        permitted_recipients: Option<HashSet<AccountId>>,
        max_per_tx: Option<Balance>,
    ) -> DelegationGrant {
        require!(self.grants.get(&child_agent_id).is_none(), ERR_DUPLICATE_REQUEST);
        let mut parent = self.grants.get(&parent_agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        let org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(org.is_active, ERR_ANCESTOR_REVOKED);
        require!(parent.org_id == org_id, ERR_UNAUTHORIZED_CALLER);

        let caller = env::predecessor_account_id();
        require!(caller == parent.agent_account || caller == org.admin, ERR_UNAUTHORIZED_CALLER);

        // Invariant 5: Ancestor Validity
        self.assert_ancestor_chain_valid(&parent_agent_id);

        let now = env::block_timestamp();
        // Policy Engine: Depth, Budget, Recipient, Expiry, Limit checks
        let child_depth = PolicyEngine::validate_delegation(
            &parent,
            budget,
            expires_at,
            &permitted_recipients,
            &max_per_tx,
            now,
        ).unwrap_or_else(|err| env::panic_str(err));

        // Deduct from parent available and add to parent delegated
        AccountingEngine::delegate(&mut parent, budget);
        self.grants.insert(&parent_agent_id, &parent);

        let child_grant = DelegationGrant {
            grant_id: format!("grant_{}", child_agent_id),
            org_id,
            agent_id: child_agent_id.clone(),
            agent_account: child_account,
            parent_agent_id: Some(parent_agent_id),
            depth: child_depth,
            balance: AgentBalance::new(budget),
            permitted_recipients,
            max_per_tx,
            expires_at,
            nonce: 0,
            is_revoked: false,
            created_at: now,
        };
        self.grants.insert(&child_agent_id, &child_grant);

        child_grant
    }

    /// Step 6b: Fund Reclamation / Undelegate
    /// Reclaims uncommitted available funds from a child grant back to the parent.
    pub fn reclaim_delegated_funds(
        &mut self,
        org_id: OrgId,
        parent_agent_id: AgentId,
        child_agent_id: AgentId,
        amount: Balance,
    ) -> DelegationGrant {
        let org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(org.is_active, ERR_ANCESTOR_REVOKED);
        let mut parent = self.grants.get(&parent_agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        let mut child = self.grants.get(&child_agent_id).expect(ERR_PAYMENT_NOT_FOUND);

        require!(parent.org_id == org_id && child.org_id == org_id, ERR_UNAUTHORIZED_CALLER);
        require!(child.parent_agent_id.as_ref() == Some(&parent_agent_id), ERR_IMMUTABLE_PARENT);

        let caller = env::predecessor_account_id();
        require!(caller == parent.agent_account || caller == org.admin, ERR_UNAUTHORIZED_CALLER);

        AccountingEngine::reclaim(&mut parent, &mut child, amount);

        self.grants.insert(&parent_agent_id, &parent);
        self.grants.insert(&child_agent_id, &child);

        child
    }

    // -------------------------------------------------------------------------
    // Step 7: Budget Reservation & Payment Request Lifecycle
    // -------------------------------------------------------------------------

    pub fn request_payment(
        &mut self,
        org_id: OrgId,
        agent_id: AgentId,
        recipient: AccountId,
        amount: Balance,
        request_id: RequestId,
        nonce: u64,
    ) -> Promise {
        require!(self.payments.get(&request_id).is_none(), ERR_DUPLICATE_REQUEST);
        let mut grant = self.grants.get(&agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(grant.org_id == org_id, ERR_UNAUTHORIZED_CALLER);
        let org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(org.is_active, ERR_ANCESTOR_REVOKED);

        let caller = env::predecessor_account_id();
        require!(caller == grant.agent_account, ERR_UNAUTHORIZED_CALLER);

        // Check Ancestors
        self.assert_ancestor_chain_valid(&agent_id);

        let now = env::block_timestamp();
        PolicyEngine::validate_payment(&grant, &recipient, amount, nonce, now)
            .unwrap_or_else(|err| env::panic_str(err));

        // Reserve funds atomically
        AccountingEngine::reserve(&mut grant, amount, nonce);
        self.grants.insert(&agent_id, &grant);

        let payment = PaymentRecord {
            request_id: request_id.clone(),
            org_id: org_id.clone(),
            agent_id: agent_id.clone(),
            recipient: recipient.clone(),
            amount,
            status: PaymentStatus::Reserved,
            nonce,
            created_at: now,
            resolved_at: None,
            failure_reason: None,
        };
        self.payments.insert(&request_id, &payment);

        // Dispatch asynchronous NEAR transfer and attach callback
        Promise::new(recipient)
            .transfer(amount)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(near_sdk::Gas::from_tgas(15))
                    .on_payment_settled(request_id)
            )
    }

    #[private]
    pub fn on_payment_settled(
        &mut self,
        request_id: RequestId,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> PaymentRecord {
        let mut payment = self.payments.get(&request_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(payment.status == PaymentStatus::Reserved, ERR_INVALID_PAYMENT_STATE);

        let mut grant = self.grants.get(&payment.agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        let now = env::block_timestamp();

        match result {
            Ok(()) => {
                // Success: Reserved -> Spent
                AccountingEngine::finalize_success(&mut grant, payment.amount);
                payment.status = PaymentStatus::Finalized;
            }
            Err(_) => {
                // Failure: Invariant 7 Safe Recovery (Reserved -> Available)
                AccountingEngine::finalize_failure(&mut grant, payment.amount);
                payment.status = PaymentStatus::Failed;
                payment.failure_reason = Some("Transfer execution failed or reverted".to_string());
            }
        }

        payment.resolved_at = Some(now);
        self.grants.insert(&payment.agent_id, &grant);
        self.payments.insert(&request_id, &payment);

        payment
    }

    // -------------------------------------------------------------------------
    // Step 8: Revocation & Authorization Security
    // -------------------------------------------------------------------------

    pub fn revoke_grant(&mut self, org_id: OrgId, agent_id: AgentId) -> bool {
        let mut target = self.grants.get(&agent_id).expect(ERR_PAYMENT_NOT_FOUND);
        let org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        require!(org.is_active, ERR_ANCESTOR_REVOKED);
        require!(target.org_id == org_id, ERR_UNAUTHORIZED_CALLER);

        let caller = env::predecessor_account_id();
        let mut is_authorized = (caller == org.admin) || (caller == target.agent_account);
        
        if !is_authorized && target.parent_agent_id.is_some() {
            let parent_id = target.parent_agent_id.as_ref().unwrap();
            if let Some(parent) = self.grants.get(parent_id) {
                if parent.agent_account == caller {
                    is_authorized = true;
                }
            }
        }
        require!(is_authorized, ERR_UNAUTHORIZED_CALLER);

        target.is_revoked = true;
        self.grants.insert(&agent_id, &target);
        true
    }

    pub fn set_organization_active(&mut self, org_id: OrgId, is_active: bool) -> bool {
        let mut org = self.organizations.get(&org_id).expect(ERR_PAYMENT_NOT_FOUND);
        let caller = env::predecessor_account_id();
        require!(caller == org.admin, ERR_UNAUTHORIZED_CALLER);
        org.is_active = is_active;
        self.organizations.insert(&org_id, &org);
        is_active
    }

    // -------------------------------------------------------------------------
    // View Methods & Invariant Verification
    // -------------------------------------------------------------------------

    pub fn get_organization(&self, org_id: OrgId) -> Option<Organization> {
        self.organizations.get(&org_id)
    }

    pub fn get_grant(&self, agent_id: AgentId) -> Option<DelegationGrant> {
        self.grants.get(&agent_id)
    }

    pub fn get_payment(&self, request_id: RequestId) -> Option<PaymentRecord> {
        self.payments.get(&request_id)
    }

    pub fn get_agent_balance(&self, agent_id: AgentId) -> Option<AgentBalance> {
        self.grants.get(&agent_id).map(|g| g.balance)
    }

    pub fn is_ancestor_chain_valid(&self, agent_id: AgentId) -> bool {
        let mut curr_id = Some(agent_id);
        while let Some(id) = curr_id {
            match self.grants.get(&id) {
                Some(grant) => {
                    if grant.is_revoked {
                        return false;
                    }
                    if let Some(org) = self.organizations.get(&grant.org_id) {
                        if !org.is_active {
                            return false;
                        }
                    } else {
                        return false;
                    }
                    curr_id = grant.parent_agent_id;
                }
                None => return false,
            }
        }
        true
    }

    pub fn verify_organization_invariants(&self, org_id: OrgId) -> bool {
        let org = match self.organizations.get(&org_id) {
            Some(o) => o,
            None => return false,
        };
        let root = match self.grants.get(&org.root_agent_id) {
            Some(r) => r,
            None => return false,
        };
        if root.balance.allocated != org.escrow_balance {
            return false;
        }
        for (_, grant) in self.grants.iter() {
            if grant.org_id == org_id {
                if grant.depth > 3 {
                    return false;
                }
                let total = match grant.balance.available
                    .checked_add(grant.balance.delegated)
                    .and_then(|v| v.checked_add(grant.balance.reserved))
                    .and_then(|v| v.checked_add(grant.balance.spent)) {
                    Some(t) => t,
                    None => return false,
                };
                if total != grant.balance.allocated {
                    return false;
                }
            }
        }
        true
    }

    fn assert_ancestor_chain_valid(&self, agent_id: &AgentId) {
        require!(self.is_ancestor_chain_valid(agent_id.clone()), ERR_ANCESTOR_REVOKED);
    }
}
