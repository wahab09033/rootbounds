#[cfg(test)]
mod tests {
    use crate::types::*;
    use crate::RootboundContract;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, AccountId, Balance, PromiseResult};
    use std::collections::HashSet;

    fn get_context(predecessor: AccountId, deposit: Balance, timestamp: u64) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit)
            .block_timestamp(timestamp);
        builder
    }

    #[test]
    fn test_create_organization_and_escrow() {
        let admin = accounts(1);
        let mut context = get_context(admin.clone(), 1_000_000, 1000);
        testing_env!(context.build());

        let mut contract = RootboundContract::new();
        let org = contract.create_organization(
            "org_1".to_string(),
            "root_agent".to_string(),
            100_000,
            None,
            None,
        );

        assert_eq!(org.id, "org_1");
        assert_eq!(org.escrow_balance, 1_000_000);

        let root_grant = contract.get_grant("root_agent".to_string()).unwrap();
        assert_eq!(root_grant.depth, 1);
        assert_eq!(root_grant.balance.allocated, 1_000_000);
        assert_eq!(root_grant.balance.available, 1_000_000);
        assert_eq!(root_grant.balance.delegated, 0);
        assert_eq!(root_grant.balance.reserved, 0);
        assert_eq!(root_grant.balance.spent, 0);
    }

    #[test]
    fn test_deposit_and_withdraw_escrow() {
        let admin = accounts(1);
        let mut context = get_context(admin.clone(), 1_000_000, 1000);
        testing_env!(context.build());

        let mut contract = RootboundContract::new();
        contract.create_organization(
            "org_1".to_string(),
            "root_agent".to_string(),
            100_000,
            None,
            None,
        );

        // Additional Deposit
        testing_env!(context.attached_deposit(500_000).build());
        let new_balance = contract.deposit_escrow("org_1".to_string());
        assert_eq!(new_balance, 1_500_000);

        let root_grant = contract.get_grant("root_agent".to_string()).unwrap();
        assert_eq!(root_grant.balance.available, 1_500_000);

        // Authorized Withdraw 200,000
        testing_env!(context.attached_deposit(0).build());
        contract.withdraw_escrow("org_1".to_string(), 200_000);
        let updated_grant = contract.get_grant("root_agent".to_string()).unwrap();
        assert_eq!(updated_grant.balance.available, 1_300_000);
        assert_eq!(updated_grant.balance.allocated, 1_300_000);
    }

    #[test]
    #[should_panic(expected = "ERR_EXCEEDED_MAX_DEPTH")]
    fn test_exceed_max_delegation_depth() {
        let admin = accounts(1);
        let mut context = get_context(admin.clone(), 1_000_000, 1000);
        testing_env!(context.build());

        let mut contract = RootboundContract::new();
        contract.create_organization(
            "org_1".to_string(),
            "root".to_string(),
            100_000,
            None,
            None,
        );

        // Depth 2: Child PM
        contract.create_delegation_grant(
            "org_1".to_string(),
            "root".to_string(),
            "child_pm".to_string(),
            accounts(2),
            500_000,
            90_000,
            None,
            None,
        );

        // Depth 3: Grandchild Researcher
        testing_env!(context.predecessor_account_id(accounts(2)).build());
        contract.create_delegation_grant(
            "org_1".to_string(),
            "child_pm".to_string(),
            "grandchild_res".to_string(),
            accounts(3),
            200_000,
            80_000,
            None,
            None,
        );

        // Depth 4: Great-grandchild (Should Panic with ERR_EXCEEDED_MAX_DEPTH)
        testing_env!(context.predecessor_account_id(accounts(3)).build());
        contract.create_delegation_grant(
            "org_1".to_string(),
            "grandchild_res".to_string(),
            "great_grandchild".to_string(),
            accounts(4),
            50_000,
            70_000,
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "ERR_UNAUTHORIZED_RECIPIENT")]
    fn test_recipient_attenuation_violation() {
        let admin = accounts(1);
        let mut context = get_context(admin.clone(), 1_000_000, 1000);
        testing_env!(context.build());

        let mut contract = RootboundContract::new();
        let mut allowed = HashSet::new();
        allowed.insert(accounts(5));
        allowed.insert(accounts(6));

        contract.create_organization(
            "org_1".to_string(),
            "root".to_string(),
            100_000,
            Some(allowed),
            None,
        );

        // Child attempts to add accounts(7) not in parent whitelist
        let mut bad_allowed = HashSet::new();
        bad_allowed.insert(accounts(5));
        bad_allowed.insert(accounts(7)); // UNAUTHORIZED!

        contract.create_delegation_grant(
            "org_1".to_string(),
            "root".to_string(),
            "child_rogue".to_string(),
            accounts(2),
            200_000,
            90_000,
            Some(bad_allowed),
            None,
        );
    }

    #[test]
    fn test_payment_reservation_and_recovery() {
        let admin = accounts(1);
        let mut context = get_context(admin.clone(), 1_000_000, 1000);
        testing_env!(context.build());

        let mut contract = RootboundContract::new();
        contract.create_organization(
            "org_1".to_string(),
            "root".to_string(),
            100_000,
            None,
            None,
        );

        contract.create_delegation_grant(
            "org_1".to_string(),
            "root".to_string(),
            "pm".to_string(),
            accounts(2),
            300_000,
            90_000,
            None,
            None,
        );

        // PM requests payment of 100,000
        testing_env!(context.predecessor_account_id(accounts(2)).build());
        contract.request_payment(
            "org_1".to_string(),
            "pm".to_string(),
            accounts(8),
            100_000,
            "req_1".to_string(),
            1,
        );

        let pm_grant = contract.get_grant("pm".to_string()).unwrap();
        assert_eq!(pm_grant.balance.available, 200_000);
        assert_eq!(pm_grant.balance.reserved, 100_000);
        assert_eq!(pm_grant.balance.spent, 0);

        // Simulate callback failure: safe reservation recovery
        testing_env!(context.predecessor_account_id(accounts(0)).build()); // contract self callback
        let res = contract.on_payment_settled(
            "req_1".to_string(),
            Err(near_sdk::PromiseError::Failed),
        );
        assert_eq!(res.status, PaymentStatus::Failed);

        let recovered_grant = contract.get_grant("pm".to_string()).unwrap();
        assert_eq!(recovered_grant.balance.available, 300_000);
        assert_eq!(recovered_grant.balance.reserved, 0);
        assert_eq!(recovered_grant.balance.spent, 0);
    }
}
