# ROOTBOUND — Architecture & Data Model Specification
**Phase 1 Deliverable — Steps 2 & 3: Architecture, Data Model & Payment Lifecycle**

---

## 1. System Architecture Overview

ROOTBOUND is architected as a high-security, on-chain policy and accounting engine for the NEAR Protocol. 

```
                               ┌────────────────────────────────┐
                               │   Organization Treasury Vault  │
                               │    (Escrow, Admin, Root Agent) │
                               └────────────────┬───────────────┘
                                                │ (Depth 1)
                                                ▼
                               ┌────────────────────────────────┐
                               │      Root Delegation Grant     │
                               │  - Total Escrow Budget         │
                               │  - Monotonic Nonce             │
                               │  - Permitted Payee Whitelist   │
                               └────────────────┬───────────────┘
                                                │
                                    Delegate    │ (Depth 2: Child)
                                                ▼
                               ┌────────────────────────────────┐
                               │   Child Agent Grant (e.g. PM)  │
                               │  - Narrowed Budget             │
                               │  - Subset Whitelist            │
                               │  - Expiry <= Parent Expiry     │
                               └────────────────┬───────────────┘
                                                │
                                    Delegate    │ (Depth 3: Grandchild)
                                                ▼
                               ┌────────────────────────────────┐
                               │ Grandchild Grant (Researcher)  │
                               │  - Sub-Budget Narrowed         │
                               │  - Strict Recipient Whitelist  │
                               │  - MAX DEPTH REACHED           │
                               └────────────────┬───────────────┘
                                                │
                        Pay Request (Reserve)   │ [Strict Verification Engine]
                                                ▼
                               ┌────────────────────────────────┐
                               │  Payment Lifecycle & Callback  │
                               │   1. Reserve Available Funds   │
                               │   2. Async NEAR Promise Call   │
                               │   3. Resolve: Spent / Refund   │
                               └────────────────────────────────┘
```

---

## 2. Technology Selection & Rationale

### 2.1 Smart Contract Language: **Rust (`near-sdk-rs`)**
* **Determinism & Performance:** Near-zero gas overhead and sub-millisecond execution.
* **Type-Safe Memory Safety:** Elimination of integer underflow/overflows via checked arithmetic.
* **Asynchronous Callbacks:** Native `near_sdk::Promise` and typed callback handlers (`PromiseResult`) for safe two-phase settlement.
* **Ecosystem Standard:** Rust is the official reference standard for NEAR Protocol, endorsed by NEAR Core founders and AI Hackathon judges.

### 2.2 Testing Framework Architecture
1. **Core Invariant & Model Engine (Python 3.13 / Native Test Runner):**
   * Instant mathematical proof of invariants, property-based boundary testing, and state transition validation.
2. **Contract Unit Testing (`near-sdk-rs` #[test]):**
   * Deterministic mock environment verifying storage collections, attenuation checks, and access control.
3. **Sandbox Integration Testing (`near-workspaces`):**
   * Realistic multi-account execution on a local standalone NEAR sandbox node testing real cross-contract async promises, gas fees, and receiver panics.

---

## 3. Data Model Specifications

### 3.1 Identifier Types
* `OrgId`: `String` (Globally unique organization identifier, e.g. `"org_rootbound_1"`)
* `AgentId`: `String` (Globally unique agent identifier, e.g. `"agent_pm_42"`)
* `AccountId`: `String` (NEAR account format, e.g. `"alice.near"` or `"provider.testnet"`)
* `RequestId`: `String` (Unique idempotency key for every payment request)
* `Balance`: `u128` (YoctoNEAR or smallest unit of NEP-141 asset)
* `Timestamp`: `u64` (Unix timestamp in nanoseconds / seconds)

### 3.2 Organization (`Organization`)
```rust
pub struct Organization {
    pub id: OrgId,
    pub admin: AccountId,
    pub root_agent_id: AgentId,
    pub escrow_balance: Balance,       // Total deposited funds
    pub created_at: Timestamp,
    pub is_active: bool,
}
```

### 3.3 5-Dimensional Fund Accounting (`AgentBalance`)
Fund accounting distinguishes 5 explicit states for every agent node to prevent double-counting while preserving delegation lineage:
```rust
pub struct AgentBalance {
    pub allocated: Balance, // Total grant ceiling issued to this agent
    pub available: Balance, // Free balance ready for payment or delegation
    pub delegated: Balance, // Sub-budgets delegated downward to child agents
    pub reserved: Balance,  // In-flight locks committed to active transfers
    pub spent: Balance,     // Confirmed transferred funds
}
```
**Core Conservation Invariant:** At all times across every node:
$$\text{allocated} = \text{available} + \text{delegated} + \text{reserved} + \text{spent}$$
And across any parent-child relationship:
$$\text{delegated}_{\text{parent}} = \sum_{C \in \text{Children}} \text{allocated}_C$$

### 3.4 Delegation Grant (`DelegationGrant`)
```rust
pub struct DelegationGrant {
    pub grant_id: String,
    pub org_id: OrgId,
    pub agent_id: AgentId,
    pub agent_account: AccountId,
    pub parent_agent_id: Option<AgentId>, // None only for Root Agent
    pub depth: u8,                        // 1 = Root, 2 = Child, 3 = Grandchild
    pub balance: AgentBalance,
    pub permitted_recipients: Option<Vec<AccountId>>, // None = unconstrained; Some = strict whitelist
    pub max_per_tx: Option<Balance>,                  // Per-transaction ceiling
    pub expires_at: Timestamp,
    pub nonce: u64,                                   // Monotonic counter preventing replay
    pub is_revoked: bool,
    pub created_at: Timestamp,
}
```

### 3.5 Payment Record & State (`PaymentRecord`)
```rust
pub enum PaymentStatus {
    Reserved,    // Funds locked on-chain, async promise dispatched
    Finalized,   // Transfer succeeded, funds marked spent
    Failed,      // Transfer failed/reverted, funds restored to available
    Cancelled,   // Cancelled before execution
}

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
```

---

## 4. Payment Lifecycle & Asynchronous Settlement Engine

The ROOTBOUND payment lifecycle follows a strictly non-blocking, two-phase reservation protocol:

```
[Agent Payment Request]
          │
          ▼
 1. Check Policy & Attenuation
    - Agent Active & Ancestors Active?
    - Not Expired (now <= expires_at)?
    - Nonce valid (req.nonce == agent.nonce + 1)?
    - Recipient permitted in Whitelist?
    - Amount <= max_per_tx?
    - Amount <= agent.available?
          │
          ├── [FAIL] ──> Reject with Structured Error (Zero State Change)
          │
          └── [PASS]
                │
                ▼
 2. Authorization & Reservation Phase (Atomic)
    - agent.available -= Amount
    - agent.reserved  += Amount
    - agent.nonce     += 1
    - Record PaymentRecord(status = Reserved)
          │
          ▼
 3. Asynchronous NEAR Execution Phase
    - Dispatch `Promise::new(recipient).transfer(amount)`
    - Attach callback: `on_payment_settled(request_id)`
          │
          ├── Cross-Contract / Transfer Execution in next block
          │
          ▼
 4. Callback Finalization Phase (`on_payment_settled`)
    - Inspect `PromiseResult`:
      ├─ CASE SUCCESS:
      │  - agent.reserved -= Amount
      │  - agent.spent    += Amount
      │  - Record status  = Finalized
      │
      └─ CASE FAILURE:
         - agent.reserved  -= Amount
         - agent.available += Amount  (RESERVATION RESTORED!)
         - Record status   = Failed(reason)
```

---

## 5. Revocation & Pending-Payment Behavior

1. **Active Revocation Effect:**
   * When an agent $A$ is revoked, its `is_revoked` flag is set to `true`.
   * Any future call to `request_payment` or `create_grant` by $A$ or any descendant of $A$ performs an upward ancestor walk:
     $$\text{is\_ancestor\_chain\_valid}(Agent) \implies \text{All ancestors active}$$
   * If any ancestor is revoked, the call immediately fails with `ErrAncestorRevoked`.

2. **Pending (In-Flight) Reservation Invariant:**
   * If a payment was already authorized and in `Reserved` status before revocation was executed:
     * The asynchronous transfer is already committed to the NEAR network.
     * When the callback completes, the reservation is either finalized as `Spent` (if transfer reached the recipient) or refunded to `Available` (if transfer failed).
     * Revocation prevents **new** authorizations; it does not corrupt the mathematical accounting of already locked promises.
