# ROOTBOUND — Security Model Specification
**Phase 1 Deliverable — Step 1: Security Model & Invariants**

---

## 1. Executive Summary & Purpose

ROOTBOUND is a decentralized, on-chain policy and treasury guardrail for autonomous AI agent networks on the NEAR Protocol. 

In autonomous agentic commerce, agents are given financial autonomy to purchase compute, APIs, data sets, or hire sub-agents. However, granting autonomous agents direct access to raw private keys or unconstrained treasuries is fundamentally unsafe due to:
* **LLM Non-Determinism & Hallucinations:** Erroneous transaction generation.
* **Prompt Injection & Social Engineering:** Adversaries manipulating agent logic into redirecting funds.
* **Rogue Delegation & Budget Laundering:** Sub-agents spawning unauthorized agents or exceeding budget limits.
* **Asynchronous Double-Spending:** Race conditions exploiting block latency and cross-contract call delays.

ROOTBOUND enforces **Root-Bound Authority Attenuation** and **4-State Invariant Accounting** directly in a NEAR smart contract. No agent ever controls master escrow custody; every financial action must satisfy immutable on-chain policy constraints.

---

## 2. Protected Assets & Security Boundaries

### 2.1 Protected Assets
1. **Treasury Escrow Principal:** Native NEAR or NEP-141 tokens deposited into the ROOTBOUND contract vault by an organization.
2. **Delegated Sub-Budgets:** Quotas allocated down an agent delegation tree.
3. **Reservation Locks:** Funds committed to in-flight asynchronous transfers pending callback execution.
4. **Agent Identity & Delegation Rights:** The right to spawn child agents or initiate payment requests.

### 2.2 Security Boundaries
* **Contract Boundary (On-Chain Trust Anchor):** The ROOTBOUND smart contract is the single source of truth. All balance accounting, hierarchy validation, and policy checks happen strictly inside contract state.
* **Organization Boundary:** Organizations are isolated silos. An organization's root agent and escrow balances can never be accessed or affected by agents of another organization.
* **Delegation Hierarchy Boundary:** Maximum depth is strictly capped at **3 levels** (`Root Agent` $\rightarrow$ `Child Agent` $\rightarrow$ `Grandchild Agent`). No agent beyond depth 3 can exist or spend.
* **Payee Boundary:** Agents can only spend to explicit, narrowed whitelists of recipient accounts. Unwhitelisted accounts are rejected on-chain.
* **Temporal Boundary:** Every grant has an immutable or narrowed expiration timestamp. Once expired, all future spending authorizations are rejected.

---

## 3. Threat Model & Attacker Capabilities

### 3.1 Trusted Components
* **NEAR Blockchain Consensus & State Storage:** Assumed secure, non-malleable, and Byzantine fault tolerant.
* **ROOTBOUND Smart Contract Logic:** Immutable and self-enforcing on NEAR.
* **Organization Admin (Human Principal):** Assumed to act in the best interest of their organization, holding the power to deposit, withdraw unreserved funds, and trigger master revocations.

### 3.2 Attacker Model & Capabilities
An adversary may be:
1. **A Compromised Agent:** An agent whose LLM prompt was injected or whose private signing key was leaked.
2. **A Rogue Sub-Agent:** A child agent attempting to escalate privileges, expand budgets, or re-parent itself.
3. **A Malicious Payee:** A recipient attempting replay attacks or double-spend race conditions.
4. **An Eavesdropping Network Adversary:** Attempting to alter transaction parameters or replay signed payment intents.

The adversary is assumed to have full access to public blockchain data, the ability to submit concurrent transactions, and full control over any compromised agent's key.

---

## 4. Formal Security Guarantees & Invariants

ROOTBOUND contract code MUST enforce the following mathematical invariants at all times:

### Invariant 1: Conservation of Treasury Funds
For any organization $O$, total deposited escrow $E$ must strictly equal the sum of unallocated root balance and all delegated allocated balances:
$$E_O = Available_{Root} + Reserved_{Root} + Spent_{Root} + \sum_{C \in Children} Allocated_C$$
At no point can funds be minted, destroyed, or double-spent.

### Invariant 2: Strict Authority Attenuation (Narrowing Only)
For any child grant $C$ derived from parent grant $P$:
1. **Budget Ceiling:** The allocated budget of $C$ cannot exceed the remaining available budget of $P$:
   $$Allocated_C \le Available_P$$
2. **Recipient Set Narrowing:** Permitted payees of $C$ must be a strict subset of permitted payees of $P$:
   $$\mathcal{R}_C \subseteq \mathcal{R}_P$$
   *(If $\mathcal{R}_P = \emptyset$, the parent has an unconstrained whitelist, but once restricted, child sets can never expand.)*
3. **Temporal Bounding:** Expiration of $C$ cannot exceed expiration of $P$:
   $$Expiry_C \le Expiry_P$$
4. **Transaction Ceiling:** Maximum single-transaction limit of $C$ cannot exceed that of $P$:
   $$MaxPerTx_C \le MaxPerTx_P$$

### Invariant 3: Maximum Hierarchy Depth Ceiling
Delegation depth $D(A)$ is defined as:
* $D(Root) = 1$
* $D(Child) = 2$
* $D(Grandchild) = 3$
* $\forall A, D(A) \le 3$. Any attempt to create a grant where $D(Parent) \ge 3$ is rejected on-chain with `ErrExceededMaxDepth`.

### Invariant 4: Immutable Lineage
Once created, an agent's `parent_id` is immutable. An agent cannot re-parent itself, change its ancestor chain, or adopt a new root.

### Invariant 5: Cascade Revocation
If an agent $A$ is marked `Revoked`:
$$\forall X \in \text{Descendants}(A), \quad \text{IsCallable}(X) = \text{False}$$
Any payment authorization or delegation attempt originating from $A$ or any descendant of $A$ MUST be rejected with `ErrAncestorRevoked`.

### Invariant 6: Payment Request Uniqueness & Nonce Monotonicity
Every payment request requires a strictly monotonically increasing nonce per agent and a globally unique `request_id`:
$$\text{Nonce}_{req} = \text{Nonce}_{agent} + 1$$
Replayed or out-of-order nonces are rejected with `ErrInvalidNonce`. Duplicate `request_id` values are rejected with `ErrDuplicateRequest`.

### Invariant 7: Safe Asynchronous Settlement & Reservation Recovery
Because NEAR transfers are asynchronous:
1. When a payment is authorized, funds transition: $Available \rightarrow Reserved$.
2. If the transfer callback returns `Success`, funds transition: $Reserved \rightarrow Spent$.
3. If the transfer callback returns `Failure` (e.g. invalid recipient contract, out of gas, receiver panic), funds transition: $Reserved \rightarrow Available$.
**Zero funds remain permanently locked in `Reserved`.**

---

## 5. Security Decision Matrix

| Scenario / Attack Vector | Contract Defense Mechanism | Rejection Code / Invariant |
| :--- | :--- | :--- |
| Agent tries to spend more than its available balance | On-chain balance validation ($Amount \le Available$) | `ErrInsufficientAvailableBudget` |
| Child grant requests budget exceeding parent's available | Parent balance attenuation check | `ErrBudgetExceedsParentAuthority` |
| Child grant includes payee not permitted by parent | Whitelist subset verification ($\mathcal{R}_{child} \subseteq \mathcal{R}_{parent}$) | `ErrUnauthorizedRecipient` |
| Agent tries to delegate beyond 3 levels | Depth check ($Depth_{parent} < 3$) | `ErrExceededMaxDelegationDepth` |
| Agent tries to pay after grant expiry | Timestamp check ($BlockTimestamp \le Expiry$) | `ErrGrantExpired` |
| Sub-agent tries to spend after parent/root is revoked | Full ancestor chain traversal & status check | `ErrAncestorRevoked` |
| Malicious payee replays a previously signed request | Monotonic nonce & unique request ID table | `ErrInvalidNonce` / `ErrReplayedPayment` |
| Concurrent requests race to spend the same balance | Atomic on-chain reservation prior to dispatch | `ErrBudgetAlreadyReserved` |
| Asynchronous NEAR transfer fails or receiver panics | Callback handles failure: $Reserved \rightarrow Available$ | Safe rollback, 0 fund loss |
| Revocation occurs while a payment is in-flight | In-flight reservation holds; callback finalizes or refunds safely; no new requests permitted | Invariant 7 preserved |
