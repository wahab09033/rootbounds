# NEAR HACKATHON 2026 — Project Submission Guide
**Project Name:** ROOTBOUND  
**Track:** AI Security & Defense  
**Secondary Track:** Autonomous Business / Agent Economy  

---

## 1. Project Overview & Pitch

### Short Description (300 characters)
ROOTBOUND is an on-chain, hierarchical policy and budget guardrail on NEAR that prevents autonomous AI agents from overspending, escalating permissions, or falling victim to prompt-injected payee substitutions—enforcing immutable attenuation and 5-state invariant balance accounting.

### Full Pitch
As autonomous multi-agent networks begin handling money to purchase compute, APIs, and hire sub-agents, giving LLMs direct access to raw private keys or master treasuries is dangerous. A single prompt injection, hallucination, or rogue sub-agent can completely drain the treasury.

**ROOTBOUND** solves this by moving budget delegation, permission narrowing, and payment routing directly into a smart contract on the NEAR Protocol. Treasury funds remain safely in an escrow vault. Sub-agents are granted strictly attenuated authority (narrowed budgets, whitelisted payees, earlier expiry, and a maximum delegation depth of 3 levels). By utilizing 5-state fund accounting (`Allocated`, `Available`, `Delegated`, `Reserved`, `Spent`), ROOTBOUND ensures that asynchronous NEAR transfers never lock funds permanently on failure, concurrent double-spends are atomically blocked, and revoking any ancestor instantly paralyzes all downstream descendants.

---

## 2. NEAR Technologies & Ecosystem Tools Used

1. **NEAR Smart Contracts (Rust / `near-sdk 5.5.0`):**
   * Core policy engine, attenuation verification, and atomic balance reservation.
2. **Asynchronous Cross-Contract Promises & Typed Callbacks:**
   * Utilizes `Promise::new(recipient).transfer(amount).then(on_payment_settled)` for non-blocking, two-phase reservation settlement with automatic refund recovery on failure.
3. **Function Call Keys & Scoped Access Control:**
   * Restricts agent accounts to contract invocation without granting raw account transfer keys.
4. **Sub-Accounts & Named Accounts:**
   * Clean separation between Organization Treasury (`org.near`), Agent accounts (`pm.near`, `researcher.near`), and verified service providers (`vendor.near`).
5. **NEAR Explorer & Testnet RPC:**
   * Complete transaction transparency with verifiable receipts and execution outcomes.

---

## 3. "Do X, See Y" Verification Guide for Judges

Designed for **Claude Code, Codex, and human judges** to test in under 60 seconds:

### Step 1: Clone & Run Full Verification Suite
```bash
git clone https://github.com/wahab/rootbounds.git
cd rootbounds
python -m unittest discover -s tests -p "test_*.py" -v
```
**Expected Result ("See Y"):**
```
Ran 58 tests in 0.046s
OK
```
*58 automated unit, integration, and adversarial tests pass with zero failures.*

---

### Step 2: Run the Official Demo Script
```bash
python scripts/run_demo.py
```
**Expected Result ("See Y"):**
* Initializes the 1,000,000 yoctoNEAR treasury.
* Builds the 3-level tree: Root $\rightarrow$ PM $\rightarrow$ Researcher.
* Executes legitimate purchases: PM buys compute (15k), Researcher buys inference (8k).
* Triggers 6 adversarial attacks (Overspend, Recipient substitution, Depth 4 breach, Concurrency race, Nonce replay, Cascade revocation) and verifies on-chain rejections (`ERR_...`).
* Confirms: `Invariants 100% Satisfied: True`.

---

### Step 3: Run the Integration Pipeline
```bash
python scripts/integrate.py
```
**Expected Result ("See Y"):**
```
[1/5] Contract and 3-Tier Multi-Agent Hierarchy Initialized.
[2/5] Executing Legitimate Multi-Tier Agent Purchases... [OK]
[3/5] Firing Adversarial Attacks Through Policy Engine... [DEFENDED x6]
[4/5] Verifying Global Invariants & State Synchronization Post-Attacks... [OK]
[5/5] System Integration Successfully Verified!
```

---

### Step 4: Open the Interactive Web Dashboard
```bash
python dashboard/server.py 8080
```
**Expected Result ("See Y"):**
* Server starts on `http://127.0.0.1:8080`.
* Open in any browser:
  * Visualize the 3-tier delegation tree.
  * View live 5-state balances updating in real time.
  * Click any attack button in the **Adversarial Attack Simulator** to witness immediate on-chain rejection with structured error codes and transaction audit entries.

---

## 4. Submission Metadata

* **Project Name:** ROOTBOUND
* **Track:** AI Security & Defense
* **Lead Email:** contact@rootbound.near
* **Team Size:** Solo / Team
* **Target Network:** NEAR Testnet
* **Contract Crate:** `contracts/rootbound`
* **Test Matrix Report:** [SECURITY_VERIFICATION_REPORT.md](docs/SECURITY_VERIFICATION_REPORT.md)
* **Architecture Docs:** [ARCHITECTURE.md](docs/ARCHITECTURE.md) | [SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
