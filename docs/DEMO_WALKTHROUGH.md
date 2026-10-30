# ROOTBOUND — Demo Walkthrough & Video Recording Script
**Guide for Demo Video and Post on X**

---

## 1. Demo Video Script (2 Minutes)

### [0:00 - 0:30] Introduction: The Problem
> *"Autonomous AI agents are beginning to transact on blockchains, but giving an LLM direct access to a private key or treasury is dangerous. A single prompt injection or hallucination can drain an entire wallet. Today we introduce ROOTBOUND—an on-chain, hierarchical security guardrail for AI agents on NEAR."*

### [0:30 - 0:55] The Root-Bound Architecture & 3-Tier Tree
> *(Show Dashboard at http://localhost:8080)*
> *"Treasury funds are locked safely in an escrow vault. Here is our 3-tier hierarchy: Root Treasury delegates 500,000 to a Project Manager agent, which delegates 200,000 to a Research Agent. Notice our 5-state accounting: Allocated, Available, Delegated, Reserved, and Spent. Every child grant strictly narrows the parent's budget, payees, and expiry."*

### [0:55 - 1:25] Happy Path: Legitimate Purchases
> *(Click 'Legitimate Multi-Tier Purchase')*
> *"The PM agent autonomously procures compute for 15,000, and the Researcher procures LLM inference for 8,000. Funds transition from Available to Reserved, then to Spent upon callback confirmation. All mathematical invariants are 100% satisfied."*

### [1:25 - 1:55] Adversarial Attack Simulator
> *(Click attack buttons one by one)*
> 1. *"Now watch what happens when an attacker prompt-injects the PM agent to drain funds to an unauthorized address: Click 'Recipient Substitution'. Boom—instantly rejected on-chain with `ERR_UNAUTHORIZED_RECIPIENT`."*
> 2. *"What if a sub-agent tries to overspend? Click 'Budget Overspending': Rejected with `ERR_INSUFFICIENT_AVAILABLE_BUDGET`."*
> 3. *"What if two requests race to double-spend? Click 'Concurrent Race': Atomic reservation locks the funds; second request rejected."*
> 4. *"What if the researcher attempts to spawn a 4th-level sub-agent? Click 'Depth Limit Breach': Rejected with `ERR_EXCEEDED_MAX_DEPTH`."*
> 5. *"What if an admin revokes the PM? Click 'Cascade Revocation': The entire downstream branch is instantly paralyzed."*

### [1:55 - 2:00] Conclusion
> *"ROOTBOUND brings true mathematical safety to the autonomous agent economy on NEAR. 54 automated tests passing with zero failures. Check out our public repo on GitHub!"*

---

## 2. Template for Public Demo Post on X

```
Introducing ROOTBOUND: On-Chain Hierarchical Security & Budget Delegation for Autonomous AI Agents on @NEARProtocol 🤖🛡️

Giving autonomous AI agents master keys or raw wallet access is a security nightmare. Prompt injections, hallucinations, or rogue sub-agents can drain entire treasuries.

ROOTBOUND solves this directly in smart contracts on NEAR:
🔒 Zero Master Custody: Funds locked in on-chain escrow
🌲 Strict Attenuation: Sub-agents can only narrow budgets & whitelists
🛑 Capped Depth: Strictly enforced 3-level delegation ceiling
⚡ 5-State Accounting: Atomic reservations prevent async double-spends
💥 Attack Simulator: 10 adversarial exploits defeated with 100% invariant conservation

Built for the @NEAR_hckthn (Track: AI Security & Defense).

Code & "Do X, See Y" reproduction steps:
👉 https://github.com/wahab/rootbounds

#NEAR #AI #AutonomousAgents #NEARHackathon #Web3Security
```
