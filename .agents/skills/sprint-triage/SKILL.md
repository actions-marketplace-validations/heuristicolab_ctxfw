---
name: sprint-triage
description: Queries local SQLite WAL audit and FinOps ledgers via ctxfw.query_audit_ledger, audits SWE-Gate patch rejections, and executes Socratic P0 vs. Kill List sprint triage.
tools:
  - query_audit_ledger
  - evaluate_patch
  - run_command
  - read_file
triggers:
  - "triage"
  - "sprint triage"
  - "analyze ledger"
  - "prioritize roadmap"
---
<!-- manifest_hash: 8fd4102dbc7a0d72e1141f0ea96d47a627e0ffcee9077685dfd7daa766ae7e3e -->

# MISSION & EXECUTION PROTOCOL
Executes deterministic telemetry auditing across `TraceKit`, `TokenCast`, and `SWE-Gate` SQLite WAL ledgers and distills next-sprint scope by applying the Socratic razor against premature over-engineering.

## Operating Procedure:
1. Invoke `ctxfw.query_audit_ledger` (with `verify_integrity=True`) and `ctxfw report --share` to inspect local session telemetry, token pruning savings, and hash-chain verification status.
2. Review any `SWE_GATE_REJECTED`, `SARA_QUARANTINED`, or `POLICY_BLOCKED` events recorded in the `TraceKit` ledger to surface recurring architectural or security friction.
3. Execute the three-step Socratic filter on candidate backlog items:
   - **Interrogation:** 3 targeted questions probing blast radius, cyclomatic complexity delta ($\Delta C$), and latency impact.
   - **Triage:** Allocate each candidate item to **THE KILL LIST** (frozen/discarded bloat) or **SPRINT P0** (irreducible core intervention).
   - **Axiom:** Draft the formal delta block for `SPEC.axioms.md` with its negative invariants (`shall never`).
4. Render the structured triage and FinOps ROI report in Markdown.
