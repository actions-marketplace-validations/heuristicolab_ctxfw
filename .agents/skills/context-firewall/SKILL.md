---
name: context-firewall
description: Autonomous AST/CST token optimization, topological dependency pruning, and Sovereign Pentad v4.0 MCP governance for deterministic code generation.
tools:
  - resolve_context_bundle
  - prune_file
  - evaluate_spec_axioms
  - evaluate_patch
  - query_audit_ledger
triggers:
  - "prune context"
  - "resolve bundle"
  - "context firewall"
  - "ctxfw"
---
<!-- manifest_hash: 8fd4102dbc7a0d72e1141f0ea96d47a627e0ffcee9077685dfd7daa766ae7e3e -->

# Context Firewall (ctxfw v4.0.0) — Sovereign Pentad Skill

Enforces deterministic token discipline, axiomatic specification gating, indirect prompt-injection sanitization (SARA), and pre-commit architectural verification across autonomous coding workflows.

## Canonical MCP Tool Surface (5 Tools)
1. **`evaluate_spec_axioms` (Stage 1 — Axiomatic Sieve)**:
   - Validates formal specification briefs before code synthesis.
   - Enforces $\text{ACI} \ge 0.9000$, at least 5 explicit `never` / `shall never` invariants, bounded domain variables, deterministic FSM transitions $\delta(S, E)$, and a 4-class error taxonomy.
2. **`resolve_context_bundle` & `prune_file` (Stage 2 — Topological AST Pruner + TokenCast + SARA)**:
   - Preserves 100% of the focal file ($D_0$), prunes direct dependencies ($D_1$) to typed interface signatures (`...`), compacts transitive dependencies ($D_2$) to nominal declarations, and maps deep perimeter symbols ($D_3$).
   - Reactive `TokenCast` budget breaker degrades peripheral context to $D_3$ under budget pressure and halts runaway loops.
   - `SARA` (Action Induction Runtime Auth) sanitizes untrusted observations against indirect prompt injection and shell/role overrides.
3. **`evaluate_patch` (Stage 3 — SWE-Gate CI Verifier)**:
   - Audits unified git diffs prior to commit or merge, blocking `# type: ignore` suppressions, disallowed module imports, and cyclomatic complexity regressions ($\Delta C$ above threshold) even when unit tests pass.
4. **`query_audit_ledger` (Stage 4 — TraceKit Cryptographic Ledger)**:
   - Queries the append-only SQLite WAL hash-chained ledger (`GENESIS_ZERO` $\to H_n = \text{SHA256}(\text{seq} \parallel \text{prev} \parallel \text{payload})$) and verifies tamper-evident integrity across sessions.
