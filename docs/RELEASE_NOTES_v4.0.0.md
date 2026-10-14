# Release Notes: ctxfw v4.0.0 — The Sovereign Pentad Architecture

`ctxfw v4.0.0` marks the major architectural release of the **Sovereign Pentad**: five hermetically vendored, cryptographically attested defense-in-depth subsystems integrated in closed loop with the Model Context Protocol (`ctxfw.mcp`) and the topological AST/CST pruning engine.

---

## What's New in v4.0.0

### 1. TraceKit Cryptographic Audit Ledger (`ctxfw.audit` — Milestone M1)
* **283-Byte Canonical Preimage Sealing**: Every tool call, circuit breaker transition, policy violation, induction quarantine, and patch audit is sealed into an append-only SHA-256 hash chain (`tracekit.db`).
* **Fail-Closed Tamper Latch**: Any in-place mutation or out-of-order block insertion triggers SQLite WAL immutability guards and latches the session state.
* **CLI & Doctor Verification**: Inspect chain integrity via `ctxfw trace verify` and `ctxfw doctor` (Check #7: TraceKit Ledger Audit).

### 2. TokenCast Forecaster & Reactive Circuit Breaker (`ctxfw.budget` — Milestone M2)
* **100% Integer Trajectory Forecasting**: Zero-float (`ceil_div`, `ceil_isqrt`) token consumption projection across multi-turn sessions (`< 0.02 ms` median latency).
* **Closed-Loop Topological Degradation**: When the session budget crosses soft thresholds (`TRIPPED`), `resolve_context_bundle` automatically forces `FORCE_D3_PRUNING` (collapsing peripheral $D_1/D_2$ modules to compact $D_3$ stubs); when hard limits are breached (`HALTED`), execution halts fail-closed (`EMERGENCY_HALT`).

### 3. Normative Rules Compiler & Enforcer (`ctxfw.rules` — Milestone M2)
* **Deterministic Rule Compilation**: Extracts negative normative clauses (`never`, `must not`, `shall not`, `do not`) from `.cursorrules`, `CLAUDE.md`, YAML, and Markdown into immutable AST, import, command, and path guards.
* **3-Round Path Traversal Shield**: Iterative percent-decoding (`normalize_path`) blocks double/triple URL-encoded path traversal (`%252e%252e`) and protected file access (`.env`, `/etc/shadow`) prior to MCP tool execution.

### 4. SARA Agent Induction Firewall (`ctxfw.sara` — Milestone M3)
* **Lexical Sanitizer & Induction Parser**: Normalizes NFKC, strips zero-width and ANSI escape sequences, and scores untrusted observations in $[0.0, 1.0]$ across `SHELL_COMMAND`, `FILE_PATH_ACCESS`, `ROLE_OVERRIDE`, and `HIDDEN_ESCAPE`.
* **Runtime Authorization Gate & Quarantine Vault**: Neutralizes role-override markers (`<system>`, `[INST]`) via `STRIP_COMMANDS` (`< 0.20 ms` median latency) and blocks destructive shell inductions or Trojan-Source bidirectional overrides via `QUARANTINE_TOOL`, isolating poisoned payloads in `sara_quarantine_payloads` (`QRN-<id>`).

### 5. SWE-Gate Deterministic CI Verifier (`ctxfw.swegate` — Milestone M4)
* **Lexical Unified-Diff & Complexity Inspector**: Evaluates unified diffs (`<= 1 MiB`) in `< 0.50 ms` without executing untrusted ASTs.
* **Closed-Loop Patch Gate (`evaluate_patch`)**: Rejects patches (`REJECT_ARCHITECTURAL_VIOLATION`) that introduce `# type: ignore` suppressions, disallowed module imports, or excessive cyclomatic complexity deltas ($\Delta CC > \text{max\_cyclomatic\_delta}$), even when 100% of functional unit tests pass.

---

## Verification & Upgrade

```bash
# Upgrade via PyPI
pip install --upgrade ctxfw

# Verify version and 7-point perimeter attestation
ctxfw --version  # Output: ctxfw 4.0.0
ctxfw doctor     # Verdict: [HEALTHY] [ATTESTED]

# Verify cryptographic audit chain
ctxfw trace verify
```
