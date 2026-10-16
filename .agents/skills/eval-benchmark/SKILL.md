---
name: eval-benchmark
description: Executes the empirical A/B evaluation harness comparing raw baseline ingestion against ctxfw AST pruning across production repositories and transactional pipelines.
tools:
  - resolve_context_bundle
  - prune_file
  - run_command
  - read_file
triggers:
  - "run evals"
  - "benchmark"
  - "measure savings"
  - "evaluate pipeline"
---
<!-- manifest_hash: 8fd4102dbc7a0d72e1141f0ea96d47a627e0ffcee9077685dfd7daa766ae7e3e -->

# MISSION & BENCHMARK HARNESS (v4.0.0 EMPIRICAL TRILOGY)
Executes comparative context ingestion benchmarks measuring real token mass reduction, Time-to-First-Token (TTFT), and syntactic compilation integrity across `D0` (focal), `D1` (interface), `D2` (nominal), and `D3` (ambient cartography).

## Operating Procedure:
1. Locate the benchmark target module or run `ctxfw benchmark` against the active workspace (canonical reference targets: `zulip/zulip`, `apache/airflow`, `PostHog/posthog`, or `tests/`).
2. Measure baseline ingestion (unpruned raw files across $D_0$, $D_1$, and $D_2$) against `ctxfw`-processed topological bundles (`resolve_context_bundle` / `prune_file`).
3. Compute critical FinOps and latency metrics:
   - Eliminated prompt tokens and net pruning percentage (`-(Raw - Pruned) / Raw * 100`).
   - Avoided USD inference expenditure across multi-turn agent sessions (`TokenCast` integer trajectory projection).
   - Time-to-First-Token (TTFT) latency delta and AST parsing throughput (tokens/sec).
4. Audit syntactic and security integrity:
   - `100% PASS` AST compilation on pruned stubs (`0` contract or argument signature hallucinations).
   - `0` bytes leaked on MCP `stdout` outside JSON-RPC 2.0 frames.
5. Emit the Comparative Telemetry Matrix and sanitized ROI report (`ctxfw report --share`).
