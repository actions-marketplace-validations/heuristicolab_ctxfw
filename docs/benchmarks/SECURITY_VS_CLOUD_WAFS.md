<!-- manifest_hash: f09d9e31251ef9ce9fc2c476b44c88cef35607497674e6841818ced0f6e7ca93 -->
# AI Agent Governance & Prompt Injection Firewalls: `CTXFW` vs. Cloud Runtime WAFs (`Lakera Guard`, `Palo Alto Prisma AIRS`, `Protect AI`, `Cloudflare Firewall for AI`)

**Canonical Version:** `ctxfw v4.1.0`  
**Security Attestation:** Glama MCP Registry **Grade A (100/100 Security)** · Skills Directory **Grade A (100/100 across 120 static patterns)**  
**Empirical Benchmark Dossier:** [`docs/benchmarks/TRILOGY_EMPIRICAL_BENCHMARK.md`](TRILOGY_EMPIRICAL_BENCHMARK.md) (`471/471` deterministic tests passing)

---

## 1. Executive Summary: The Pre-Ingestion AST/MCP Boundary vs. Cloud Runtime Proxies

When enterprise CISOs, Staff Engineers, and AI Platform Architects evaluate **AI Agent Governance & Prompt Injection Firewalls**, the market divides into two distinct architectural layers that solve fundamentally different attack surfaces:

1. **Cloud Runtime API Firewalls (`Lakera Guard`, `Palo Alto Networks Prisma AIRS`, `Protect AI Guardian`, `Cloudflare Firewall for AI`)**:
   - **What they protect:** HTTP/REST inference traffic between customer-facing chatbots and cloud LLM APIs.
   - **How they work:** Probabilistic classifier models or cloud edge proxies inspecting assembled text prompts over the network.
   - **Enterprise Limitation for Coding & MCP Agents:** Require transmitting proprietary source code and tool outputs to an external cloud inspection endpoint (**Network Egress**), add `30 ms – 250 ms` of network round-trip latency per call, and **save 0% of peripheral AST token bloat**.
2. **Local Pre-Ingestion Context & MCP Firewall (`CTXFW // Context Firewall v4.1.0`)**:
   - **What it protects:** Autonomous coding agents (`Claude Code`, `Cursor`, `Windsurf`, `Antigravity`, `Aider`) and Model Context Protocol (`MCP`) tool pipelines **before** context assembly leaves the developer workstation or air-gapped CI runner.
   - **How it works:** Deterministic in-memory **Tree-Sitter AST/CST topological compaction** ($D_0 \to D_3$) combined with **`ctxfw.sara` (Sovereign Agent Induction Firewall)**, **`ctxfw.rules` (Normative Rules Enforcer)**, **`TokenCast` (FinOps Circuit Breaker)**, and **`TraceKit` (SHA-256 Hash-Chained Audit Ledger)**.
   - **Enterprise Advantage:** **100% Zero-Egress** (runs strictly in local RAM / stdio / loopback), **< 5.0 ms warm cache latency** (`437,351 tokens/sec` AST slicing throughput), and **cuts peripheral dependency token costs by 42.96% to 90.26%** while blocking indirect prompt injections and Trojan-Source bidi escapes deterministically.

---

## 2. Head-to-Head Architectural & Benchmark Matrix

| Evaluation Dimension | **CTXFW (`Context Firewall v4.1.0`)** | **Lakera Guard** (`Check Point`) | **Palo Alto Networks Prisma AIRS** | **Protect AI Guardian / Rebuff** | **Cloudflare Firewall for AI** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Protection Layer** | **Pre-Ingestion AST, Repository Context & MCP Tool Boundary (`stdio` / Local Proxy)** | Runtime HTTP Prompt / Response API Classifier | Enterprise Cloud Network & Runtime AI Security | ML Supply Chain & Runtime LLM Guardrails | Edge WAF for HTTP LLM API Endpoints |
| **Data Sovereignty / Egress** | **100% Zero-Egress (Air-Gapped Local RAM & SQLite WAL)** | Cloud API Egress (or heavy Enterprise container) | Cloud Inspection / Network Appliance | Cloud / Self-Hosted ML Inference | Cloud Edge Proxy Egress |
| **Indirect Prompt Injection Defense (`MCP` / Tool I/O)** | **Deterministic `ctxfw.sara`**: Blocks `<system>`, `[INST]`, role hijacks, null-bytes & Trojan-Source Unicode bidi escapes (`U+202E`) | Probabilistic ML Bert/Transformer classifier | Network + Runtime policy inspection | Heuristic + Vector DB + ML classifier | Edge WAF regex + LLM scoring |
| **Token & FinOps Cost Reduction** | **42.96% – 90.26% $D_1$ AST Bloat Eliminated** (~**$87.70 USD saved per 1K calls**) | **0% token reduction** (bills per API call) | **0% token reduction** | **0% token reduction** | **0% token reduction** |
| **Focal Code Signal Preservation ($D_0$)** | **100.00% Byte-for-Byte Identical (`AXIOM-3`)** — Zero focal loss | N/A (Pass-through text) | N/A (Pass-through text) | N/A (Pass-through text) | N/A (Pass-through text) |
| **Inspection Latency (P95)** | **< 0.8 ms (Warm WAL Cache) / 44–138 ms (Full Monorepo Cold AST)** | `35 ms – 120 ms` (Network + ML inference) | `25 ms – 90 ms` (Inline proxy) | `40 ms – 150 ms` | `15 ms – 60 ms` (Edge hop) |
| **Cryptographic Audit Trail** | **Built-in `TraceKit` (`tracekit.db`)**: 283-byte canonical SHA-256 Merkle chain | Cloud dashboard logs | Panorama / Strata Cloud logs | Guardian telemetry logs | Cloudflare dashboard logs |
| **MCP Ecosystem Native Support** | **Native 5-Tool JSON-RPC `stdio` Server (`Glama Grade A 100/100`)** | No native AST/MCP `stdio` compactor | External MCP discovery only | No native AST/MCP compactor | No local `stdio` MCP compactor |
| **Setup Complexity** | **1 Command (< 10 sec)**: `pipx install ctxfw && ctxfw init` | API keys + SDK wrapper refactoring | TLS decryption + network routing | SDK + Vector DB setup | DNS / Cloudflare Worker proxy |

---

## 3. Resolving the 3 Core Enterprise Objections (Empirical Evidence)

### Objection 1: *"Is there independent benchmark evidence against real production codebases and prompt injection vectors?"*
- **Independent Security Certification (`100/100 Grade A`)**:
  - Audited by the **[Glama MCP Registry](https://glama.ai/mcp/servers/heuristicolab/ctxfw)** (`Grade A · Security 100/100 · TDQS 4.5/5.0`) and **[Skills Directory](https://www.skillsdirectory.com/authors/heuristicolab)** (`100/100 Security` across 120 static vulnerability patterns).
- **Deterministic Prompt Injection & Trojan-Source Sieve (`ctxfw.sara` + `ctxfw.rules`)**:
  - Unlike probabilistic LLM guards that suffer from adversarial suffix bypasses, `ctxfw.sara` enforces deterministic lexical and structural invariants over untrusted tool outputs, social/web payloads, and MCP responses:
    1. **Role & Delimiter Hijack Quarantine**: Immediate interception of `<system>`, `</system>`, `[INST]`, `[/INST]`, `<<SYS>>`, and `IGNORE ALL PREVIOUS INSTRUCTIONS` directives (`QUARANTINE_TOOL` / `STRIP_COMMANDS`).
    2. **Trojan-Source & Invisible Unicode Neutralization**: Deterministic stripping/quarantine of bidirectional control characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`) and null-byte injection (`\x00`).
    3. **Iterative Path-Traversal Normalization (`ctxfw.rules`)**: 3-round canonical path resolution blocking `../` escapes, `.env` exfiltration, and unauthorized shell invocations before execution.
- **Production Monorepo Validation (`TRILOGY_EMPIRICAL_BENCHMARK.md`)**:
  - Verified in isolated Ubuntu 24.04 LTS containers across **[`zulip/zulip`](https://github.com/zulip/zulip)** (`-42.96%` Interface / `-78.20%` Nominal $D_1$ reduction, `44.1 ms`), **[`PostHog/posthog`](https://github.com/PostHog/posthog)** (`-59.53%` $D_1$ reduction, `50.2 ms`), and **[`apache/airflow`](https://github.com/apache/airflow)** (`-66.90%` Interface / `-90.26%` Nominal $D_1$ reduction, **40,428 bloat tokens pruned**, `437,351 tok/s` throughput, `0 bytes` stdio leak).

### Objection 2: *"Does pruning the AST risk losing signal that the coding agent needs?"*
- **Mathematical Guarantee — `AXIOM-3` (100% Zero Focal Degradation)**:
  - **`CTXFW` NEVER modifies, summarizes, or prunes the active focal file ($D_0$) being edited or debugged.** $D_0$ is preserved **100% byte-for-byte**.
  - Compaction is strictly applied to **peripheral imported dependencies ($D_1, D_2$)** where the agent only needs the **typed function signature, class hierarchy, return types, and docstrings** (`...` interface stubs) rather than 5,000 lines of internal helper implementation.
  - Furthermore, **$D_3$ Ambient Cartography** injects a bounded flat symbol catalog ($\le 1,000$ tokens) up to 3 hops deep, **increasing** agent reasoning accuracy by eliminating *Lost-in-the-Middle* attention degradation. Every compacted output is verified via `ast.parse()` (`100% PASS` syntactic validity).

### Objection 3: *"Does a 6-subsystem firewall add operational complexity?"*
- **Zero-Touch 1-Command Provisioning (< 10 Seconds)**:
  - All 6 subsystems (`Tree-Sitter Pruner`, `TraceKit`, `TokenCast`, `RulesCompiler`, `SARA`, `SWE-Gate`) ship inside a single pure-Python/C-binding package (`pip install ctxfw`) with **zero external databases or cloud accounts required**.
  - Running `ctxfw init --global` (or `ctxfw install --claude`) automatically discovers and configures **Claude Code CLI, Claude Desktop, Cursor, and Windsurf** with atomic `.bak.<timestamp>` backups and `3x` idempotency.
  - Running `ctxfw doctor` verifies the entire stack in `< 2 seconds`.

---

## 4. Recommended Enterprise Defense-in-Depth Architecture

`CTXFW` and Cloud Runtime WAFs (`Lakera Guard`, `Prisma AIRS`, `Cloudflare Firewall for AI`) are **complementary layers** in an enterprise AI stack:
- **Use `CTXFW` at the Developer Workstation, IDE, MCP Server, and CI/CD Pre-Commit Layer (`Layer 0 / Pre-Ingestion`)**: To guarantee **Zero-Egress** code sovereignty, cut LLM API token bills by **43%–72%+**, enforce `.cursorrules`/`CLAUDE.md` deterministically, and sanitize MCP tool observations locally.
- **Use `Lakera Guard` / `Prisma AIRS` / `Cloudflare` at the Public Cloud API Edge (`Layer 7 / Post-Deployment`)**: To monitor external end-user chat traffic hitting production customer-support endpoints.
