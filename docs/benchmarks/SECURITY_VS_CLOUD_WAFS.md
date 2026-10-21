<!-- manifest_hash: d7faafa9f4778840246212f483a520aed6d52526569a9a8b2303e3a5a3ab830e -->
# Comparative Benchmark: CTXFW vs. Cloud AI Runtime Firewalls (Lakera Guard, Palo Alto Prisma AIRS, Protect AI, Cloudflare Firewall for AI)

**Canonical Version:** `v4.0.1`  
**Attestation Status:** `VERIFIED` (`ACI: 1.0000` · `467/467` Deterministic Test Suite)  
**Target Domain:** AI Agent Governance, Indirect Prompt Injection Defense (`SARA`), & Pre-Ingestion AST Context Compaction (`MCP` & Local Proxy)

---

## 1. Executive Architecture Distinction: Pre-Ingestion Local AST vs. Cloud HTTP Edge WAFs

Enterprise AI security teams evaluating **Lakera Guard** (Check Point), **Palo Alto Networks Prisma AIRS**, **Protect AI Guardian**, or **Cloudflare Firewall for AI** face a structural gap when governing autonomous coding agents (**Claude Code**, **Cursor**, **Windsurf**, **Aider**, **GitHub Copilot**):

1. **Cloud Runtime WAFs operate at the HTTP API edge** *after* proprietary source code, peripheral dependencies, and untrusted MCP tool outputs have already been serialized into the prompt and transmitted off-premise.
2. **CTXFW (`Context Firewall`) operates at the Pre-Ingestion AST & MCP `stdio` boundary (`100% Zero-Egress`)** *before* any token leaves the developer workstation or CI/CD runner.

---

## 2. Head-to-Head Capability & Performance Matrix

| Security & FinOps Dimension | **CTXFW (`v4.0.1` Sovereign Pentad)** | **Lakera Guard** (`Check Point`) | **Palo Alto Networks Prisma AIRS** | **Protect AI Guardian / Recon** | **Cloudflare Firewall for AI** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Enforcement Layer** | **Local Pre-Ingestion AST & MCP `stdio` / Loopback Proxy** | Cloud HTTP Prompt API | Network & Cloud API Runtime | Model Artifact & Runtime API | Cloud Edge WAF Proxy |
| **Data Residency & Egress** | **100% Zero-Egress (Air-Gapped RAM + Local SQLite WAL)** | Cloud API Egress Required | Cloud / Virtual Appliance | Cloud / VPC Deployment | Cloud Edge Egress |
| **Indirect Prompt Injection Defense (`MCP` Tool Outputs)** | **Deterministic `ctxfw.sara`** (`<system>`, `[INST]`, role override & Unicode bidi `U+202E` Trojan-Source quarantine) | Probabilistic ML Classifier | Network / API Policy Inspection | Heuristic & ML Scanner | Edge WAF Prompt Classifier |
| **AST Token Compaction (`FinOps`)** | **42.96% – 90.26% $D_1$ Perimeter Reduction** (`437,351 tok/s`) | **0% (No AST Compaction)** | **0% (No AST Compaction)** | **0% (No AST Compaction)** | **0% (No AST Compaction)** |
| **Focal Code Signal Preservation ($D_0$)** | **100% Byte-for-Byte Preservation (`AXIOM-3`)** | N/A (Pass-through) | N/A (Pass-through) | N/A (Pass-through) | N/A (Pass-through) |
| **Cryptographic Audit Trail** | **Append-Only SHA-256 Hash Chain (`TraceKit` 283-byte blocks)** | Cloud Dashboard Logs | Panorama / Strata Cloud Logs | Central Audit Logs | Cloudflare HTTP Logs |
| **Pre-Commit Architectural Gate** | **Built-in `SWE-Gate` (`evaluate_patch`: cyclomatic $\Delta C$, banned imports, `# type: ignore` ban)** | Not Included | Not Included | Not Included | Not Included |
| **Median Inspection Latency** | **< 0.8 ms (Warm WAL Cache) / < 5.0 ms Engine** | `35 ms – 120 ms` (Network RTT) | `25 ms – 90 ms` (Inline Proxy) | `30 ms – 110 ms` | `15 ms – 80 ms` (Edge RTT) |
| **Onboarding Complexity** | **Single Command (`pipx install ctxfw && ctxfw init`)** | SDK Integration + API Keys | Enterprise Network Provisioning | Platform Deployment | DNS / Worker Routing |

---

## 3. Empirical Answers to Common Enterprise Architecture Questions

### Q1: How does CTXFW defend against Indirect Prompt Injection compared to Lakera Guard or Prisma AIRS?
Autonomous coding agents frequently read untrusted external data via MCP tools (GitHub issues, third-party dependency docstrings, PR diffs, or logs). **CTXFW's `SARA` engine (`ctxfw.sara`)** inspects every raw tool observation deterministically in `< 5.0 ms`:
- **Lexical & Trojan-Source Sanitization (`LexicalSanitizer`)**: Immediately rejects null-byte smuggling and invisible Unicode bidirectional control characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`) before they enter the LLM context window.
- **Deterministic Induction Scoring (`InductionParser` & `RuntimeAuthorizationGate`)**: Detects imperative override directives (`ignore previous instructions`, `<system>`, `[INST]`, unauthorized shell/file-mutation induction) and enforces a 3-tier fail-closed verdict:
  - `VerdictKind.ALLOW` ($R < 0.35$)
  - `VerdictKind.STRIP_COMMANDS` ($0.35 \le R < 0.70$)
  - `VerdictKind.QUARANTINE_TOOL` ($R \ge 0.70$), sealing the forensic digest into `sara.db` and `tracekit.db`.

### Q2: Does AST pruning risk losing signal or breaking code generation?
**No (`0%` focal signal loss).** Under **AXIOM-3 (Zero Focal Degradation)**:
1. **$D_0$ (Active Focal File under edit)** is preserved **100% byte-for-byte** without modification.
2. **$D_1$ & $D_2$ (Imported Peripheral Dependencies)** retain **100% of their public class hierarchies, function signatures, type annotations, return types, and docstrings**, replacing only internal function bodies with valid `...` stubs.
3. **$D_3$ (Ambient Cartography Manifest)** provides a compact ($\le 1,000$ token) symbol catalog of the surrounding repository, preventing hallucinated imports while cutting peripheral token spend by **42.96% to 90.26%** (verified across [`zulip/zulip`](TRILOGY_EMPIRICAL_BENCHMARK.md), [`PostHog/posthog`](TRILOGY_EMPIRICAL_BENCHMARK.md), and [`apache/airflow`](TRILOGY_EMPIRICAL_BENCHMARK.md)).

### Q3: Does CTXFW add operational complexity to developer workflows?
**Zero workflow friction.** Unlike cloud proxies that require TLS certificate interception, API key rotation, or SDK wrappers, CTXFW installs in **under 10 seconds** via a single idempotent command:
```bash
pipx install ctxfw && ctxfw init
```
It automatically detects **Claude Code**, **Claude Desktop**, **Cursor**, and **Windsurf**, creates a timestamped `.bak` backup of existing IDE configs, and runs transparently over local `stdio` JSON-RPC.
