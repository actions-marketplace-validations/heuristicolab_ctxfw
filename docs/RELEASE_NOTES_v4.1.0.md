# Release Notes: ctxfw v4.1.0 — Enterprise FinOps, Asymmetric Licensing & CI/CD Gate

<!-- manifest_hash: c4a9e57cc11c29f1ab117e278bf71ddbcec97bf885c4973034a230b49821bc24 -->

`ctxfw v4.1.0` elevates the **Sovereign Pentad** into an enterprise-ready governance, FinOps, and CI/CD enforcement platform for autonomous coding agents, featuring LiveBench 2.0 model-tier optimization, offline RSA-2048 licensing, an official GitHub Action (`heuristicolab/ctxfw@v4`), and a reproducible 24-vector OWASP AISVS (`C02-01`) security benchmark.

---

## What's New in v4.1.0

### 1. LiveBench 2.0 FinOps Model Matrix & 4.2x Multi-Turn Economics (`ctxfw.finops`)
* **October 2026 Frontier Model Matrix (`model_matrix.json`)**: Native cost & LiveBench coding score comparison across Claude Opus 4.6, Claude Sonnet 4.6, GPT-5, o3, Gemini 2.5 Pro, and DeepSeek V3.2.
* **4.2x Multi-Turn Compounding Calculator**: Quantifies 15-turn stateful coding session savings factoring prompt cache writes (`1.25x`), cache reads (`0.10x`), and TTL invalidation pauses.
* **Tamper-Evident Squad Consolidation (`ctxfw report --team-merge`)**: Aggregates distributed `.jsonl` telemetry ledgers across engineering squads with SHA-256 line-level attestation.

### 2. Deterministic CI/CD Pull Request Gate & Composite GitHub Action (`ctxfw gate`)
* **Autonomous PR Gate (`ctxfw gate`)**: Evaluates unified git diffs (`--diff` / `--base`) in `< 1.0 ms` against cyclomatic complexity bounds, banned imports, and `# type: ignore` suppressions, emitting native GitHub Step Summaries (`--github-summary`).
* **Official Composite GitHub Action (`action.yml`)**: Drop-in `uses: heuristicolab/ctxfw@v4` integration for GitHub Actions workflows with zero external cloud dependencies.

### 3. Sovereign Offline RSA-2048 Licensing (`ctxfw license`)
* **Zero-Callout Cryptographic Verification**: Open-Core B2B governance (`TEAM`, `TEAM_TRIAL`, `ENTERPRISE`) verified 100% locally via RSA-2048 PKCS#1 v1.5 signatures (`CTXFW-LIC-v1.<payload>.<sig>`) and optional `revoked.json` sync.

### 4. Reproducible 24-Vector OWASP AISVS & `arXiv:2510.05244v2` Benchmark
* **100.0% Recall / 0.0% False Positive Rate**: Executable harness (`benchmarks/run_sara_security_benchmark.py`) across 16 adversarial indirect prompt injection & Trojan-Source vectors and 8 benign developer workflows (`0.33 ms` P50 / `1.72 ms` P95 latency, `0` network egress calls).

### 5. Full Sovereign Pentad SQLite WAL Synchronization (`ctxfw doctor`)
* **Check #8 (`Sovereign Pentad WAL Ledgers`)**: Synchronizes and audits all 5 local SQLite WAL ledgers (`tracekit.db`, `sara.db`, `tokencast.db` / `tokens.db`, `rules.db`, and `swegate.db`) in `%LOCALAPPDATA%/ctxfw` (`~/.local/share/ctxfw`).

---

## Verification & Upgrade

```bash
# Upgrade via PyPI
pip install --upgrade ctxfw

# Verify version, 472/472 test parity, and 8-point perimeter attestation
ctxfw --version  # Output: ctxfw 4.1.0
ctxfw doctor     # Verdict: [HEALTHY] [ATTESTED]

# Execute reproducible 24-vector SARA security benchmark
python benchmarks/run_sara_security_benchmark.py --json
```
