# manifest_hash: 17115315fea30a3c46ca0d986ddeb8eccd3113864a9403383c8002fbed6bd050
"""
scripts/render_cast_to_svg.py — Deterministic Asciinema (.cast) to Animated CSS SVG Compiler (v4.1.1)
manifest_hash: 17115315fea30a3c46ca0d986ddeb8eccd3113864a9403383c8002fbed6bd050

Compiles docs/benchmarks/ctxfw_v411_90s_showcase.cast into a pure CSS @keyframes
animated terminal SVG (logos/ctxfw_v411_live_demo.svg) 100% compatible with GitHub's
Camo image proxy (zero <script> tags, strict XML validation, < 150 KB).
"""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parent.parent
CAST_PATH = REPO_ROOT / "docs" / "benchmarks" / "ctxfw_v411_90s_showcase.cast"
SVG_PATH = REPO_ROOT / "logos" / "ctxfw_v411_live_demo.svg"

ANSI_COLOR_MAP = {
    "1;36": "#38bdf8",  # Cyan bold
    "1;37": "#f8fafc",  # White bold
    "1;32": "#34d399",  # Emerald green bold
    "0;32": "#6ee7b7",  # Soft green
    "1;33": "#fbbf24",  # Amber gold bold
    "1;31": "#f87171",  # Red bold
    "1;35": "#c084fc",  # Purple bold
    "1;41;37": "#fda4af",  # Alert badge crimson text
}

ANSI_TOKEN_RE = re.compile(r"\x1b\[([0-9;]+)m")


def _ansi_line_to_tspans(raw_line: str) -> str:
    """Converts a single ANSI-colored line into escaped SVG <tspan> fragments."""
    line = raw_line.replace("\r", "").replace("\n", "")
    if not line.strip():
        return ""

    parts = ANSI_TOKEN_RE.split(line)
    # parts[0] is text before first code, then pairs of (code, text)
    out: list[str] = []
    current_color = "#cbd5e1"
    current_weight = "normal"

    if parts[0]:
        out.append(f'<tspan fill="{current_color}">{html.escape(parts[0])}</tspan>')

    idx = 1
    while idx < len(parts):
        code = parts[idx]
        text_seg = parts[idx + 1] if (idx + 1) < len(parts) else ""
        idx += 2
        if code == "0":
            current_color = "#cbd5e1"
            current_weight = "normal"
        else:
            current_color = ANSI_COLOR_MAP.get(code, "#e2e8f0")
            current_weight = "bold" if code.startswith("1;") else "normal"
        if text_seg:
            weight_attr = ' font-weight="bold"' if current_weight == "bold" else ""
            out.append(
                f'<tspan fill="{current_color}"{weight_attr}>{html.escape(text_seg)}</tspan>'
            )

    return "".join(out)


def compile_cast_to_svg(
    cast_path: Path = CAST_PATH,
    svg_path: Path = SVG_PATH,
    duration_s: float = 18.0,
) -> dict:
    raw_lines = cast_path.read_text(encoding="utf-8").splitlines()
    events: list[tuple[float, str]] = []
    for ln in raw_lines[1:]:
        if not ln.strip():
            continue
        ts, ev_type, text = json.loads(ln)
        if ev_type == "o":
            events.append((float(ts), str(text)))

    max_ts = max((e[0] for e in events), default=14.0)
    width_px = 920
    line_height = 20
    top_padding = 58
    bottom_padding = 26
    height_px = top_padding + len(events) * line_height + bottom_padding

    css_rules: list[str] = []
    text_nodes: list[str] = []

    for i, (ts, raw_text) in enumerate(events):
        # Map timestamp into [3%, 78%] of the animation cycle so final frame holds for ~4 seconds
        pct_appear = round(3.0 + (ts / max(max_ts, 0.1)) * 72.0, 2)
        pct_pre = max(0.0, round(pct_appear - 0.5, 2))
        css_rules.append(
            f".L{i}{{opacity:0;animation:K{i} {duration_s:.1f}s linear infinite}}"
            f"@keyframes K{i}{{0%,{pct_pre}%{{opacity:0}}{pct_appear}%,94%{{opacity:1}}98%,100%{{opacity:0}}}}"
        )
        y_pos = top_padding + (i + 1) * line_height
        tspans = _ansi_line_to_tspans(raw_text)
        if tspans:
            text_nodes.append(
                f'  <text x="24" y="{y_pos}" class="L{i}" xml:space="preserve">{tspans}</text>'
            )

    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width_px} {height_px}" width="100%" role="img" aria-label="CTXFW v4.1.1 Live Terminal Demo: SARA Zero-Trust Gate, Polyglot AST Context Pruner, and M2M Sovereign Vault">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#090d16"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <style>
      .term-font {{
        font-family: 'JetBrains Mono', 'Fira Code', 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 12.5px;
      }}
      .title-font {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        font-size: 12px;
        font-weight: 600;
      }}
      {"".join(css_rules)}
    </style>
  </defs>

  <!-- Outer Terminal Frame -->
  <rect width="{width_px}" height="{height_px}" rx="12" ry="12" fill="url(#bgGrad)" stroke="#1e293b" stroke-width="1.5"/>

  <!-- Top Window Bar -->
  <rect x="1" y="1" width="{width_px - 2}" height="40" rx="11" ry="11" fill="#111827"/>
  <line x1="0" y1="41" x2="{width_px}" y2="41" stroke="#1e293b" stroke-width="1"/>

  <!-- Window Traffic Lights -->
  <circle cx="22" cy="21" r="6" fill="#ef4444"/>
  <circle cx="42" cy="21" r="6" fill="#f59e0b"/>
  <circle cx="62" cy="21" r="6" fill="#10b981"/>

  <!-- Window Title -->
  <text x="{width_px // 2}" y="25" text-anchor="middle" fill="#94a3b8" class="title-font">ctxfw v4.1.1 — SARA Prompt Injection Gate (0.38ms) + AST Pruner (-66.1%) + M2M Vault</text>

  <!-- Live Badge -->
  <rect x="{width_px - 118}" y="11" width="98" height="20" rx="4" fill="#064e3b" stroke="#10b981" stroke-width="0.8"/>
  <circle cx="{width_px - 104}" cy="21" r="3.5" fill="#34d399"/>
  <text x="{width_px - 94}" y="25" fill="#ecfdf5" class="term-font" font-size="10.5px" font-weight="bold">ACI 1.0000</text>

  <!-- Terminal Output Lines -->
  <g class="term-font">
{chr(10).join(text_nodes)}
  </g>
</svg>
"""

    # Enforce negative invariants before writing
    assert "<script" not in svg_content.lower(), "SVG shall never contain <script> tags"
    svg_bytes = len(svg_content.encode("utf-8"))
    assert 2000 <= svg_bytes <= 150000, f"SVG byte size {svg_bytes} outside [2000, 150000]"

    # Validate strict XML well-formedness
    ET.fromstring(svg_content)

    svg_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.write_text(svg_content, encoding="utf-8")
    svg_sha256 = hashlib.sha256(svg_content.encode("utf-8")).hexdigest()

    print(f"[OK] Compiled animated SVG: {svg_path} ({svg_bytes:,} bytes, {len(events)} lines)")
    print(f"[OK] XML Validation       : PASSED (0 <script> tags, Camo-safe CSS @keyframes)")
    print(f"[OK] SVG SHA-256 Seal     : {svg_sha256}")
    return {
        "svg_path": str(svg_path),
        "svg_bytes": svg_bytes,
        "line_count": len(events),
        "svg_sha256": svg_sha256,
    }


if __name__ == "__main__":
    compile_cast_to_svg()
