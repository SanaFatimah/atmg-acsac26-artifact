import json
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

METRICS_FILE = "metrics/all_runs.json"
OUTPUT_DIR   = "metrics/charts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── LOAD DATA ────────────────────────────────────────────────────────────────
with open(METRICS_FILE, "r") as f:
    all_runs = json.load(f)

valid_runs = [r for r in all_runs if r.get("final") and "pipeline" in r["final"]]
n = len(valid_runs)
run_labels = [f"Run {i+1}\n{r['spec'][:30]}..." for i, r in enumerate(valid_runs)]
short_labels = [f"Run {i+1}" for i in range(n)]

# ── COLORS ───────────────────────────────────────────────────────────────────
BLUE   = "#2E86C1"
RED    = "#C0392B"
TEAL   = "#148F77"
AMBER  = "#CA6F1E"
PURPLE = "#6C3483"
GREEN  = "#1E8449"
GREY   = "#7F8C8D"

# ═══════════════════════════════════════════════════════════════════════════
# CHART 1 — CVSS Progression per Run (line chart)
# ═══════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(12, 6))

colors_line = [BLUE, RED, TEAL, AMBER, PURPLE]
for i, run in enumerate(valid_runs):
    prog = run["final"]["pipeline"]["cvss_progression"]
    iters = list(range(1, len(prog) + 1))
    ax.plot(iters, prog,
            marker="o", linewidth=2.5, markersize=7,
            color=colors_line[i % len(colors_line)],
            label=f"Run {i+1}: {run['spec'][:40]}...")

ax.axhline(y=7.0, color=RED, linestyle="--", linewidth=1.5, alpha=0.7, label="Threshold (7.0)")
ax.fill_between([0.5, 3.5], 0, 7.0, alpha=0.05, color=GREEN, label="Safe zone")
ax.fill_between([0.5, 3.5], 7.0, 10, alpha=0.05, color=RED,   label="Danger zone")

ax.set_title("CVSS Score Progression Across Iterations", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Iteration", fontsize=12)
ax.set_ylabel("Max CVSS Score", fontsize=12)
ax.set_ylim(0, 10.5)
ax.set_xticks([1, 2, 3])
ax.legend(fontsize=9, loc="upper right")
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/01_cvss_progression.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 1 saved — CVSS Progression")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 2 — CWE Top 10 Distribution (horizontal bar)
# ═══════════════════════════════════════════════════════════════════════════
cwe_freq = {}
for run in valid_runs:
    for it in run.get("iterations", []):
        for cwe in it["analyst"]["cwe_ids"]:
            cwe_freq[cwe] = cwe_freq.get(cwe, 0) + 1

top_cwes  = sorted(cwe_freq.items(), key=lambda x: x[1], reverse=True)[:10]
cwe_names = [c[0] for c in top_cwes]
cwe_vals  = [c[1] for c in top_cwes]

fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.barh(cwe_names[::-1], cwe_vals[::-1], color=BLUE, alpha=0.85, height=0.6)

for bar, val in zip(bars, cwe_vals[::-1]):
    ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
            str(val), va="center", fontsize=11, fontweight="bold", color=BLUE)

ax.set_title("Top 10 CWEs Found Across All Runs", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Occurrences", fontsize=12)
ax.set_xlim(0, max(cwe_vals) + 2)
ax.grid(axis="x", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/02_cwe_distribution.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 2 saved — CWE Distribution")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 3 — Severity Breakdown per Run (stacked bar)
# ═══════════════════════════════════════════════════════════════════════════
crits   = [sum(it["analyst"]["critical_count"] for it in r["iterations"]) for r in valid_runs]
highs   = [sum(it["analyst"]["high_count"]     for it in r["iterations"]) for r in valid_runs]
mediums = [sum(it["analyst"]["medium_count"]   for it in r["iterations"]) for r in valid_runs]
lows    = [sum(it["analyst"]["low_count"]      for it in r["iterations"]) for r in valid_runs]

x = np.arange(n)
w = 0.55

fig, ax = plt.subplots(figsize=(11, 6))
b1 = ax.bar(x, crits,   w, label="Critical (9.0–10.0)", color="#C0392B", alpha=0.9)
b2 = ax.bar(x, highs,   w, label="High (7.0–8.9)",      color="#E67E22", alpha=0.9, bottom=crits)
b3 = ax.bar(x, mediums, w, label="Medium (4.0–6.9)",     color="#F1C40F", alpha=0.9,
            bottom=[c+h for c,h in zip(crits, highs)])
b4 = ax.bar(x, lows,    w, label="Low (0–3.9)",          color="#2ECC71", alpha=0.9,
            bottom=[c+h+m for c,h,m in zip(crits, highs, mediums)])

ax.set_title("Severity Breakdown per Run (All Iterations Combined)", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Run", fontsize=12)
ax.set_ylabel("Number of Findings", fontsize=12)
ax.set_xticks(x)
ax.set_xticklabels(short_labels)
ax.legend(loc="upper right", fontsize=10)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/03_severity_breakdown.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 3 saved — Severity Breakdown")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 4 — Convergence vs Non-convergence (pie)
# ═══════════════════════════════════════════════════════════════════════════
converged     = sum(1 for r in valid_runs if r["final"]["pipeline"]["converged"])
not_converged = n - converged

fig, ax = plt.subplots(figsize=(7, 7))
wedges, texts, autotexts = ax.pie(
    [converged, not_converged],
    labels=["Converged\n(CVSS < 7.0)", "Not converged\n(max iterations)"],
    colors=[GREEN, RED],
    autopct="%1.0f%%",
    startangle=90,
    explode=(0.04, 0),
    textprops={"fontsize": 13}
)
for at in autotexts:
    at.set_fontsize(14)
    at.set_fontweight("bold")
    at.set_color("white")

ax.set_title("Pipeline Convergence Rate", fontsize=15, fontweight="bold", pad=20)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/04_convergence_rate.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 4 saved — Convergence Rate")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 5 — Attacks Found per Iteration per Run (grouped bar)
# ═══════════════════════════════════════════════════════════════════════════
max_iters = max(len(r["iterations"]) for r in valid_runs)
x = np.arange(max_iters)
w = 0.15
colors_bar = [BLUE, RED, TEAL, AMBER, PURPLE]

fig, ax = plt.subplots(figsize=(11, 6))
for i, run in enumerate(valid_runs):
    vals = [it["attacker"]["attacks_found"] for it in run["iterations"]]
    while len(vals) < max_iters:
        vals.append(0)
    offset = (i - n/2 + 0.5) * w
    ax.bar(x + offset, vals, w, label=f"Run {i+1}", color=colors_bar[i], alpha=0.85)

ax.set_title("Attacks Found per Iteration per Run", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Iteration", fontsize=12)
ax.set_ylabel("Number of Attacks Found", fontsize=12)
ax.set_xticks(x)
ax.set_xticklabels([f"Iteration {i+1}" for i in range(max_iters)])
ax.legend(fontsize=10)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/05_attacks_per_iteration.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 5 saved — Attacks per Iteration")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 6 — Generator Security Signals (grouped bar)
# ═══════════════════════════════════════════════════════════════════════════
val_rates    = []
param_rates  = []
hash_rates   = []

for run in valid_runs:
    iters = run["iterations"]
    total = len(iters)
    val_rates.append(   sum(1 for it in iters if it["generator"]["has_input_validation"])    / total)
    param_rates.append( sum(1 for it in iters if it["generator"]["uses_parameterised_query"])/ total)
    hash_rates.append(  sum(1 for it in iters if it["generator"]["uses_hashing"])            / total)

x = np.arange(n)
w = 0.25

fig, ax = plt.subplots(figsize=(11, 6))
ax.bar(x - w,   val_rates,   w, label="Input validation",      color=BLUE,   alpha=0.85)
ax.bar(x,       param_rates, w, label="Parameterised queries",  color=TEAL,   alpha=0.85)
ax.bar(x + w,   hash_rates,  w, label="Password hashing",       color=PURPLE, alpha=0.85)

ax.set_title("Generator — Security Signal Detection Rate per Run", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Run", fontsize=12)
ax.set_ylabel("Rate (0.0 — 1.0)", fontsize=12)
ax.set_xticks(x)
ax.set_xticklabels(short_labels)
ax.set_ylim(0, 1.15)
ax.legend(fontsize=10)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/06_generator_signals.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 6 saved — Generator Security Signals")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 7 — CVSS Reduction per Run (bar)
# ═══════════════════════════════════════════════════════════════════════════
reductions = [r["final"]["pipeline"]["cvss_reduction"] for r in valid_runs]
colors_red = [GREEN if v > 0 else RED for v in reductions]

fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.bar(short_labels, reductions, color=colors_red, alpha=0.85, width=0.5)

for bar, val in zip(bars, reductions):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
            f"{val:.1f}", ha="center", fontsize=12, fontweight="bold")

ax.axhline(y=0, color=GREY, linewidth=0.8)
ax.set_title("CVSS Reduction per Run (Initial → Final)", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Run", fontsize=12)
ax.set_ylabel("CVSS Reduction", fontsize=12)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/07_cvss_reduction.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 7 saved — CVSS Reduction")

# ═══════════════════════════════════════════════════════════════════════════
# CHART 8 — Attacker Diversity Score per Run (bar)
# ═══════════════════════════════════════════════════════════════════════════
diversity = [r["final"]["attacker"]["avg_diversity_score"] for r in valid_runs]

fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.bar(short_labels, diversity, color=AMBER, alpha=0.85, width=0.5)

for bar, val in zip(bars, diversity):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
            f"{val:.2f}", ha="center", fontsize=12, fontweight="bold", color=AMBER)

ax.axhline(y=1.0, color=GREEN, linestyle="--", linewidth=1.5, alpha=0.7, label="Perfect diversity (1.0)")
ax.set_title("Attacker — CWE Diversity Score per Run", fontsize=15, fontweight="bold", pad=15)
ax.set_xlabel("Run", fontsize=12)
ax.set_ylabel("Diversity Score (unique CWEs / total attacks)", fontsize=12)
ax.set_ylim(0, 1.2)
ax.legend(fontsize=10)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/08_attacker_diversity.png", dpi=150, bbox_inches="tight")
plt.close()
print("Chart 8 saved — Attacker Diversity")

print(f"\nAll 8 charts saved to {OUTPUT_DIR}/")