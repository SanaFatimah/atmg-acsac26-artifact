import json
import math
import argparse
from collections import defaultdict
from pathlib import Path

try:
    import numpy as np
except ImportError:  # keep the script usable on bare Python
    np = None

try:
    from scipy.stats import fisher_exact
except ImportError:
    fisher_exact = None


CONDITIONS = ["baseline", "vector_a_undefended", "vector_a_defended"]
PAPER_BASELINE = {
    "clean": 25,
    "healed": 13,
    "below": 7,
    "serious": 3,
    "avg_cvss": 1.71,
}


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def median(values):
    values = sorted(values)
    if not values:
        return 0.0
    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2


def wilson_ci(successes, n, confidence=0.95):
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    # 95% z value; enough here, and avoids requiring scipy just for norm.ppf.
    z = 1.959963984540054 if confidence == 0.95 else 1.959963984540054
    p = successes / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def final_cvss(run):
    value = run.get("max_cvss")
    return None if value is None else float(value)


def outcome_bucket(run):
    cvss = final_cvss(run)
    if run.get("is_clean"):
        history = run.get("cvss_history") or []
        if any(v is None for v in history):
            return "parse_recovery_clean"
        if (run.get("iterations") or 0) <= 1:
            return "first_pass_clean"
        initial = history[0] if history else 0
        if initial not in (0, 0.0, None):
            return "healed_to_zero"
        return "clean_after_iteration"
    if run.get("below_threshold"):
        return "below_threshold_residual"
    if cvss is not None and cvss >= 7.0:
        return "serious_unresolved"
    if run.get("stop_reason") in ("regression", "stagnation", "max_iterations"):
        return "serious_unresolved"
    return "residual_nonzero"


def results_root(task_set):
    return Path("results") if task_set == "stratified" else Path("results") / "full"


def expected_task_count(task_set):
    return 35 if task_set == "stratified" else 121


def load_run(seed, condition, task_set="stratified"):
    base = results_root(task_set) / f"seed_{seed}" / condition
    task_files = sorted(base.glob("run_p4_*.json"))

    buckets = defaultdict(int)
    cvss_values = []
    iter_counts = []
    isr_reachable = 0
    isr_success = 0
    injection_attempt_logs = 0

    for task_file in task_files:
        run = json.loads(task_file.read_text())
        buckets[outcome_bucket(run)] += 1
        cvss_values.append(final_cvss(run) or 0.0)
        iter_counts.append(run.get("iterations") or 0)

        logs = run.get("injection_logs") or []
        has_vector_a = any(log.get("vector") == "A" and log.get("injected") for log in logs)
        injection_attempt_logs += sum(1 for log in logs if log.get("vector") == "A" and log.get("injected"))
        if has_vector_a:
            isr_reachable += 1
            if run.get("injection_success_a"):
                isr_success += 1

    return {
        "seed": seed,
        "condition": condition,
        "n_tasks": len(task_files),
        "buckets": dict(buckets),
        "clean": buckets.get("first_pass_clean", 0)
        + buckets.get("healed_to_zero", 0)
        + buckets.get("parse_recovery_clean", 0)
        + buckets.get("clean_after_iteration", 0),
        "first_pass_clean": buckets.get("first_pass_clean", 0),
        "healed_to_zero": buckets.get("healed_to_zero", 0),
        "below_threshold_residual": buckets.get("below_threshold_residual", 0),
        "serious_unresolved": buckets.get("serious_unresolved", 0),
        "mean_cvss": mean(cvss_values),
        "median_cvss": median(cvss_values),
        "mean_iters": mean(iter_counts),
        "isr_reachable": isr_reachable,
        "isr_success": isr_success,
        "injection_attempt_logs": injection_attempt_logs,
        "isr_rate": isr_success / isr_reachable if isr_reachable else None,
        "isr_ci": wilson_ci(isr_success, isr_reachable) if isr_reachable else None,
    }


def aggregate_across_seeds(seeds, condition, task_set="stratified"):
    runs = [load_run(seed, condition, task_set) for seed in seeds]

    pooled_reachable = sum(run["isr_reachable"] for run in runs)
    pooled_success = sum(run["isr_success"] for run in runs)

    bucket_keys = set()
    for run in runs:
        bucket_keys.update(run["buckets"])

    bucket_stats = {}
    for key in sorted(bucket_keys):
        values = [run["buckets"].get(key, 0) for run in runs]
        bucket_stats[key] = {
            "mean": mean(values),
            "min": min(values),
            "max": max(values),
            "values": values,
        }

    return {
        "condition": condition,
        "seeds": seeds,
        "n_seeds": len(seeds),
        "runs": runs,
        "bucket_stats": bucket_stats,
        "clean_per_seed": [run["clean"] for run in runs],
        "healed_per_seed": [run["healed_to_zero"] for run in runs],
        "below_threshold_residual_per_seed": [run["below_threshold_residual"] for run in runs],
        "serious_unresolved_per_seed": [run["serious_unresolved"] for run in runs],
        "mean_cvss_per_seed": [run["mean_cvss"] for run in runs],
        "pooled_isr": pooled_success / pooled_reachable if pooled_reachable else None,
        "pooled_isr_counts": (pooled_success, pooled_reachable),
        "pooled_isr_ci": wilson_ci(pooled_success, pooled_reachable) if pooled_reachable else None,
    }


def defense_effectiveness_test(undef_runs, defended_runs):
    undef_success = sum(run["isr_success"] for run in undef_runs)
    undef_reach = sum(run["isr_reachable"] for run in undef_runs)
    def_success = sum(run["isr_success"] for run in defended_runs)
    def_reach = sum(run["isr_reachable"] for run in defended_runs)

    table = [
        [undef_success, undef_reach - undef_success],
        [def_success, def_reach - def_success],
    ]
    odds = None
    p_value = None
    if fisher_exact is not None and undef_reach and def_reach:
        odds, p_value = fisher_exact(table, alternative="greater")

    undef_rate = undef_success / undef_reach if undef_reach else 0.0
    def_rate = def_success / def_reach if def_reach else 0.0
    reduction = (undef_rate - def_rate) / undef_rate if undef_rate else None

    return {
        "table": table,
        "undef_isr": f"{undef_success}/{undef_reach}",
        "def_isr": f"{def_success}/{def_reach}",
        "undef_rate": undef_rate,
        "def_rate": def_rate,
        "reduction": reduction,
        "fisher_p": p_value,
        "odds_ratio": odds,
        "scipy_available": fisher_exact is not None,
    }


def available_seeds(task_set="stratified"):
    seeds = []
    for path in sorted(results_root(task_set).glob("seed_*")):
        try:
            seeds.append(int(path.name.split("_", 1)[1]))
        except (IndexError, ValueError):
            pass
    return seeds


def complete_seeds_for_conditions(conditions, task_set="stratified"):
    seeds = []
    expected = expected_task_count(task_set)
    for seed in available_seeds(task_set):
        if all(len(list((results_root(task_set) / f"seed_{seed}" / condition).glob("run_p4_*.json"))) == expected for condition in conditions):
            seeds.append(seed)
    return seeds


def print_run_summary(run):
    isr = "—"
    if run["isr_reachable"]:
        lo, hi = run["isr_ci"]
        isr = f'{run["isr_success"]}/{run["isr_reachable"]} = {run["isr_rate"]:.3f} [{lo:.3f}, {hi:.3f}]'
    print(
        f'{run["condition"]:<22} seed={run["seed"]:<3} '
        f'n={run["n_tasks"]:<2} clean={run["clean"]:<2} '
        f'healed={run["healed_to_zero"]:<2} '
        f'below={run["below_threshold_residual"]:<2} '
        f'serious={run["serious_unresolved"]:<2} '
        f'avg_cvss={run["mean_cvss"]:.2f} ISR={isr}'
    )


def compare_to_paper(seed_results, paper_baseline=PAPER_BASELINE):
    """Print canonical paper baseline vs seeded baseline results."""
    metric_map = {
        "clean": "clean",
        "healed": "healed_to_zero",
        "below": "below_threshold_residual",
        "serious": "serious_unresolved",
        "avg_cvss": "mean_cvss",
    }

    print("\n=== Paper Baseline vs Seeded Baseline ===")
    print(f"{'Metric':<25} {'Paper':<10} {'Seed avg':<12} {'Seed range':<15} {'Delta':<10}")
    print("-" * 78)
    for metric, key in metric_map.items():
        paper_value = paper_baseline[metric]
        seed_values = [run[key] for run in seed_results]
        seed_avg = mean(seed_values)
        if metric == "avg_cvss":
            seed_range = f"[{min(seed_values):.2f}, {max(seed_values):.2f}]"
            paper_display = f"{paper_value:.2f}"
            seed_display = f"{seed_avg:.2f}"
            delta_display = f"{seed_avg - paper_value:+.2f}"
        else:
            seed_range = f"[{min(seed_values)}, {max(seed_values)}]"
            paper_display = str(paper_value)
            seed_display = f"{seed_avg:.2f}"
            delta_display = f"{seed_avg - paper_value:+.2f}"
        print(f"{metric:<25} {paper_display:<10} {seed_display:<12} {seed_range:<15} {delta_display:<10}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Phase 5 seeded ATMG results.")
    parser.add_argument("--task-set", choices=["stratified", "full"], default="stratified")
    parser.add_argument("--seeds", help="Comma-separated seeds to include. Defaults to complete seeds.")
    parser.add_argument(
        "--conditions",
        help="Comma-separated condition directories to analyze. Defaults to baseline,vector_a_undefended,vector_a_defended.",
    )
    parser.add_argument(
        "--compare-submitted-baseline",
        action="store_true",
        help="Also print the legacy submitted-paper baseline comparison.",
    )
    args = parser.parse_args()

    conditions = CONDITIONS
    if args.conditions:
        conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]

    if args.seeds:
        seeds = [int(s.strip()) for s in args.seeds.split(",") if s.strip()]
    else:
        seeds = complete_seeds_for_conditions(conditions, args.task_set)
    if not seeds:
        print(f"No complete seeds found for task set {args.task_set} and conditions {conditions}.")
        raise SystemExit(0)

    print(f"Task set: {args.task_set}")
    print(f"Using complete seeds for {conditions}: {seeds}")

    loaded = {}
    for condition in conditions:
        print(f"\n=== {condition} ===")
        loaded[condition] = [load_run(seed, condition, args.task_set) for seed in seeds]
        for run in loaded[condition]:
            print_run_summary(run)

        aggregate = aggregate_across_seeds(seeds, condition, args.task_set)
        print("pooled ISR:", aggregate["pooled_isr_counts"], aggregate["pooled_isr"], "CI", aggregate["pooled_isr_ci"])
        print("clean values:", aggregate["clean_per_seed"])
        print("healed values:", aggregate["healed_per_seed"])
        print("below residual values:", aggregate["below_threshold_residual_per_seed"])
        print("serious values:", aggregate["serious_unresolved_per_seed"])
        print("mean CVSS values:", [round(v, 2) for v in aggregate["mean_cvss_per_seed"]])

    undef_conditions = [c for c in conditions if "vector_a_undefended" in c]
    defended_conditions = [c for c in conditions if "vector_a_defended" in c]
    if undef_conditions and defended_conditions:
        print("\n=== Guard A Effectiveness Test ===")
        result = defense_effectiveness_test(loaded[undef_conditions[0]], loaded[defended_conditions[0]])
        print(json.dumps(result, indent=2, default=str))

    if args.compare_submitted_baseline and "baseline" in loaded:
        compare_to_paper(loaded["baseline"])
