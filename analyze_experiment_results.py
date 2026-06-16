#!/usr/bin/env python3
"""
Aggregate ATMG condition summaries into tables and simple plots.

Examples:
  python3 analyze_experiment_results.py \
    --condition baseline=data/phase4_summary_merged_1778463835.json

  python3 analyze_experiment_results.py \
    --condition baseline=data/baseline.json \
    --condition undefended=data/undefended.json \
    --outdir analysis_outputs

  python3 analyze_experiment_results.py \
    --auto 'data/experiment_*.json' \
    --outdir analysis_outputs
"""

import argparse
import csv
import json
import os
import re
from collections import Counter, defaultdict


CVSS_THRESHOLD = 7.0


def extract_cwe(task_id):
    match = re.search(r"CWE-\d+", task_id or "")
    return match.group(0) if match else "UNKNOWN"


def as_float(value, default=0.0):
    return default if value is None else float(value)


def load_condition(spec):
    if "=" not in spec:
        raise ValueError(f"Condition must be name=path, got: {spec}")

    name, path = spec.split("=", 1)
    return load_path(path, fallback_name=name)


def normalize_item(item, condition_name):
    history = item.get("cvss_history") or []
    final = as_float(item.get("max_cvss"))
    initial = as_float(history[0], final) if history else final
    injection_logs = item.get("injection_logs") or []
    vector_a_injected = any(
        log.get("vector") == "A" and log.get("injected") for log in injection_logs
    )
    vector_b_injected = any(
        log.get("vector") == "B" and log.get("injected") for log in injection_logs
    )

    iterations = item.get("iterations", item.get("iteration", 0)) or 0
    return {
        "condition": item.get("condition") or condition_name,
        "run_id": item.get("run_id", ""),
        "task_id": item.get("task_id", ""),
        "cwe": extract_cwe(item.get("task_id", "")),
        "iterations": iterations,
        "is_clean": item.get("is_clean") is True,
        "below_threshold": item.get("below_threshold"),
        "stop_reason": item.get("stop_reason"),
        "stagnation_detected": item.get("stagnation_detected", False),
        "regression_detected_loop": item.get("regression_detected_loop", False),
        "initial_cvss": initial,
        "final_cvss": final,
        "cvss_delta": round(initial - final, 2),
        "cvss_history": history,
        "first_iteration_clean": len(history) == 1 and final == 0.0 and item.get("is_clean") is True,
        "healed_to_zero": len(history) > 1 and initial > 0.0 and final == 0.0,
        "vector_a_injected": vector_a_injected,
        "vector_b_injected": vector_b_injected,
        "injection_success_a": item.get("injection_success_a") is True,
        "injection_success_b": item.get("injection_success_b") is True,
        "guard_b_stripped_count": len(item.get("guard_b_stripped") or []),
        "backdoor_evidence_count": len(item.get("backdoor_evidence") or []),
        "failed": item.get("failed") is True,
        "error": item.get("error", ""),
    }


def rows_from_data(data, fallback_name):
    if isinstance(data, list):
        return [normalize_item(item, fallback_name) for item in data]

    if "summary" in data:
        return [normalize_item(item, fallback_name) for item in data.get("summary", [])]

    if "results" in data:
        condition = data.get("condition") or {}
        name = condition.get("name") if isinstance(condition, dict) else fallback_name
        return [normalize_item(item, name or fallback_name) for item in data.get("results", [])]

    if "all_results" in data:
        rows = []
        for condition_name, results in data.get("all_results", {}).items():
            rows.extend(normalize_item(item, condition_name) for item in results)
        return rows

    return []


def load_path(path, fallback_name=None):
    with open(path) as f:
        data = json.load(f)

    name = fallback_name
    if isinstance(data, dict):
        condition = data.get("condition")
        if isinstance(condition, dict) and condition.get("name"):
            name = condition["name"]
    name = name or os.path.splitext(os.path.basename(path))[0]

    return name, path, data.get("statistics", {}) if isinstance(data, dict) else {}, rows_from_data(data, name)


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def classify(row):
    if row["is_clean"] and row["final_cvss"] == 0.0:
        return "truly_clean"
    if row["final_cvss"] < CVSS_THRESHOLD:
        return "below_threshold_nonzero"
    return "failed_or_unresolved"


def condition_metrics(rows):
    total = len(rows)
    valid_rows = [row for row in rows if not row["failed"]]
    classes = Counter(classify(row) for row in rows)
    vector_a_surface = sum(1 for row in valid_rows if row["vector_a_injected"])
    vector_b_surface = sum(1 for row in valid_rows if row["vector_b_injected"])
    return {
        "total": total,
        "failed": sum(1 for row in rows if row["failed"]),
        "truly_clean": classes["truly_clean"],
        "below_threshold_nonzero": classes["below_threshold_nonzero"],
        "failed_or_unresolved": classes["failed_or_unresolved"],
        "first_iteration_clean": sum(1 for row in rows if row["first_iteration_clean"]),
        "healed_to_zero": sum(1 for row in rows if row["healed_to_zero"]),
        "avg_initial_cvss": round(mean(row["initial_cvss"] for row in rows), 2),
        "avg_final_cvss": round(mean(row["final_cvss"] for row in rows), 2),
        "avg_cvss_reduction": round(mean(row["cvss_delta"] for row in rows), 2),
        "avg_iterations": round(mean(row["iterations"] for row in rows), 2),
        "stagnation_stops": sum(1 for row in rows if row["stagnation_detected"]),
        "regression_stops": sum(1 for row in rows if row["regression_detected_loop"]),
        "vector_a_surface": vector_a_surface,
        "vector_a_success": sum(1 for row in valid_rows if row["injection_success_a"]),
        "vector_a_success_rate": round(
            sum(1 for row in valid_rows if row["injection_success_a"]) / vector_a_surface, 3
        ) if vector_a_surface else 0.0,
        "vector_b_surface": vector_b_surface,
        "vector_b_success": sum(1 for row in valid_rows if row["injection_success_b"]),
        "vector_b_success_rate": round(
            sum(1 for row in valid_rows if row["injection_success_b"]) / vector_b_surface, 3
        ) if vector_b_surface else 0.0,
        "guard_b_stripped": sum(row["guard_b_stripped_count"] for row in valid_rows),
    }


def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(outdir, condition_rows, metrics_rows):
    os.makedirs(outdir, exist_ok=True)

    metrics_path = os.path.join(outdir, "condition_metrics.csv")
    write_csv(metrics_path, metrics_rows, list(metrics_rows[0].keys()))

    task_rows = []
    for row in condition_rows:
        out = dict(row)
        out["classification"] = classify(row)
        out["cvss_history"] = json.dumps(row["cvss_history"])
        task_rows.append(out)

    task_path = os.path.join(outdir, "task_metrics.csv")
    write_csv(task_path, task_rows, list(task_rows[0].keys()))

    cwe_rows = []
    grouped = defaultdict(list)
    for row in condition_rows:
        grouped[(row["condition"], row["cwe"])].append(row)
    for (condition, cwe), rows in sorted(grouped.items()):
        cwe_rows.append({
            "condition": condition,
            "cwe": cwe,
            "count": len(rows),
            "nonzero_final": sum(1 for row in rows if row["final_cvss"] > 0.0),
            "worst_final_cvss": max(row["final_cvss"] for row in rows),
            "avg_final_cvss": round(mean(row["final_cvss"] for row in rows), 2),
        })

    cwe_path = os.path.join(outdir, "cwe_metrics.csv")
    write_csv(cwe_path, cwe_rows, list(cwe_rows[0].keys()))

    return metrics_path, task_path, cwe_path


def maybe_plot(outdir, metrics_rows):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipped plots.")
        return []

    paths = []
    names = [row["condition"] for row in metrics_rows]

    plot_specs = [
        ("avg_final_cvss", "Average Final CVSS", "avg_final_cvss.png"),
        ("truly_clean", "Truly Clean Runs", "truly_clean_runs.png"),
        ("first_iteration_clean", "First-Iteration Clean Runs", "first_iteration_clean.png"),
        ("healed_to_zero", "Healed To Zero Runs", "healed_to_zero.png"),
    ]

    for key, title, filename in plot_specs:
        values = [row[key] for row in metrics_rows]
        plt.figure(figsize=(7, 4))
        plt.bar(names, values)
        plt.title(title)
        plt.xticks(rotation=20, ha="right")
        plt.tight_layout()
        path = os.path.join(outdir, filename)
        plt.savefig(path, dpi=180)
        plt.close()
        paths.append(path)

    return paths


def print_console(metrics_rows):
    print("=" * 88)
    print("ATMG EXPERIMENT AGGREGATE")
    print("=" * 88)
    headers = [
        "condition",
        "total",
        "truly_clean",
        "below_threshold_nonzero",
        "failed_or_unresolved",
        "first_iteration_clean",
        "healed_to_zero",
        "avg_final_cvss",
        "avg_iterations",
    ]
    print("\t".join(headers))
    for row in metrics_rows:
        print("\t".join(str(row[h]) for h in headers))


def main():
    parser = argparse.ArgumentParser(description="Aggregate ATMG experiment summaries.")
    parser.add_argument(
        "--condition",
        action="append",
        help="Condition input as name=path. Repeat for 2x2 conditions.",
    )
    parser.add_argument(
        "--auto",
        action="append",
        help="Glob of experiment JSON files to load automatically.",
    )
    parser.add_argument(
        "--outdir",
        default="analysis_outputs",
        help="Directory for CSV tables and plots.",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip matplotlib plots.",
    )
    args = parser.parse_args()

    all_rows = []
    metrics_rows = []
    inputs = []
    if args.condition:
        inputs.extend(("condition", spec) for spec in args.condition)

    if args.auto:
        import glob
        for pattern in args.auto:
            for path in sorted(glob.glob(pattern)):
                if os.path.basename(path).startswith("experiment_merged_"):
                    inputs.append(("path", path))
                elif os.path.basename(path).startswith("experiment_"):
                    inputs.append(("path", path))

    if not inputs:
        parser.error("provide at least one --condition name=path or --auto glob")

    for kind, value in inputs:
        if kind == "condition":
            name, path, stored_stats, rows = load_condition(value)
        else:
            name, path, stored_stats, rows = load_path(value)
        if not rows:
            print(f"Skipped {path}: no rows found")
            continue
        all_rows.extend(rows)
        metrics = condition_metrics(rows)
        metrics["condition"] = name
        metrics["source_path"] = path
        metrics["stored_statistics"] = json.dumps(stored_stats, sort_keys=True)
        metrics_rows.append(metrics)

    print_console(metrics_rows)
    written = write_outputs(args.outdir, all_rows, metrics_rows)
    print("\nWrote:")
    for path in written:
        print(f"  {path}")

    if not args.no_plots:
        plot_paths = maybe_plot(args.outdir, metrics_rows)
        if plot_paths:
            print("\nPlots:")
            for path in plot_paths:
                print(f"  {path}")


if __name__ == "__main__":
    main()
