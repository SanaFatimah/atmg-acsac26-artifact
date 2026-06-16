import json
import os
import time
from datetime import datetime


class MetricsTracker:
    """
    Tracks performance metrics across all ATMG pipeline runs.
    Separate metric tables for Generator, Attacker, Analyst, and Pipeline.
    """

    def __init__(self, metrics_dir: str = "metrics"):
        self.metrics_dir = metrics_dir
        os.makedirs(metrics_dir, exist_ok=True)
        self.current_run = {}
        self.all_runs    = self._load_existing()

    # ── LOAD / SAVE ──────────────────────────────────────────────────────────
    def _load_existing(self) -> list:
        path = os.path.join(self.metrics_dir, "all_runs.json")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return []

    def _save_all(self):
        path = os.path.join(self.metrics_dir, "all_runs.json")
        with open(path, "w") as f:
            json.dump(self.all_runs, f, indent=2)

    # ── START RUN ────────────────────────────────────────────────────────────
    def start_run(self, spec: str, language: str, max_iterations: int):
        self.current_run = {
            "run_id":         f"run_{int(time.time())}",
            "timestamp":      datetime.now().isoformat(),
            "spec":           spec,
            "language":       language,
            "max_iterations": max_iterations,
            "iterations":     [],
            "final":          {}
        }
        print(f"\n[METRICS] Run started: {self.current_run['run_id']}")

    # ── RECORD ITERATION ─────────────────────────────────────────────────────
    def record_iteration(
        self,
        iteration:      int,
        generated_code: str,
        attacks:        list,
        report:         dict,
    ):
        findings    = report.get("findings", [])
        cvss_scores = [f.get("cvss_score", 0.0) for f in findings]
        cwe_ids     = [f.get("cwe_id", "Unknown") for f in findings]

        # ── GENERATOR METRICS ────────────────────────────────────────────────
        generator_metrics = {
            "code_lines":               len(generated_code.splitlines()),
            "code_chars":               len(generated_code),
            "code_functions":           generated_code.count("def "),
            "has_input_validation":     any(kw in generated_code.lower()
                                            for kw in ["if not", "raise", "valueerror",
                                                       "assert", "validate", "isinstance"]),
            "uses_parameterised_query": any(kw in generated_code.lower()
                                            for kw in ["?", "%s", "execute(", "prepared"]),
            "uses_hashing":             any(kw in generated_code.lower()
                                            for kw in ["bcrypt", "hashlib", "sha256",
                                                       "pbkdf2", "argon2"]),
        }

        # ── ATTACKER METRICS ─────────────────────────────────────────────────
        attacker_metrics = {
            "attacks_found":             len(attacks),
            "unique_attack_cwes":        len(set(a.get("cwe", "Unknown") for a in attacks)),
            "attack_cwe_ids":            [a.get("cwe", "Unknown") for a in attacks],
            "injection_attacks":         sum(1 for a in attacks
                                             if any(kw in a.get("cwe", "").lower()
                                                    for kw in ["89", "78", "77", "94"])),
            "auth_attacks":              sum(1 for a in attacks
                                             if any(kw in a.get("cwe", "").lower()
                                                    for kw in ["287", "306", "307", "521", "916"])),
            "info_disclosure":           sum(1 for a in attacks
                                             if any(kw in a.get("cwe", "").lower()
                                                    for kw in ["200", "203", "208", "209"])),
            "diversity_score":           round(
                len(set(a.get("cwe", "Unknown") for a in attacks)) / len(attacks)
                if attacks else 0.0, 2),
            "sandbox_confirmed":         sum(1 for a in attacks
                                             if a.get("sandbox", {}).get("confirmed")),
            "sandbox_not_confirmed":     sum(1 for a in attacks
                                             if not a.get("sandbox", {}).get("confirmed")
                                             and not a.get("sandbox", {}).get("skipped")),
            "sandbox_skipped":           sum(1 for a in attacks
                                             if a.get("sandbox", {}).get("skipped")),
            "sandbox_timed_out":         sum(1 for a in attacks
                                             if a.get("sandbox", {}).get("timed_out")),
            "sandbox_confirmation_rate": round(
                sum(1 for a in attacks if a.get("sandbox", {}).get("confirmed")) / len(attacks)
                if attacks else 0.0, 2),
        }

        # ── ANALYST METRICS ──────────────────────────────────────────────────
        analyst_metrics = {
            "findings_count":            len(findings),
            "cvss_scores":               cvss_scores,
            "max_cvss":                  max(cvss_scores) if cvss_scores else 0.0,
            "avg_cvss":                  round(sum(cvss_scores) / len(cvss_scores), 2)
                                          if cvss_scores else 0.0,
            "cwe_ids":                   cwe_ids,
            "unique_cwes":               len(set(cwe_ids)),
            "overall_risk":              report.get("overall_risk", "Unknown"),
            "critical_count":            sum(1 for s in cvss_scores if s >= 9.0),
            "high_count":                sum(1 for s in cvss_scores if 7.0 <= s < 9.0),
            "medium_count":              sum(1 for s in cvss_scores if 4.0 <= s < 7.0),
            "low_count":                 sum(1 for s in cvss_scores if s < 4.0),
            "has_remediation":           all("remediation_code" in f for f in findings),
            "analyst_parse_ok":          bool(findings),
            "patch_feedback_len":        len(report.get("patch_feedback", "")),
            "confirmed_count":           report.get("confirmed_count", 0),
            "suspected_count":           report.get("suspected_count", 0),
            "architectural_count":       report.get("architectural_count", 0),
            "sandbox_confirmation_rate": round(
                report.get("confirmed_count", 0) / len(findings)
                if findings else 0.0, 2),
        }

        iteration_data = {
            "iteration": iteration,
            "generator": generator_metrics,
            "attacker":  attacker_metrics,
            "analyst":   analyst_metrics,
        }

        self.current_run["iterations"].append(iteration_data)

        print(f"[METRICS] Iteration {iteration} — "
              f"attacks: {attacker_metrics['attacks_found']} "
              f"(diversity: {attacker_metrics['diversity_score']}) | "
              f"findings: {analyst_metrics['findings_count']} | "
              f"max CVSS: {analyst_metrics['max_cvss']}")

    # ── FINISH RUN ───────────────────────────────────────────────────────────
    def finish_run(self, is_clean: bool, final_code: str, final_report: dict):
        iters = self.current_run["iterations"]
        total = len(iters)

        if total == 0:
            print("[METRICS] Warning: no iterations recorded for this run.")
            return

        cvss_progression = [it["analyst"]["max_cvss"] for it in iters]
        first_cwes       = set(iters[0]["analyst"]["cwe_ids"])  if iters else set()
        last_cwes        = set(iters[-1]["analyst"]["cwe_ids"]) if iters else set()
        fixed_cwes       = first_cwes - last_cwes
        new_cwes         = last_cwes  - first_cwes

        # ── GENERATOR SUMMARY ────────────────────────────────────────────────
        generator_summary = {
            "avg_code_lines":           round(
                sum(it["generator"]["code_lines"] for it in iters) / total, 1),
            "validation_rate":          round(
                sum(1 for it in iters if it["generator"]["has_input_validation"]) / total, 2),
            "parameterised_query_rate": round(
                sum(1 for it in iters if it["generator"]["uses_parameterised_query"]) / total, 2),
            "hashing_rate":             round(
                sum(1 for it in iters if it["generator"]["uses_hashing"]) / total, 2),
        }

        # ── ATTACKER SUMMARY ─────────────────────────────────────────────────
        attacker_summary = {
            "avg_attacks_per_iter":          round(
                sum(it["attacker"]["attacks_found"] for it in iters) / total, 1),
            "avg_unique_cwes":               round(
                sum(it["attacker"]["unique_attack_cwes"] for it in iters) / total, 1),
            "avg_diversity_score":           round(
                sum(it["attacker"]["diversity_score"] for it in iters) / total, 2),
            "total_injection_attacks":       sum(it["attacker"]["injection_attacks"]  for it in iters),
            "total_auth_attacks":            sum(it["attacker"]["auth_attacks"]        for it in iters),
            "total_info_disclosure":         sum(it["attacker"]["info_disclosure"]     for it in iters),
            "total_sandbox_confirmed":       sum(it["attacker"].get("sandbox_confirmed", 0)       for it in iters),
            "total_sandbox_not_confirmed":   sum(it["attacker"].get("sandbox_not_confirmed", 0)   for it in iters),
            "total_sandbox_skipped":         sum(it["attacker"].get("sandbox_skipped", 0)         for it in iters),
            "total_sandbox_timed_out":       sum(it["attacker"].get("sandbox_timed_out", 0)       for it in iters),
            "avg_sandbox_confirmation_rate": round(
                sum(it["attacker"].get("sandbox_confirmation_rate", 0) for it in iters) / total, 2),
        }

        # ── ANALYST SUMMARY ──────────────────────────────────────────────────
        analyst_summary = {
            "avg_findings":       round(
                sum(it["analyst"]["findings_count"] for it in iters) / total, 1),
            "avg_cvss":           round(
                sum(it["analyst"]["avg_cvss"] for it in iters) / total, 2),
            "parse_success_rate": round(
                sum(1 for it in iters if it["analyst"]["analyst_parse_ok"]) / total, 2),
            "remediation_rate":   round(
                sum(1 for it in iters if it["analyst"]["has_remediation"]) / total, 2),
            "severity_breakdown": {
                "critical": sum(it["analyst"]["critical_count"] for it in iters),
                "high":     sum(it["analyst"]["high_count"]     for it in iters),
                "medium":   sum(it["analyst"]["medium_count"]   for it in iters),
                "low":      sum(it["analyst"]["low_count"]      for it in iters),
            }
        }

        # ── PIPELINE SUMMARY ─────────────────────────────────────────────────
        pipeline_summary = {
            "total_iterations": total,
            "converged":        is_clean,
            "cvss_progression": cvss_progression,
            "initial_max_cvss": cvss_progression[0]  if cvss_progression else 0.0,
            "final_max_cvss":   cvss_progression[-1] if cvss_progression else 0.0,
            "cvss_reduction":   round(
                (cvss_progression[0] - cvss_progression[-1]), 2)
                if cvss_progression else 0.0,
            "fixed_cwes":       list(fixed_cwes),
            "regression_cwes":  list(new_cwes),
            "had_regression":   bool(new_cwes),
        }

        # ── STORE FINAL ──────────────────────────────────────────────────────
        self.current_run["final"] = {
            "generator": generator_summary,
            "attacker":  attacker_summary,
            "analyst":   analyst_summary,
            "pipeline":  pipeline_summary,
        }

        self.all_runs.append(self.current_run)
        self._save_all()
        self._save_run_report()

        print(f"[METRICS] Run finished — "
              f"converged: {is_clean} | "
              f"iterations: {total} | "
              f"CVSS: {cvss_progression[0] if cvss_progression else 0}"
              f" → {cvss_progression[-1] if cvss_progression else 0}")

    # ── SAVE INDIVIDUAL REPORT ───────────────────────────────────────────────
    def _save_run_report(self):
        run_id = self.current_run["run_id"]
        path   = os.path.join(self.metrics_dir, f"{run_id}.json")
        with open(path, "w") as f:
            json.dump(self.current_run, f, indent=2)
        print(f"[METRICS] Saved to {path}")

    # ── AGGREGATE SUMMARY ────────────────────────────────────────────────────
    def get_summary(self) -> dict:
        if not self.all_runs:
            return {"error": "No runs recorded yet"}

        total_runs = len(self.all_runs)
        finals     = [
            r["final"] for r in self.all_runs
            if r.get("final") and "pipeline" in r["final"]
        ]

        if not finals:
            return {"error": "No valid runs with final data yet"}

        converged   = sum(1 for f in finals if f["pipeline"]["converged"])
        regressions = sum(1 for f in finals if f["pipeline"]["had_regression"])
        all_iters   = [f["pipeline"]["total_iterations"] for f in finals]
        cvss_reds   = [f["pipeline"]["cvss_reduction"]   for f in finals]

        all_cwes = []
        for run in self.all_runs:
            for it in run.get("iterations", []):
                if "analyst" in it:
                    all_cwes.extend(it["analyst"]["cwe_ids"])
        cwe_freq = {}
        for cwe in all_cwes:
            cwe_freq[cwe] = cwe_freq.get(cwe, 0) + 1
        top_cwes = sorted(cwe_freq.items(), key=lambda x: x[1], reverse=True)[:10]

        languages = {}
        for run in self.all_runs:
            lang = run.get("language", "unknown")
            languages[lang] = languages.get(lang, 0) + 1

        return {
            "total_runs": total_runs,

            "generator": {
                "avg_code_lines":         round(sum(f["generator"]["avg_code_lines"]           for f in finals) / len(finals), 1),
                "avg_validation_rate":    round(sum(f["generator"]["validation_rate"]          for f in finals) / len(finals), 2),
                "avg_parameterised_rate": round(sum(f["generator"]["parameterised_query_rate"] for f in finals) / len(finals), 2),
                "avg_hashing_rate":       round(sum(f["generator"]["hashing_rate"]             for f in finals) / len(finals), 2),
            },

            "attacker": {
                "avg_attacks_per_iter":          round(sum(f["attacker"]["avg_attacks_per_iter"]          for f in finals) / len(finals), 1),
                "avg_unique_cwes":               round(sum(f["attacker"]["avg_unique_cwes"]               for f in finals) / len(finals), 1),
                "avg_diversity_score":           round(sum(f["attacker"]["avg_diversity_score"]           for f in finals) / len(finals), 2),
                "total_sandbox_confirmed":       sum(f["attacker"].get("total_sandbox_confirmed", 0)       for f in finals),
                "total_sandbox_not_confirmed":   sum(f["attacker"].get("total_sandbox_not_confirmed", 0)   for f in finals),
                "total_sandbox_skipped":         sum(f["attacker"].get("total_sandbox_skipped", 0)         for f in finals),
                "total_sandbox_timed_out":       sum(f["attacker"].get("total_sandbox_timed_out", 0)       for f in finals),
                "avg_sandbox_confirmation_rate": round(sum(f["attacker"].get("avg_sandbox_confirmation_rate", 0) for f in finals) / len(finals), 2),
            },

            "analyst": {
                "avg_findings":           round(sum(f["analyst"]["avg_findings"]       for f in finals) / len(finals), 1),
                "avg_cvss":               round(sum(f["analyst"]["avg_cvss"]           for f in finals) / len(finals), 2),
                "avg_parse_success_rate": round(sum(f["analyst"]["parse_success_rate"] for f in finals) / len(finals), 2),
                "avg_remediation_rate":   round(sum(f["analyst"]["remediation_rate"]   for f in finals) / len(finals), 2),
                "total_severity": {
                    "critical": sum(f["analyst"]["severity_breakdown"]["critical"] for f in finals),
                    "high":     sum(f["analyst"]["severity_breakdown"]["high"]     for f in finals),
                    "medium":   sum(f["analyst"]["severity_breakdown"]["medium"]   for f in finals),
                    "low":      sum(f["analyst"]["severity_breakdown"]["low"]      for f in finals),
                }
            },

            "pipeline": {
                "convergence_rate":      round(converged   / total_runs, 2),
                "regression_rate":       round(regressions / total_runs, 2),
                "mean_iterations":       round(sum(all_iters) / total_runs, 2),
                "mean_cvss_reduction":   round(sum(cvss_reds) / total_runs, 2),
                "language_distribution": languages,
                "top_10_cwes":           top_cwes,
                "unique_cwes_found":     len(set(all_cwes)),
            }
        }

    # ── PRINT SUMMARY ────────────────────────────────────────────────────────
    def print_summary(self):
        s = self.get_summary()
        if "error" in s:
            print(f"[METRICS] {s['error']}")
            return

        w = 60
        print("\n" + "="*w)
        print("ATMG METRICS SUMMARY")
        print("="*w)
        print(f"Total runs : {s['total_runs']}")

        print(f"\n── GENERATOR ──")
        g = s["generator"]
        print(f"  Avg code lines            : {g['avg_code_lines']}")
        print(f"  Input validation rate     : {g['avg_validation_rate']*100:.0f}%")
        print(f"  Parameterised query rate  : {g['avg_parameterised_rate']*100:.0f}%")
        print(f"  Password hashing rate     : {g['avg_hashing_rate']*100:.0f}%")

        print(f"\n── ATTACKER ──")
        a = s["attacker"]
        print(f"  Avg attacks per iteration : {a['avg_attacks_per_iter']}")
        print(f"  Avg unique CWEs           : {a['avg_unique_cwes']}")
        print(f"  Avg diversity score       : {a['avg_diversity_score']}")
        print(f"  Sandbox confirmed         : {a.get('total_sandbox_confirmed', 0)}")
        print(f"  Sandbox not confirmed     : {a.get('total_sandbox_not_confirmed', 0)}")
        print(f"  Sandbox skipped           : {a.get('total_sandbox_skipped', 0)}")
        print(f"  Sandbox timed out         : {a.get('total_sandbox_timed_out', 0)}")
        print(f"  Avg confirmation rate     : {a.get('avg_sandbox_confirmation_rate', 0)*100:.0f}%")

        print(f"\n── ANALYST ──")
        an = s["analyst"]
        print(f"  Avg findings per run      : {an['avg_findings']}")
        print(f"  Avg CVSS score            : {an['avg_cvss']}")
        print(f"  JSON parse success rate   : {an['avg_parse_success_rate']*100:.0f}%")
        print(f"  Remediation coverage      : {an['avg_remediation_rate']*100:.0f}%")
        print(f"  Severity — Critical       : {an['total_severity']['critical']}")
        print(f"  Severity — High           : {an['total_severity']['high']}")
        print(f"  Severity — Medium         : {an['total_severity']['medium']}")
        print(f"  Severity — Low            : {an['total_severity']['low']}")

        print(f"\n── PIPELINE ──")
        p = s["pipeline"]
        print(f"  Convergence rate          : {p['convergence_rate']*100:.0f}%")
        print(f"  Regression rate           : {p['regression_rate']*100:.0f}%")
        print(f"  Mean iterations to clean  : {p['mean_iterations']}")
        print(f"  Mean CVSS reduction       : {p['mean_cvss_reduction']}")
        print(f"  Languages tested          : {p['language_distribution']}")
        print(f"  Unique CWEs found         : {p['unique_cwes_found']}")
        print(f"\n  Top CWEs:")
        for cwe, count in p["top_10_cwes"]:
            print(f"    {cwe:<15} — {count} occurrences")
        print("="*w)