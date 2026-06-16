import json
import re
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tools.gpu_config import num_gpu, ollama_chat

try:
    import json_repair
    HAS_JSON_REPAIR = True
except ImportError:
    HAS_JSON_REPAIR = False
    print("[ANALYST] Warning: json_repair not installed.")


def analyse_vulnerabilities(
    code: str,
    attacks: list,
    language: str,
    retry_count: int = 0,
    previous_findings: list = None,
    codeql_results: list = None,
    guard_a: bool = True,
    seed: int = None,
    analyst_model: str = "qwen3:32b",
) -> tuple:

    previous_findings = previous_findings or []
    codeql_results = codeql_results or []

    # ── HARD GUARD: short-circuit if no evidence ────────────────────────
    # Analyst is a verifier, not an auditor. With zero evidence, we return clean.
    no_attacks = not attacks or len(attacks) == 0
    no_codeql = not codeql_results or len(codeql_results) == 0

    if no_attacks and no_codeql and not previous_findings:
        print("[ANALYST] HARD GUARD: no attacks + no codeql + no prev findings -> clean report")
        clean_report = _build_clean_report()
        return clean_report, json.dumps(clean_report)

    system_prompt = """You are a security analyst agent in the ATMG pipeline.

Your role: VERIFY evidence from the Attacker, CodeQL, and Sandbox.
You are a VERIFIER, NOT an AUDITOR.
You score evidence. You do NOT generate findings from inspecting the code yourself.

CRITICAL EVIDENCE RULE — read carefully:
A finding MUST come from one of these evidence sources:
  1. The Attacker reported it (in the attack list)
  2. CodeQL detected it (in the codeql_results list)
  3. Previous iteration reported it (regression/healing tracking)

If NONE of these reported a CWE, you MUST NOT add it to findings.
You MUST NOT invent findings by examining the code yourself.
If attacks is empty AND codeql_results is empty, return findings: [].

Confidence levels — strict evidence rules:
- CONFIRMED: requires sandbox_confirmed=true (sandbox executed payload successfully)
              OR codeql_confirmed=true AND attacker reported it
- SUSPECTED: attacker reported it but sandbox/codeql could not verify
- ARCHITECTURAL: attacker or codeql reported a structural issue (rate limit, weak entropy, weak password policy) that cannot be dynamically triggered

NEVER mark CONFIRMED without sandbox_confirmed=true OR codeql_confirmed=true.

CodeQL evidence rules:
- CodeQL confirms a CWE statically AND sandbox confirms exploit -> CONFIRMED
- CodeQL confirms statically but sandbox cannot trigger -> SUSPECTED with codeql_confirmed=true
- Only attacker claims it, no CodeQL, no sandbox -> SUSPECTED with codeql_confirmed=false
- Attacker reports an architectural issue not caught by CodeQL -> ARCHITECTURAL

CVSS scoring:
- CONFIRMED: full CVSS score
- SUSPECTED: subtract 1.0 from CVSS
- ARCHITECTURAL: keep full CVSS, mark not dynamically confirmable

OUTPUT — strict JSON only, no text outside the object:
{
    "findings": [
        {
            "cwe_id": "CWE-89",
            "cwe_name": "SQL Injection",
            "cvss_score": 9.1,
            "cvss_severity": "Critical",
            "confidence": "CONFIRMED",
            "sandbox_confirmed": true,
            "codeql_confirmed": true,
            "sandbox_output": "RESULT: True",
            "novelty": 3,
            "novelty_reason": "common SQL injection pattern",
            "description": "detailed description",
            "affected_lines": "function or line numbers",
            "remediation_code": "corrected snippet",
            "remediation_description": "explanation of the fix"
        }
    ],
    "overall_risk": "Critical",
    "max_cvss": 9.1,
    "confirmed_count": 1,
    "suspected_count": 0,
    "architectural_count": 0,
    "codeql_confirmed_count": 1,
    "tier_gap": 0,
    "healing_verified": {},
    "healing_failures": [],
    "regression_detected": false,
    "regressed_cwes": [],
    "new_cwes": [],
    "recommendation": "overall recommendation",
    "patch_feedback": {
        "critical_fixes": [],
        "do_not_regress": [],
        "priority": "Fix CONFIRMED first, then SUSPECTED"
    }
}

RULES:
- Always output valid JSON only
- Never skip any field
- Never add text outside the JSON object
- CVSS v4.0 scoring
- sandbox_confirmed=true ONLY if sandbox result shows confirmed=true
- codeql_confirmed=true ONLY if CodeQL listed the CWE for this code
- novelty: integer 0-10 (0-3 common OWASP, 7-10 chained or non-obvious)
- patch_feedback MUST be a structured object, not a string
- healing_verified maps each previously-fixed CWE to true (still fixed) or false (regressed)
- healing_failures lists each false entry with location and root-cause reason
- regression_detected=true if any previously fixed CWE reappears
- tier_gap = confirmed_count - codeql_confirmed_count (signed integer)
- DO NOT INVENT FINDINGS. Only score the evidence given to you."""

    # ── build attack block ──────────────────────────────────────────────
    if attacks:
        attacks_formatted = ""
        for i, a in enumerate(attacks, 1):
            sandbox = a.get("sandbox", {})
            confirmed = sandbox.get("confirmed", False)
            timed_out = sandbox.get("timed_out", False)
            skipped = sandbox.get("skipped", False)
            output = sandbox.get("output", "")
            error = sandbox.get("error", "")

            if skipped:
                sandbox_status = "SKIPPED — no payload to test"
            elif timed_out:
                sandbox_status = "TIMED OUT — container exceeded time limit"
            elif confirmed:
                sandbox_status = f"CONFIRMED — payload executed. Output: {output}"
            else:
                sandbox_status = f"NOT CONFIRMED — Output: {output} | Error: {error}"

            novelty = a.get("novelty", "N/A")
            novelty_reason = a.get("novelty_reason", "")
            location = a.get("location", "N/A")

            attacks_formatted += f"""
Attack {i}:
  Vulnerability : {a.get('vulnerability', 'Unknown')}
  CWE           : {a.get('cwe', 'Unknown')}
  Location      : {location}
  Payload       : {a.get('payload', 'N/A')}
  Impact        : {a.get('impact', 'N/A')}
  Novelty       : {novelty} ({novelty_reason})
  Sandbox Result: {sandbox_status}
"""
    else:
        attacks_formatted = "NONE — Attacker found no vulnerabilities."

    # ── build codeql block ──────────────────────────────────────────────
    if codeql_results:
        codeql_block = "\n".join(
            f"  - {r.get('cwe', 'CWE-?')} at {r.get('location', '?')}: {r.get('message', '')}"
            for r in codeql_results
        )
        codeql_section = f"\nCodeQL Static Findings (Tier 1):\n{codeql_block}\n"
    else:
        codeql_section = "\nCodeQL Static Findings (Tier 1): NONE — CodeQL detected nothing.\n"

    # ── build previous findings block ───────────────────────────────────
    if previous_findings:
        prev_cwes = sorted({f.get("cwe_id", "?") for f in previous_findings if f.get("cwe_id")})
        prev_locations = "\n".join(
            f"  - {f.get('cwe_id', '?')} at {f.get('affected_lines', '?')}"
            for f in previous_findings
        )
        prev_section = f"""

Previous Iteration Findings (for regression and healing tracking):
Previously found CWEs: {', '.join(prev_cwes) if prev_cwes else 'none'}

Detail:
{prev_locations}

Check each previously-found CWE against the current code:
- If still present in attacker/codeql evidence -> healing_verified[cwe] = false, add to healing_failures, add to regressed_cwes
- If absent from current evidence -> healing_verified[cwe] = true
- regression_detected = true if any healing_verified value is false
- new_cwes = CWEs in current evidence not in previously found list
"""
    else:
        prev_section = "\nPrevious Iteration Findings: NONE (first iteration)\n"

    # ── compose user prompt with explicit empty-evidence guard ──────────
    evidence_guard = ""
    if no_attacks and no_codeql:
        evidence_guard = """

CRITICAL — EMPTY EVIDENCE DETECTED:
Attacker found 0 vulnerabilities AND CodeQL found 0 issues.
The code passed both verification tiers.
You MUST return findings: [] with overall_risk: "Low" and max_cvss: 0.0.
DO NOT invent findings by examining the code yourself.
The ONLY exception is regression tracking from previous_findings (healing_verified).
"""

    user_prompt = f"""
Analyse this {language} code with attacker findings, CodeQL results, and sandbox results.

Source Code (provided as CONTEXT only — DO NOT generate findings from it):
```{language}
{code}
```

Attack Vectors with Sandbox Results:
{attacks_formatted}
{codeql_section}
{prev_section}
{evidence_guard}
Produce the complete JSON security report now. Strict JSON only.
Score the evidence given to you. Do NOT invent new findings."""

    num_attacks = len(attacks)
    if retry_count == 0:
        num_predict = 12288 if num_attacks <= 3 else 14336
    else:
        num_predict = 16384

    options = {"temperature": 0.1, "num_predict": num_predict, "num_gpu": num_gpu()}
    if seed is not None:
        options["seed"] = seed

    response = ollama_chat(
        model=analyst_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        options=options,
    )

    raw_output = response["message"]["content"]
    report = _parse_json_response(raw_output, retry_count)

    if report is None or not isinstance(report, dict):
        return _create_error_report(raw_output, attacks), raw_output

    # ── post-hoc evidence enforcement ───────────────────────────────────
    # Guard A: strip unsupported findings. Disabled in undefended experiment conditions.
    if guard_a:
        report = _enforce_evidence_rules(report, attacks, codeql_results)

    if "findings" in report and len(report.get("findings", [])) > 0:
        findings = report["findings"]
        cvss_scores = [
            f.get("cvss_score", 0.0)
            for f in findings
            if isinstance(f.get("cvss_score"), (int, float))
        ]
        if cvss_scores:
            calculated_max_cvss = max(cvss_scores)
            if report.get("max_cvss", 0.0) == 0.0 and calculated_max_cvss > 0.0:
                report["max_cvss"] = calculated_max_cvss

    if "confirmed_count" not in report:
        findings = report.get("findings", [])
        report["confirmed_count"] = sum(1 for f in findings if f.get("confidence") == "CONFIRMED")
        report["suspected_count"] = sum(1 for f in findings if f.get("confidence") == "SUSPECTED")
        report["architectural_count"] = sum(1 for f in findings if f.get("confidence") == "ARCHITECTURAL")

    _validate_and_fix_report(report, previous_findings)
    return report, raw_output


def _enforce_evidence_rules(report: dict, attacks: list, codeql_results: list) -> dict:
    """
    Post-hoc enforcement: strip findings that have NO evidence backing.
    Catches model hallucinations even when the prompt fails.
    """
    findings = report.get("findings", [])
    if not findings:
        return report

    # build evidence sets
    attacker_cwes = {a.get("cwe", "").upper() for a in (attacks or []) if a.get("cwe")}
    codeql_cwes = {r.get("cwe", "").upper() for r in (codeql_results or []) if r.get("cwe")}
    sandbox_confirmed_cwes = {
        a.get("cwe", "").upper()
        for a in (attacks or [])
        if a.get("sandbox", {}).get("confirmed")
    }
    evidence_cwes = attacker_cwes | codeql_cwes

    cleaned_findings = []
    stripped_count = 0

    for f in findings:
        cwe = f.get("cwe_id", "").upper()

        # If no evidence at all, drop it
        if cwe not in evidence_cwes:
            print(f"[ANALYST GUARD] STRIPPED hallucinated finding: {cwe} — no attacker or codeql evidence")
            stripped_count += 1
            continue

        # If marked CONFIRMED, must have sandbox or codeql evidence
        if f.get("confidence") == "CONFIRMED":
            has_sandbox = f.get("sandbox_confirmed") is True and cwe in sandbox_confirmed_cwes
            has_codeql = f.get("codeql_confirmed") is True and cwe in codeql_cwes
            if not (has_sandbox or has_codeql):
                # downgrade to SUSPECTED with -1.0 CVSS
                print(f"[ANALYST GUARD] DOWNGRADED {cwe}: CONFIRMED -> SUSPECTED (no sandbox/codeql evidence)")
                f["confidence"] = "SUSPECTED"
                f["sandbox_confirmed"] = False
                f["codeql_confirmed"] = cwe in codeql_cwes
                if isinstance(f.get("cvss_score"), (int, float)):
                    f["cvss_score"] = max(0.0, f["cvss_score"] - 1.0)

        cleaned_findings.append(f)

    if stripped_count > 0:
        print(f"[ANALYST GUARD] Stripped {stripped_count} hallucinated findings")

    report["findings"] = cleaned_findings

    # recompute aggregates
    report["confirmed_count"] = sum(1 for f in cleaned_findings if f.get("confidence") == "CONFIRMED")
    report["suspected_count"] = sum(1 for f in cleaned_findings if f.get("confidence") == "SUSPECTED")
    report["architectural_count"] = sum(1 for f in cleaned_findings if f.get("confidence") == "ARCHITECTURAL")
    report["codeql_confirmed_count"] = len(codeql_results or [])

    # tier_gap = sandbox_confirmed − codeql_confirmed
    # Positive → dynamic execution caught more than static analysis
    # Negative → static analysis flagged issues the sandbox couldn't trigger
    sandbox_confirmed_count = sum(
        1 for a in (attacks or [])
        if a.get("sandbox", {}).get("confirmed")
    )
    report["sandbox_confirmed_count"] = sandbox_confirmed_count
    report["tier_gap"] = sandbox_confirmed_count - report["codeql_confirmed_count"]

    cvss_scores = [
        f.get("cvss_score", 0.0)
        for f in cleaned_findings
        if isinstance(f.get("cvss_score"), (int, float))
    ]
    report["max_cvss"] = max(cvss_scores) if cvss_scores else 0.0

    max_cvss = report["max_cvss"]
    if max_cvss >= 9.0:
        report["overall_risk"] = "Critical"
    elif max_cvss >= 7.0:
        report["overall_risk"] = "High"
    elif max_cvss >= 4.0:
        report["overall_risk"] = "Medium"
    else:
        report["overall_risk"] = "Low"

    return report


def _build_clean_report() -> dict:
    """Build a clean-state report when no evidence exists."""
    return {
        "findings": [],
        "overall_risk": "Low",
        "max_cvss": 0.0,
        "confirmed_count": 0,
        "suspected_count": 0,
        "architectural_count": 0,
        "codeql_confirmed_count": 0,
        "sandbox_confirmed_count": 0,
        "tier_gap": 0,
        "healing_verified": {},
        "healing_failures": [],
        "regression_detected": False,
        "regressed_cwes": [],
        "new_cwes": [],
        "recommendation": "Code passed both verification tiers. No findings.",
        "patch_feedback": {
            "critical_fixes": [],
            "do_not_regress": [],
            "priority": "No fixes required"
        }
    }


def _parse_json_response(raw_output: str, retry_count: int) -> dict:
    clean = raw_output.strip()

    if "```json" in clean:
        parts = clean.split("```json")
        if len(parts) > 1:
            clean = parts[1].split("```")[0].strip()
    elif "```" in clean:
        parts = clean.split("```")
        if len(parts) >= 3:
            clean = parts[1].strip()

    if not clean.startswith("{"):
        first = clean.find("{")
        last = clean.rfind("}")
        if first != -1 and last != -1 and last > first:
            clean = clean[first:last + 1]

    try:
        report = json.loads(clean)
        print("[ANALYST] Successfully parsed JSON (standard parser)")
        return report
    except json.JSONDecodeError as e:
        print(f"[ANALYST] Standard JSON parsing failed: {e}")

    if HAS_JSON_REPAIR:
        try:
            report = json_repair.loads(clean)
            print("[ANALYST] Successfully parsed JSON (json_repair library)")
            return report
        except Exception as e:
            print(f"[ANALYST] json_repair parsing failed: {e}")

    truncation_fixes = [
        clean + '}',
        clean + ']}',
        clean + '}]}',
        clean + '"]}}',
        clean + '"]}',
    ]
    for fixed in truncation_fixes:
        try:
            report = json.loads(fixed)
            print("[ANALYST] Successfully parsed JSON (truncation fix)")
            return report
        except:
            continue

    json_pattern = r'\{(?:[^{}]|(?:\{[^{}]*\}))*\}'
    matches = re.findall(json_pattern, raw_output, re.DOTALL)
    for match in matches:
        try:
            partial = json.loads(match)
            if "findings" in partial:
                print("[ANALYST] Successfully extracted partial JSON from nested object")
                return partial
        except:
            continue

    print("[ANALYST] All JSON parsing strategies failed")
    print(f"[ANALYST] Raw output length: {len(raw_output)} chars")
    print(f"[ANALYST] First 300 chars: {raw_output[:300]}")
    print(f"[ANALYST] Last 300 chars: {raw_output[-300:]}")
    return None


def _validate_and_fix_report(report: dict, previous_findings: list) -> None:
    if "findings" not in report:
        report["findings"] = []

    findings = report["findings"]

    if len(findings) > 0:
        cvss_scores = [
            f.get("cvss_score", 0.0)
            for f in findings
            if isinstance(f.get("cvss_score"), (int, float))
        ]
        if cvss_scores:
            calculated_max_cvss = max(cvss_scores)
            current_max = report.get("max_cvss", 0.0)
            if current_max == 0.0 and calculated_max_cvss > 0.0:
                report["max_cvss"] = calculated_max_cvss
            elif abs(current_max - calculated_max_cvss) > 0.1:
                report["max_cvss"] = calculated_max_cvss

    if "confirmed_count" not in report:
        report["confirmed_count"] = sum(1 for f in findings if f.get("confidence") == "CONFIRMED")
        report["suspected_count"] = sum(1 for f in findings if f.get("confidence") == "SUSPECTED")
        report["architectural_count"] = sum(1 for f in findings if f.get("confidence") == "ARCHITECTURAL")

    if "codeql_confirmed_count" not in report:
        report["codeql_confirmed_count"] = sum(1 for f in findings if f.get("codeql_confirmed") is True)

    if "tier_gap" not in report:
        report["tier_gap"] = report.get("confirmed_count", 0) - report.get("codeql_confirmed_count", 0)

    if "overall_risk" not in report:
        max_cvss = report.get("max_cvss", 0.0)
        if max_cvss >= 9.0:
            report["overall_risk"] = "Critical"
        elif max_cvss >= 7.0:
            report["overall_risk"] = "High"
        elif max_cvss >= 4.0:
            report["overall_risk"] = "Medium"
        else:
            report["overall_risk"] = "Low"

    prev_cwes = {f.get("cwe_id") for f in previous_findings if f.get("cwe_id")}
    current_cwes = {f.get("cwe_id") for f in findings if f.get("cwe_id")}

    if "healing_verified" not in report:
        report["healing_verified"] = {}
        for cwe in prev_cwes:
            report["healing_verified"][cwe] = cwe not in current_cwes

    if "healing_failures" not in report:
        report["healing_failures"] = []

    if "regressed_cwes" not in report:
        report["regressed_cwes"] = [
            cwe for cwe, ok in report.get("healing_verified", {}).items() if ok is False
        ]

    if "regression_detected" not in report:
        report["regression_detected"] = len(report.get("regressed_cwes", [])) > 0

    if "new_cwes" not in report:
        report["new_cwes"] = sorted(current_cwes - prev_cwes)

    if "recommendation" not in report:
        report["recommendation"] = "Address identified vulnerabilities according to severity."

    pf = report.get("patch_feedback")
    if not isinstance(pf, dict):
        critical_fixes = [
            {
                "cwe_id": f.get("cwe_id", "CWE-UNKNOWN"),
                "location": f.get("affected_lines", "unknown"),
                "instruction": f.get("remediation_description", "review and remediate")
            }
            for f in findings
            if f.get("confidence") in ("CONFIRMED", "SUSPECTED")
        ]
        report["patch_feedback"] = {
            "critical_fixes": critical_fixes,
            "do_not_regress": sorted(prev_cwes),
            "priority": "Fix CONFIRMED first, then SUSPECTED"
        }


def _create_error_report(raw_output: str, attacks: list) -> dict:
    print("[ANALYST] Creating error report — parsing completely failed")
    return {
        "findings": [],
        "overall_risk": "ParseError",
        "max_cvss": None,          # None = parse failure, not a real CVSS score
        "confirmed_count": 0,
        "suspected_count": 0,
        "architectural_count": 0,
        "codeql_confirmed_count": 0,
        "sandbox_confirmed_count": 0,
        "tier_gap": 0,
        "healing_verified": {},
        "healing_failures": [],
        "regression_detected": False,
        "regressed_cwes": [],
        "new_cwes": [],
        "recommendation": f"JSON parsing failed. Attacks found: {len(attacks)}. Raw output length: {len(raw_output)} chars",
        "patch_feedback": {
            "critical_fixes": [],
            "do_not_regress": [],
            "priority": "ANALYST PARSE ERROR — retry with clearer output format"
        },
        "parse_error": True
    }
