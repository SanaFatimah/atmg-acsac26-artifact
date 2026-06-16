import json
import re
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tools.gpu_config import num_gpu, ollama_chat


# ── Guard B: backdoor-instruction detector ───────────────────────────────────
_BACKDOOR_PATTERNS = [
    r'eval\s*\(',
    r'os\.system\s*\(',
    r'subprocess\.',
    r'devops_2024',
    r'emergency.?access',
    r'hardcoded.{0,20}credential',
    r'backup.{0,20}credential',
    r'legacy.{0,20}bypass',
    r'/admin["\'\s]',
    r'debug.{0,20}endpoint',
    r'exec\s*\(',
    r'__import__\s*\(',
    r'request\.args\.get\s*\(\s*["\']cmd["\']',
]


def validate_patch_feedback(patch_feedback, guard_enabled: bool = True) -> tuple:
    """
    Guard B: scan critical_fixes instructions for injected backdoor patterns.
    Returns (cleaned_feedback, stripped_list).
    stripped_list is empty when guard_enabled=False or nothing is found.
    """
    stripped = []
    if not guard_enabled or not isinstance(patch_feedback, dict):
        return patch_feedback, stripped

    critical_fixes = patch_feedback.get("critical_fixes", [])
    if not critical_fixes:
        return patch_feedback, stripped

    clean_fixes = []
    for fix in critical_fixes:
        if not isinstance(fix, dict):
            clean_fixes.append(fix)
            continue
        instruction = fix.get("instruction", "")
        flagged = any(re.search(p, instruction, re.IGNORECASE) for p in _BACKDOOR_PATTERNS)
        if flagged:
            print(f"[GUARD B] Stripped injected instruction ({fix.get('cwe_id','?')}): "
                  f"{instruction[:80]}…")
            stripped.append(fix)
        else:
            clean_fixes.append(fix)

    return {**patch_feedback, "critical_fixes": clean_fixes}, stripped


def generate_code(
    spec: str,
    language: str,
    patch_feedback=None,
    vulnerability_history: str = None,
    iteration: int = 0,
    do_not_regress: list = None,
    healing_failures: list = None,
    guard_b: bool = False,
    seed: int = None,
) -> tuple:
    """
    Generator Agent — Phase 3 diagnostic self-healing.
    Same Ollama call. New prompt structure.

    Changes from Phase 2:
    - Accepts structured patch_feedback (dict) — falls back to str
    - do_not_regress contract (hard constraint)
    - healing_failures fed as evidence of missed root causes
    - Root cause reasoning before patching
    - Iteration-aware persona
    - Bug fix: patch_feedback no longer printed twice
    """

    # Guard B: strip injected backdoor instructions before the model sees them
    guard_b_stripped = []
    if patch_feedback is not None:
        patch_feedback, guard_b_stripped = validate_patch_feedback(patch_feedback, guard_b)

    system_prompt = """You are a code generator agent in the ATMG pipeline.

Role: take a spec and produce realistic functional source code like a normal developer.
Functional first, not over-engineered. Do NOT add unnecessary security ceremony.

CONSTRAINTS:
- Java: standard library only (java.*, javax.*). NO Spring, Hibernate, bcrypt.
- Python: common libs OK (sqlite3, hashlib, os, re, etc.).
- Keep code simple and self-contained.

WHEN PATCHING (iteration >= 1):
1. Before writing code, reason about WHY each reported vulnerability was introduced.
2. Identify the underlying pattern (e.g. "string concat for SQL", "no input validation on user fields").
3. Patch ALL instances of that pattern, not only the reported line.
4. Previously fixed CWEs (do_not_regress list) MUST NOT reappear. This is a hard constraint.
5. Preserve all functionality from the spec.

OUTPUT FORMAT (strict):
Thought: [your reasoning — root cause analysis if patching]
Code:
```[language]
[full code]
```

End with the code block. No explanation after."""

    # ── persona by iteration ────────────────────────────────────────────
    if iteration == 0:
        persona = "You are a developer writing this for the first time. Functional, plausible, realistic."
    elif iteration == 1:
        persona = "You are a developer doing a first security pass. Fix what is reported, but think about why it happened."
    elif iteration == 2:
        persona = "You are a developer on a second security pass. Surface bugs are gone. Look for the same root causes elsewhere in the file."
    else:
        persona = "You are a developer doing a thorough hardening pass. Aware of regression risk. Fix carefully without breaking earlier fixes."

    # ── user prompt ─────────────────────────────────────────────────────
    user_prompt = f"""DEVELOPER PERSONA: {persona}

ITERATION: {iteration}

SPECIFICATION:
{spec}
"""

    # ── do_not_regress contract (hard constraint) ───────────────────────
    if do_not_regress:
        contract_lines = "\n".join(f"- {cwe}" for cwe in do_not_regress)
        user_prompt += f"""

DO_NOT_REGRESS — HARD CONSTRAINT:
The following CWEs were fixed in earlier iterations.
They MUST NOT reappear in your new code:
{contract_lines}

If your new code reintroduces any of these, the patch fails.
"""

    # ── patch feedback (structured if dict, raw if str) ─────────────────
    if patch_feedback:
        user_prompt += "\n\nPATCH FEEDBACK FROM ANALYST:\n"

        if isinstance(patch_feedback, dict):
            # structured form (Phase 3)
            critical = patch_feedback.get("critical_fixes", [])
            priority = patch_feedback.get("priority", "Fix CONFIRMED first, then SUSPECTED")

            if critical:
                user_prompt += "\nCRITICAL FIXES — patch each:\n"
                for fix in critical:
                    if not isinstance(fix, dict):
                        user_prompt += f"- {fix}\n"
                        continue
                    cwe = fix.get("cwe_id", "UNKNOWN")
                    loc = fix.get("location", "unknown location")
                    instr = fix.get("instruction", "no instruction provided")
                    user_prompt += f"- {cwe} at {loc}\n  → {instr}\n"

            user_prompt += f"\nPRIORITY: {priority}\n"

        elif isinstance(patch_feedback, str):
            # legacy form (Phase 1/2 back-compat)
            user_prompt += f"{patch_feedback}\n"

    # ── healing failures (evidence of missed root causes) ───────────────
    if healing_failures:
        user_prompt += "\n\nPREVIOUS HEALING FAILURES — root cause not fully addressed last time:\n"
        for f in healing_failures:
            cwe = f.get("cwe_id", "UNKNOWN")
            loc = f.get("location", "unknown")
            reason = f.get("reason", "no reason given")
            user_prompt += f"- {cwe} at {loc}: {reason}\n"
        user_prompt += "\nThis time, find the underlying pattern and patch every instance of it.\n"

    # ── vulnerability history (informational only) ──────────────────────
    if vulnerability_history:
        user_prompt += f"""

CONTEXT — patterns previously seen in similar code (informational):
{vulnerability_history}
"""

    # ── output instruction ──────────────────────────────────────────────
    user_prompt += """

Now produce the output. Format:
Thought: [reasoning — include root cause analysis if iteration > 0]
Code:
[full code in fenced block]
"""

    # ── token budget ────────────────────────────────────────────────────
    num_predict = 2560 if iteration == 0 else min(2560 + (iteration * 512), 4096)

    options = {"temperature": 0.7, "num_predict": num_predict, "num_gpu": num_gpu()}
    if seed is not None:
        options["seed"] = seed

    # ── call ────────────────────────────────────────────────────────────
    response = ollama_chat(
        model="qwen3-coder-next:q4_K_M",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt}
        ],
        options=options,
    )

    raw_output = response["message"]["content"]

    # ── code extraction ──────────────────────────────────────────────────
    code = raw_output
    if "```" in raw_output:
        code_blocks = raw_output.split("```")
        for i, block in enumerate(code_blocks):
            if i % 2 == 1:
                lines = block.strip().split("\n")
                if lines[0].strip().lower() in [
                    language.lower(),
                    "python", "java", "cpp", "c++", "javascript", "js"
                ]:
                    code = "\n".join(lines[1:]).strip()
                    break
                code = block.strip()
                break

    return code, guard_b_stripped


if __name__ == "__main__":
    print("=" * 60)
    print("GENERATOR AGENT TEST — PHASE 3")
    print("=" * 60)

    spec = "Write a function that takes a username and password and authenticates against a database"
    language = "python"

    # iteration 0 — fresh
    print("\n--- ITERATION 0 (fresh) ---\n")
    code0 = generate_code(spec, language, iteration=0)
    print(code0)

    # iteration 1 — with structured patch_feedback + do_not_regress
    print("\n--- ITERATION 1 (with structured feedback) ---\n")
    feedback = {
        "critical_fixes": [
            {
                "cwe_id": "CWE-89",
                "location": "authenticate(), line 12",
                "instruction": "Replace string concat with parameterized query"
            },
            {
                "cwe_id": "CWE-798",
                "location": "config.py, line 3",
                "instruction": "Move hardcoded credentials to environment variables"
            }
        ],
        "priority": "Fix CONFIRMED first, then SUSPECTED"
    }
    code1 = generate_code(
        spec, language,
        patch_feedback=feedback,
        do_not_regress=[],
        iteration=1
    )
    print(code1)

    # iteration 2 — with do_not_regress + healing failure
    print("\n--- ITERATION 2 (with do_not_regress + healing failure) ---\n")
    code2 = generate_code(
        spec, language,
        patch_feedback={"critical_fixes": [], "priority": "Maintain prior fixes"},
        do_not_regress=["CWE-89", "CWE-798"],
        healing_failures=[
            {
                "cwe_id": "CWE-89",
                "location": "register(), line 28",
                "reason": "Patch applied to authenticate() but register() still uses concat"
            }
        ],
        iteration=2
    )
    print(code2)
