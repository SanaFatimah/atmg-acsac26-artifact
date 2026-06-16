import re
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tools.gpu_config import num_gpu, ollama_chat


def attack_code(
    code: str,
    language: str,
    found_cwes: list = None,
    iteration: int = 0,
    spec: str = None,
    seed: int = None,
) -> tuple:

    found_cwes = found_cwes or []

    if iteration == 0:
        depth_block = """ITERATION 0 — SURFACE LAYER:
Focus on the most common, easily detectable vulnerabilities:
- Injection (SQL, command, path traversal / CWE-022)
- Authentication bypass and missing authorization checks
- Hardcoded secrets or credentials
- Missing input validation and sanitization
- Insecure direct object reference (IDOR)
- Server-side request forgery (SSRF)
- Sensitive data exposure (tokens, keys in responses or logs)"""
    elif iteration == 1:
        depth_block = """ITERATION 1 — STRUCTURAL LAYER:
Surface bugs likely already found. Look deeper:
- Insecure deserialization (pickle, yaml.load, ObjectInputStream)
- Race conditions and TOCTOU
- Integer overflow / arithmetic errors
- Type confusion / unsafe casting
- Insecure direct object references (IDOR)"""
    else:
        depth_block = """ITERATION 2+ — DEEP / NON-OBVIOUS LAYER:
Surface and structural likely found. Hunt for:
- Business logic flaws
- Chained exploitation (multi-step attacks)
- Prompt injection in LLM-integrated code (CWE-1388)
- Subtle authentication / session flaws
- Side-channel and timing leaks
Avoid generic OWASP Top 10 unless found in a NEW chained context."""

    if found_cwes:
        exclusion_lines = ", ".join(sorted(set(found_cwes)))
        exclusion_block = f"""
ALREADY FOUND IN PRIOR ITERATIONS — DO NOT REPEAT:
{exclusion_lines}

You MUST find DIFFERENT attack surfaces.
Re-reporting an excluded CWE counts as failure unless it appears
in a genuinely NEW location with a NEW exploitation path."""
    else:
        exclusion_block = "\nNo CWEs excluded — fresh analysis."

    system_prompt = f"""You are a security red-teamer agent in the ATMG pipeline.

Your role: analyze source code and find security vulnerabilities.

{depth_block}
{exclusion_block}

OUTPUT FORMAT (strict, plain text, NO markdown formatting):

Thought: [reason about what vulnerability you see]
Vulnerability: [short name]
CWE: [CWE-ID e.g. CWE-89]
Location: [function name and/or line number]
Payload: [actual exploit payload or malicious input]
Expected Impact: [what this exploit achieves]
Novelty: [0-10 score]
Novelty Reason: [why this is or is not non-obvious]
---

NOVELTY SCALE:
0-3 = Common OWASP Top 10, well-known
4-6 = Less common, requires specific context
7-9 = Uncommon vector, chained or non-obvious
10  = Novel, outside standard taxonomies

RULES:
- Find at least 3 different attack vectors when possible.
- Each attack MUST have CWE filled. If unsure, closest match.
- NEVER use markdown like **, *, _, or backticks around labels.
- Plain text only.
- Each attack ends with --- on its own line.
- Skip a CWE entirely if there is genuinely no instance — do NOT pad with N/A.
"""

    spec_block = f"\nSPEC CONTEXT:\n{spec}\n" if spec else ""

    user_prompt = (
        f"ITERATION: {iteration}\n"
        f"{spec_block}\n"
        f"Analyze this {language} code and find security vulnerabilities:\n\n"
        f"{code}\n\n"
        f"Begin your security analysis now. Follow the format strictly."
    )

    options = {"temperature": 0.85, "num_predict": 2048, "num_gpu": num_gpu()}
    if seed is not None:
        options["seed"] = seed

    response = ollama_chat(
        model="qwen3:32b",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt}
        ],
        options=options,
    )

    raw_output = response["message"]["content"]

    clean_output = re.sub(r'[\*\_]+', '', raw_output)
    clean_output = re.sub(r'`+', '', clean_output)

    attacks = []
    current_attack = {}

    def _save_current():
        if current_attack.get("vulnerability") and \
           current_attack["vulnerability"].lower() not in ("n/a", "none", ""):
            attacks.append(current_attack.copy())

    for line in clean_output.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("---"):
            _save_current()
            current_attack = {}
            continue

        if re.search(r'\bVulnerability\s*:', line, re.IGNORECASE):
            _save_current()
            vuln_text = re.sub(
                r'.*Vulnerability\s*:\s*', '', line, flags=re.IGNORECASE
            ).strip()
            current_attack = {
                "vulnerability":  vuln_text,
                "cwe":            _extract_cwe_from_text(vuln_text),
                "location":       "",
                "payload":        "",
                "impact":         "",
                "thought":        "",
                "novelty":        None,
                "novelty_reason": ""
            }

        elif re.search(r'\bCWE\s*:', line, re.IGNORECASE):
            value = re.sub(r'.*CWE\s*:\s*', '', line, flags=re.IGNORECASE).strip()
            extracted = _extract_cwe_from_text(value)
            if current_attack:
                current_attack["cwe"] = extracted if extracted else value

        elif re.search(r'\bCWE[\s\-]+\d+', line, re.IGNORECASE):
            match = re.search(r'CWE[\s\-]*([0-9]+)', line, re.IGNORECASE)
            if match and current_attack:
                current_attack["cwe"] = f"CWE-{match.group(1)}"

        elif re.search(r'\bLocation\s*:', line, re.IGNORECASE):
            if current_attack:
                current_attack["location"] = re.sub(
                    r'.*Location\s*:\s*', '', line, flags=re.IGNORECASE
                ).strip()

        elif re.search(r'\bPayload\s*:', line, re.IGNORECASE):
            if current_attack:
                current_attack["payload"] = re.sub(
                    r'.*Payload\s*:\s*', '', line, flags=re.IGNORECASE
                ).strip()

        elif re.search(r'\bExpected Impact\s*:', line, re.IGNORECASE):
            if current_attack:
                current_attack["impact"] = re.sub(
                    r'.*Expected Impact\s*:\s*', '', line, flags=re.IGNORECASE
                ).strip()

        elif re.search(r'\bThought\s*:', line, re.IGNORECASE):
            if current_attack:
                current_attack["thought"] = re.sub(
                    r'.*Thought\s*:\s*', '', line, flags=re.IGNORECASE
                ).strip()

        elif re.search(r'\bNovelty\s*Reason\s*:', line, re.IGNORECASE):
            if current_attack:
                current_attack["novelty_reason"] = re.sub(
                    r'.*Novelty\s*Reason\s*:\s*', '', line, flags=re.IGNORECASE
                ).strip()

        elif re.search(r'\bNovelty\s*:', line, re.IGNORECASE):
            if current_attack:
                value = re.sub(
                    r'.*Novelty\s*:\s*', '', line, flags=re.IGNORECASE
                ).strip()
                num_match = re.search(r'\d+', value)
                if num_match:
                    score = int(num_match.group(0))
                    current_attack["novelty"] = max(0, min(10, score))
                else:
                    current_attack["novelty"] = None

    _save_current()

    for atk in attacks:
        if not atk.get("cwe"):
            found = _extract_cwe_from_text(
                atk.get("vulnerability", "") + " " + atk.get("thought", "")
            )
            atk["cwe"] = found if found else "CWE-UNKNOWN"
        if atk.get("novelty") is None:
            atk["novelty"] = 0

    return attacks, raw_output


def _extract_cwe_from_text(text: str) -> str:
    match = re.search(r'CWE-\d+', text, re.IGNORECASE)
    return match.group(0).upper() if match else ""


if __name__ == "__main__":
    print("=" * 60)
    print("ATTACKER AGENT TEST — PHASE 3")
    print("=" * 60)

    test_code = """
def authenticate(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone() is not None

def load_config(path):
    with open(path) as f:
        return pickle.loads(f.read())
"""

    print("\n--- ITERATION 0 (surface) ---\n")
    attacks0, _ = attack_code(test_code, "python", iteration=0)
    for a in attacks0:
        print(f"{a['cwe']:12} | nov={a['novelty']:>2} | {a['vulnerability'][:60]}")

    print("\n--- ITERATION 1 (structural, exclude prior CWEs) ---\n")
    excluded = list({a["cwe"] for a in attacks0 if a["cwe"] != "CWE-UNKNOWN"})
    print(f"Excluded: {excluded}")
    attacks1, _ = attack_code(test_code, "python", found_cwes=excluded, iteration=1)
    for a in attacks1:
        print(f"{a['cwe']:12} | nov={a['novelty']:>2} | {a['vulnerability'][:60]}")
