import os
import re
import subprocess
import json
import tempfile
import shutil
import time

CODEQL_BIN = os.environ.get("CODEQL_BIN", "codeql")

NOISE_RULES = {
    "py/unused-import",
    "py/unused-local-variable",
    "py/unused-global-variable",
    "py/import-shadowed-by-loop-variable",
    "py/mixed-returns",
    "py/redundant-comparison",
    "py/similar-function",
    "py/duplicate-key",
    "py/cyclic-import",
    "py/missing-docstring",
    "py/inconsistent-equality",
    "py/multiple-calls-to-init",
    "py/unreachable-statement",
    "py/stack-trace-exposure",
}


def maybe_wrap_for_codeql(code: str, language: str) -> str:
    """
    Inject flask entry points for every top-level function.
    Ensures CodeQL traces taint for every potential entry point.
    """
    if language != "python":
        return code

    # Check for actual route decorators / taint sources already present.
    # Import strings alone are NOT enough — wrapping is needed even when flask
    # is imported but no route decorator is defined.
    _ROUTE_DECORATOR = re.compile(
        r'@(?:\w+\.)?(?:route|get|post|put|delete|patch|head|options)\s*\('
        r'|@app\.\w+\s*\('
        r'|@router\.\w+\s*\('
        r'|@blueprint\.\w+\s*\(',
        re.IGNORECASE,
    )
    _REQUEST_TAINT = re.compile(
        r'request\.(?:args|form|json|data|files|values|get_json)\b',
        re.IGNORECASE,
    )
    has_framework = bool(_ROUTE_DECORATOR.search(code)) or bool(_REQUEST_TAINT.search(code))
    if has_framework:
        return code

    funcs = re.findall(r'^def\s+(\w+)\s*\(([^)]*)\)', code, re.MULTILINE)
    if not funcs:
        return code

    routes = []
    for i, (name, params) in enumerate(funcs):
        if name.startswith("_"):
            continue
        param_names = [
            p.strip().split(":")[0].split("=")[0].strip()
            for p in params.split(",")
            if p.strip() and p.strip() not in ("self", "cls")
        ]
        args_str = ", ".join(f'request.args.get("{p}")' for p in param_names) if param_names else ""
        routes.append(f"""
@_atmg_app.route("/atmg_entry_{i}")
def _atmg_entry_{i}():
    try:
        return str({name}({args_str}))
    except Exception as e:
        return str(e)
""")

    if not routes:
        return code

    return code + "\n\nfrom flask import Flask, request\n_atmg_app = Flask(__name__)\n" + "".join(routes)


def run_codeql_scan(code: str, language: str) -> list:
    """CodeQL Runner for ATMG Phase 3 — Tier 1 static confirmation."""
    findings = []

    if not code or len(code.strip()) < 10:
        return []

    ql_lang = "python"
    temp_id = int(time.time() * 1000)
    source_dir = tempfile.mkdtemp(prefix=f"atmg_src_{temp_id}_")
    db_dir = tempfile.mkdtemp(prefix=f"atmg_db_{temp_id}_")
    sarif_file = f"/tmp/atmg_scan_{temp_id}.sarif"
    filename = "app.py"

    try:
        code_for_scan = maybe_wrap_for_codeql(code, language)
        wrapped = code_for_scan != code

        source_file = os.path.join(source_dir, filename)
        with open(source_file, "w") as f:
            f.write(code_for_scan)

        if wrapped:
            print(f"[CODEQL] Wrapped bare code with Flask taint sources")

        print(f"[CODEQL] Scanning {ql_lang} code ({len(code)} chars)...")

        create_cmd = [
            CODEQL_BIN, "database", "create", db_dir,
            f"--language={ql_lang}",
            f"--source-root={source_dir}",
            "--overwrite"
        ]
        cp = subprocess.run(create_cmd, capture_output=True, text=True, timeout=180)
        if cp.returncode != 0:
            print(f"[CODEQL] Create DB failed: {cp.stderr[:500]}")
            return []

        query_target = f"codeql/{ql_lang}-queries:codeql-suites/{ql_lang}-security-extended.qls"
        analyze_cmd = [
            CODEQL_BIN, "database", "analyze", db_dir,
            query_target,
            "--format=sarif-latest",
            f"--output={sarif_file}",
            "--threads=0"
        ]
        ap = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=300)
        if ap.returncode != 0:
            print(f"[CODEQL] Analyze failed: {ap.stderr[:500]}")
            return []

        if not os.path.exists(sarif_file):
            print("[CODEQL] No SARIF output produced")
            return []

        with open(sarif_file, "r") as f:
            sarif_data = json.load(f)

        runs = sarif_data.get("runs", [])
        if not runs:
            return []

        run = runs[0]
        rules = {}
        tool_rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for r in tool_rules:
            rid = r.get("id")
            cwes = []
            for tag in r.get("properties", {}).get("tags", []):
                if tag.startswith("external/cwe/cwe-"):
                    num = tag.split("cwe-")[-1]
                    cwes.append(f"CWE-{num}")
            rules[rid] = {"cwes": cwes, "name": r.get("name", rid)}

        skipped_noise = 0
        skipped_no_cwe = 0

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "UNKNOWN")
            rule_meta = rules.get(rule_id, {"cwes": [], "name": rule_id})
            cwes = rule_meta["cwes"]
            primary_cwe = cwes[0] if cwes else "CWE-UNKNOWN"

            locs = result.get("locations", [])
            loc_str = filename
            line_num = 0
            if locs:
                phys = locs[0].get("physicalLocation", {})
                line_num = phys.get("region", {}).get("startLine", 0)
                if line_num:
                    loc_str = f"{filename}:{line_num}"

            # filter 1: skip rules with no CWE mapping
            if primary_cwe == "CWE-UNKNOWN":
                skipped_no_cwe += 1
                continue

            # filter 2: skip known noisy/quality rules
            if rule_id in NOISE_RULES:
                skipped_noise += 1
                continue


            findings.append({
                "cwe":       primary_cwe,
                "all_cwes":  cwes,
                "rule_id":   rule_id,
                "rule_name": rule_meta["name"],
                "location":  loc_str,
                "message":   result.get("message", {}).get("text", "")
            })

        if skipped_noise or skipped_no_cwe:
            print(f"[CODEQL] Filtered: {skipped_noise} noise, {skipped_no_cwe} no-cwe")
        print(f"[CODEQL] Done — {len(findings)} security findings")

    except subprocess.TimeoutExpired:
        print("[CODEQL] Timeout exceeded")
    except Exception as e:
        print(f"[CODEQL] Error: {e}")
    finally:
        for path in (source_dir, db_dir):
            try:
                if os.path.exists(path):
                    shutil.rmtree(path)
            except Exception:
                pass
        try:
            if os.path.exists(sarif_file):
                os.remove(sarif_file)
        except Exception:
            pass

    return findings


if __name__ == "__main__":
    print("=" * 60)
    print("TEST 1 — multi-function bare python (should find SQLi, cmd inj, deserialization)")
    print("=" * 60)
    multi_code = """
import os
import sqlite3
import pickle

def authenticate(u, p):
    conn = sqlite3.connect("u.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE u='" + u + "' AND p='" + p + "'")
    return c.fetchone()

def run_cmd(cmd):
    os.system(cmd)

def load_config(path):
    with open(path, 'rb') as f:
        return pickle.loads(f.read())
"""
    results = run_codeql_scan(multi_code, "python")
    print(f"\nFound {len(results)} findings:")
    for r in results:
        print(f"  {r['cwe']:14} | {r['rule_id']:30} | {r['location']}")
        print(f"    {r['message'][:80]}")

    print("\n" + "=" * 60)
    print("TEST 2 — clean flask code (should find SQLi only)")
    print("=" * 60)
    flask_code = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/login")
def login():
    u = request.args.get("u")
    p = request.args.get("p")
    conn = sqlite3.connect("u.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE u='" + u + "' AND p='" + p + "'")
    return str(c.fetchone())
"""
    results = run_codeql_scan(flask_code, "python")
    print(f"\nFound {len(results)} findings:")
    for r in results:
        print(f"  {r['cwe']:14} | {r['rule_id']:30} | {r['location']}")
        print(f"    {r['message'][:80]}")

    print("\n" + "=" * 60)
    print("TEST 3 — clean code (should find 0)")
    print("=" * 60)
    clean_code = """
def safe_add(a, b):
    return int(a) + int(b)

def safe_format(name):
    return f"Hello, {name}"
"""
    results = run_codeql_scan(clean_code, "python")
    print(f"\nFound {len(results)} findings:")
    for r in results:
        print(f"  {r['cwe']:14} | {r['rule_id']:30} | {r['location']}")
