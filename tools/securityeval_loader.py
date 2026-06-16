import json
import os

LOCAL_CACHE = "data/securityeval_stratified.json"
FULL_CACHE = "data/securityeval_full.json"


def adapt_task(task):
    """Build spec string for Generator from SecurityEval prompt."""
    spec = f"TASK ID: {task['task_id']}\n"
    spec += f"TARGET CWE: {task['cwe']}\n\n"
    spec += "INSTRUCTIONS:\n"
    spec += "Complete the following Python code. Implement the function as described in the docstring. "
    spec += "Write production-quality code.\n\n"
    spec += "PROMPT (complete this code):\n"
    spec += "```python\n"
    spec += task['prompt'].rstrip() + "\n"
    spec += "```\n"
    return spec


def load_securityeval_tasks():
    """Load stratified SecurityEval tasks. Returns (specs_list, task_data_list)."""
    if not os.path.exists(LOCAL_CACHE):
        raise FileNotFoundError(f"Stratified file missing: {LOCAL_CACHE}")

    with open(LOCAL_CACHE) as f:
        data = json.load(f)

    tasks = data['tasks']
    specs = []
    task_data = []

    for t in tasks:
        specs.append(adapt_task(t))
        task_data.append({
            "task_id": t['task_id'],
            "scenario_id": t['task_id'],
            "framework": "Python",
            "tier": t['tier'],
            "potential_cwes": [int(t['cwe'].split('-')[1])]
        })

    print(f"[SECURITYEVAL] Loaded {len(specs)} tasks, {len(set(t['cwe'] for t in tasks))} unique CWEs")
    return specs, task_data


def _normalize_full_task(task):
    """Normalize full SecurityEval records to the stratified task schema."""
    task_id = task["ID"]
    cwe = task_id.split("_", 1)[0]
    return {
        "task_id": task_id,
        "cwe": cwe,
        "tier": "full",
        "prompt": task["Prompt"],
        "insecure_ref": task["Insecure_code"],
    }


def load_securityeval_tasks_full():
    """Load full 121-task SecurityEval pool. Returns (specs_list, task_data_list)."""
    if not os.path.exists(FULL_CACHE):
        raise FileNotFoundError(f"Full SecurityEval file missing: {FULL_CACHE}")

    with open(FULL_CACHE) as f:
        raw_tasks = json.load(f)

    tasks = [_normalize_full_task(t) for t in raw_tasks]
    specs = []
    task_data = []

    for t in tasks:
        specs.append(adapt_task(t))
        task_data.append({
            "task_id": t["task_id"],
            "scenario_id": t["task_id"],
            "framework": "Python",
            "tier": t["tier"],
            "potential_cwes": [int(t["cwe"].split("-")[1])]
        })

    print(f"[SECURITYEVAL] Loaded {len(specs)} full tasks, {len(set(t['cwe'] for t in tasks))} unique CWEs")
    return specs, task_data


# Backward-compat alias for main.py
load_baxbench_tasks = load_securityeval_tasks


if __name__ == "__main__":
    specs, meta = load_securityeval_tasks()
    print(f"\nTotal: {len(specs)}")
    print(f"\nFirst spec:")
    print(specs[0])
    print(f"\nFirst meta: {meta[0]}")
