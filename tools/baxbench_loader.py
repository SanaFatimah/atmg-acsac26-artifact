import json
import os

LOCAL_CACHE = "data/baxbench_flask_full.json"
STRATIFIED = "data/stratified_tasks_p3.json"


def adapt_baxbench_task(task):
    spec = f"SCENARIO: {task['scenario_id']}\n"
    spec += f"TIER: {task.get('tier', 'unknown')}\n"
    spec += f"DESCRIPTION: {task['text_specification'].strip()}\n\n"
    spec += f"API SPECIFICATION (OpenAPI):\n{task['api_specification'].strip()}\n\n"
    spec += f"FRAMEWORK: {task['env_framework']}\n"
    spec += f"CONSTRAINTS: {task['env_instructions']}\n"
    return spec


def load_baxbench_tasks():
    """Load 14 Flask tasks from local cache. Returns (specs_list, task_data_list)."""
    if not os.path.exists(LOCAL_CACHE):
        raise FileNotFoundError(f"Run cache build first: {LOCAL_CACHE}")
    if not os.path.exists(STRATIFIED):
        raise FileNotFoundError(f"Stratification missing: {STRATIFIED}")

    with open(LOCAL_CACHE) as f:
        all_rows = json.load(f)
    with open(STRATIFIED) as f:
        stratified = json.load(f)['tasks']

    # Filter stratified to Flask only
    stratified_flask = [t for t in stratified if t['framework'] == 'Flask']
    target_ids = [t['task_id'] for t in stratified_flask]

    row_map = {r['task_id']: r for r in all_rows}

    specs, task_data = [], []
    missing = []
    for t_meta in stratified_flask:
        tid = t_meta['task_id']
        if tid not in row_map:
            missing.append(tid)
            continue
        row = dict(row_map[tid])
        row['tier'] = t_meta['tier']
        specs.append(adapt_baxbench_task(row))
        task_data.append({
            "task_id": tid,
            "scenario_id": t_meta['scenario_id'],
            "framework": t_meta['framework'],
            "tier": t_meta['tier'],
            "potential_cwes": t_meta['expected_cwes']
        })

    if missing:
        print(f"[BAXBENCH] WARNING — missing tasks: {missing}")
    print(f"[BAXBENCH] Loaded {len(specs)} Flask tasks from local cache")
    return specs, task_data


if __name__ == "__main__":
    specs, meta = load_baxbench_tasks()
    print(f"Total: {len(specs)}")
    for m in meta[:3]:
        print(" ", m['task_id'], m['tier'], m['potential_cwes'])
