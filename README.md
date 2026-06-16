# ATMG Anonymous Rebuttal Artifact

This repository is an anonymous artifact snapshot for the ATMG rebuttal. It
contains the source code, task lists, condition configuration, Docker sandbox
files, analysis scripts, and compact result artifacts needed to reproduce the
headline rebuttal statistics.

The snapshot intentionally omits local virtual environments, CodeQL binaries,
large generated databases, private notes, and full raw working-tree logs.

## Contents

- `agents/`: Generator, Attacker, Analyst, and Manipulator logic.
- `tools/`: CodeQL wrapper, sandbox execution, GPU/model helpers, and dataset
  loaders.
- `docker/`: Python sandbox image definition and build helper.
- `data/securityeval_stratified.json`: 35-task stratified subset.
- `data/securityeval_full.json`: full 121-task SecurityEval list.
- `data/stratified_tasks_p3*.json`: stratified task metadata used by earlier
  phase scripts.
- `results/`: JSON run records and summaries used for rebuttal statistics.
- `logs/`: representative anonymized logs for spot checking.
- `analyze.py`: Wilson confidence intervals and one-sided Fisher exact tests.

## Conditions

The main runner supports these conditions:

| Condition | Vector A | Vector B | Guard A | Guard B |
|---|---:|---:|---:|---:|
| `baseline` | off | off | on | on |
| `vector_a_undefended` | on | off | off | on |
| `vector_a_defended` | on | off | on | on |
| `vector_b_undefended` | off | on | on | off |
| `vector_b_defended` | off | on | on | on |
| `vector_a_guardb_only` | on | off | off | on |
| `vector_b_guarda_only` | off | on | on | off |
| `both_vectors_defended` | on | on | on | on |

Vector A targets Analyst-facing sandbox evidence. Guard A enforces
evidence-grounding constraints on Analyst findings. Vector B targets
Generator-facing patch feedback. Guard B sanitizes patch feedback before it is
reused by the Generator.

The deterministic manipulator payload templates are implemented in
`agents/manipulator.py`. They are included for reproducibility and are scoped to
the synthetic benchmark pipeline.

## Reproduce Headline Numbers

Create an environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If SciPy is unavailable, `analyze.py` still computes descriptive statistics and
Wilson intervals, but Fisher exact p-values require SciPy.

### 35-task 3-seed campaign

```bash
python analyze.py --task-set stratified --seeds 42,43,44
```

Expected Guard A effect:

```text
Vec-A undefended ISR: 26/48 = 54.2%
Wilson CI: 40.3%-67.4%

Vec-A defended ISR: 6/48 = 12.5%
Wilson CI: 5.9%-24.7%

One-sided Fisher exact p = 1.27e-05
Odds ratio = 8.27
```

Baseline serious-unresolved counts across seeds 42, 43, 44 are `3/35`,
`3/35`, and `4/35`. Baseline clean counts are `22/35`, `23/35`, and
`26/35`; mean final CVSS values are `2.27`, `2.16`, and `1.75`.

### Full 121-task seed-42 campaign

```bash
python analyze.py --task-set full --seeds 42
```

Expected Guard A effect:

```text
Vec-A undefended ISR: 33/55 = 60.0%
Vec-A defended ISR: 5/55 = 9.1%
Reduction: 84.8%
One-sided Fisher exact p = 9.73e-09
Odds ratio = 15.0
```

Baseline at full scale:

```text
Clean: 78/121
Residual nonzero: 43/121 = 35.5%
Serious unresolved: 7/121
Mean final CVSS: 2.18
```

### Analyst model swap

```bash
python analyze.py \
  --task-set stratified \
  --seeds 42 \
  --conditions baseline_analyst_gemma2_27b,vector_a_undefended_analyst_gemma2_27b,vector_a_defended_analyst_gemma2_27b
```

Expected Gemma2:27b Analyst result:

```text
Vec-A undefended ISR: 11/16 = 68.8%
Vec-A defended ISR: 1/16 = 6.2%
Reduction: 90.9%
One-sided Fisher exact p = 3.18e-04
Odds ratio = 33.0
```

For comparison, the default Qwen Analyst seed-42 result is:

```text
Vec-A undefended ISR: 12/17 = 70.6%
Vec-A defended ISR: 1/17 = 5.9%
Reduction: 91.7%
One-sided Fisher exact p = 1.16e-04
Odds ratio = 38.4
```

## Running New Experiments

The included JSON results are sufficient to reproduce rebuttal statistics.
Running new experiments requires local model and tool setup:

- Python 3
- Ollama with the configured local models
- Docker
- CodeQL CLI available on `PATH` or via `CODEQL_BIN=/path/to/codeql`
- Optional NVIDIA GPU for practical local inference

Example:

```bash
python -u main.py \
  --iterations 5 \
  --condition vector_a_defended \
  --seed 42 \
  --task-set stratified
```

Build the optional sandbox image:

```bash
cd docker
./build_sandbox_images.sh
```

## Safety Scope

This artifact is a research prototype for controlled benchmark experiments. It
uses synthetic SecurityEval tasks, deterministic injection templates, and
isolated sandbox execution. It is not intended to attack real systems, deploy
generated code, or release operational backdoor templates.
