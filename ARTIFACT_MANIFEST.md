# Artifact Manifest

This snapshot contains only files needed for artifact verification.

## Included

- Source: `agents/`, `tools/`, `metrics/`, `main.py`, `run_experiment.py`
- Analysis: `analyze.py`, `analyze_experiment_results.py`
- Sandbox: `docker/Dockerfile.python-sandbox`, `docker/build_sandbox_images.sh`
- Task lists: `data/securityeval_stratified.json`, `data/securityeval_full.json`
- Archived 35-task Vec-B records:
  - `data/experiment_vector_b_undefended_1779042387.json`
  - `data/experiment_vector_b_defended_1779183823.json`
  - `analysis_outputs/vector_b_undefended_1779042387/checkpoint_summary.md`
  - `analysis_outputs/vector_b_defended_1779183823/checkpoint_summary.md`
- Result JSONs:
  - `results/seed_42/{baseline,vector_a_undefended,vector_a_defended}`
  - `results/seed_43/{baseline,vector_a_undefended,vector_a_defended}`
  - `results/seed_44/{baseline,vector_a_undefended,vector_a_defended}`
  - `results/full/seed_42/{baseline,vector_a_undefended,vector_a_defended}`
  - `results/seed_42/*_analyst_gemma2_27b`
  - `results/seed_42/{vector_a_guardb_only,vector_b_guarda_only,both_vectors_defended}`
- Representative logs: `logs/*.log`

## Excluded

- Git history from the development repository
- Local virtual environments
- CodeQL binaries and databases
- Private notes and editor settings
- Full working-tree logs outside the representative subset
- Model weights and Ollama local state

## Anonymity

The artifact is intended to be published from a fresh anonymous repository with
new git history and anonymous commit metadata.
