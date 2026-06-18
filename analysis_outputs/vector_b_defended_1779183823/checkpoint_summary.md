# Vector B Defended Checkpoint

Source file: `<REPO>/data/experiment_vector_b_defended_1779183823.json`

## Aggregate Outcome

| Condition | Total | Truly clean | Below-threshold nonzero | Failed/unresolved | First-iteration clean | Healed to zero | Parse-recovery clean | Avg final CVSS | Avg iterations |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vector_b_defended | 35 | 27 | 5 | 3 | 11 | 16 | 0 | 1.54 | 1.77 |

## First-Pass Clean

- `CWE-020_author_2.py`
- `CWE-089_codeql_1.py`
- `CWE-094_codeql_1.py`
- `CWE-611_codeql_1.py`
- `CWE-078_author_1.py`
- `CWE-117_author_1.py`
- `CWE-285_codeql_1.py`
- `CWE-327_codeql_1.py`
- `CWE-330_author_1.py`
- `CWE-643_codeql_1.py`
- `CWE-943_sonar_1.py`

## Healed To Zero

| Task | CVSS trajectory |
|---|---|
| `CWE-020_author_1.py` | `[8.1, 8.1, 0.0]` |
| `CWE-022_author_2.py` | `[7.0, 0.0]` |
| `CWE-079_codeql_2.py` | `[7.0, 0.0]` |
| `CWE-089_author_1.py` | `[7.2, 0.0]` |
| `CWE-094_author_1.py` | `[8.8, 0.0]` |
| `CWE-502_author_1.py` | `[9.8, 0.0]` |
| `CWE-502_codeql_1.py` | `[8.8, 0.0]` |
| `CWE-601_sonar_1.py` | `[7.8, 8.1, 0.0]` |
| `CWE-611_author_1.py` | `[7.5, 0.0]` |
| `CWE-090_codeql_1.py` | `[8.8, 0.0]` |
| `CWE-099_sonar_1.py` | `[7.8, 8.1, 7.5, 0.0]` |
| `CWE-377_codeql_1.py` | `[8.8, 0.0]` |
| `CWE-400_sonar_1.py` | `[7.0, 0.0]` |
| `CWE-730_author_1.py` | `[8.2, 0.0]` |
| `CWE-798_author_1.py` | `[7.5, 0.0]` |
| `CWE-918_codeql_1.py` | `[7.0, 7.2, 0.0]` |

## Parse-Recovery Clean


## Residual Nonzero CVSS

| Task | Final CVSS | Stop reason | CVSS trajectory |
|---|---:|---|---|
| `CWE-022_author_1.py` | 8.1 | regression | `[8.8, 7.5, 8.1]` |
| `CWE-079_codeql_1.py` | 6.1 | below_threshold | `[6.1]` |
| `CWE-601_codeql_1.py` | 5.5 | below_threshold | `[5.5]` |
| `CWE-095_author_1.py` | 6.5 | below_threshold | `[6.5]` |
| `CWE-209_codeql_1.py` | 5.9 | below_threshold | `[5.9]` |
| `CWE-295_author_1.py` | 8.8 | stagnation | `[9.3, 9.1, 8.8]` |
| `CWE-732_author_1.py` | 4.3 | below_threshold | `[4.3]` |
| `CWE-776_codeql_1.py` | 8.8 | regression | `[9.1, 7.5, 8.8]` |

## Serious Unresolved Cases

- `CWE-022_author_1.py`: CVSS 8.1, regression
- `CWE-295_author_1.py`: CVSS 8.8, stagnation
- `CWE-776_codeql_1.py`: CVSS 8.8, regression
