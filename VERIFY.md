# VERIFY.md

Fresh-clone verification – python-tarfile-extraction-filter-lab

## Commit verified

```
38529e64cf29036e4c07f50956a1542f1d65b947
python-tarfile-extraction-filter-lab – initial
```

## Fresh clone transcript

This lab **requires Python 3.14+** for `tarfile` extraction filter defaults (PEP 706). The transcript below uses `uv run --python 3.14` to provision/run CPython 3.14. uv was used **only for interpreter provisioning**, NOT for installing project dependencies.

```bash
$ git clone https://github.com/necat101/python-tarfile-extraction-filter-lab.git verify_tarfile
Cloning into 'verify_tarfile'...

$ cd verify_tarfile

$ uv run --python 3.14 python -c "import sys, tarfile; print(sys.version.split()[0]); print(tarfile.data_filter); print(tarfile.tar_filter)"
3.14.6
<function data_filter at 0x783620aec040>
<function tar_filter at 0x783620ae7ed0>

$ uv run --python 3.14 python -m py_compile generate_cases.py run_lab.py

$ uv run --python 3.14 python generate_cases.py
Generated 53 cases
Wrote cases.json

$ uv run --python 3.14 python run_lab.py
Passed 848/848, failed 0
Wrote RESULTS.md, results_rows.csv (848 rows), results_rows.json
```

Exit code: 0

## Environment

- System Python: 3.12.3
- Benchmark Python: 3.14.6 (via `uv run --python 3.14`)
- Benchmark Python executable: `/home/ubuntu/.local/share/uv/python/cpython-3.14.6-linux-x86_64-gnu/bin/python3.14`
- Platform: Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
- tarfile.data_filter available: True
- tarfile.tar_filter available: True
- tarfile.fully_trusted_filter available: True
- Cases: 53 | Methods: 16 | Total runs: 848
- Network calls during benchmark: 0
- Subprocess count: 0
- uv used for interpreter provisioning: yes
- External archive / malware / package / API calls: 0

## Artifacts produced

- `cases.json` – 53 deterministic synthetic archive member cases
- `RESULTS.md` – summary tables
- `results_rows.csv` – 848 rows, full per-method/per-case records
- `results_rows.json` – same data as JSON

All artifacts match the committed versions (modulo timestamps / tracemalloc memory counters in RESULTS.md).

## Interpreter provisioning note

`uv` was used to obtain/run CPython 3.14 (`uv run --python 3.14 …`). No pip, uv, or other package manager was used to install project dependencies (libarchive, patool, py7zr, zstandard, pytest, hypothesis, numpy, pandas, etc.). The lab uses Python 3.14+ stdlib `tarfile` / `zipfile` only. Network use occurred only during `uv python install 3.14` (one-time interpreter download, before the benchmark). No network calls occurred during `generate_cases.py` or `run_lab.py`.
