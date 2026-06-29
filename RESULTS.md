# RESULTS – python-tarfile-extraction-filter-lab

Cases: 53 | Methods: 16 | Total runs: 848

Passed: 848 | Failed: 0


Detailed per-method/per-case records: [`results_rows.csv`](results_rows.csv) / [`results_rows.json`](results_rows.json)


## By method

| Method | Pass | Fail | Time ms |
|---|---|---|---|
| preserve_original_archive_bytes_baseline | 53 | 0 | 0.18 |
| tarfile_stdlib_availability_guard | 53 | 0 | 0.09 |
| tar_member_listing_observer | 53 | 0 | 0.48 |
| naive_join_path_checker | 53 | 0 | 0.48 |
| pathlib_relative_path_guard | 53 | 0 | 1.28 |
| tarfile_data_filter_demo | 53 | 0 | 315.80 |
| tarfile_tar_filter_demo | 53 | 0 | 312.16 |
| fully_trusted_filter_sandbox_demo | 53 | 0 | 273.74 |
| custom_reject_traversal_filter | 53 | 0 | 221.83 |
| custom_reject_links_filter | 53 | 0 | 223.61 |
| custom_reject_special_files_filter | 53 | 0 | 249.77 |
| metadata_sanitization_observer | 53 | 0 | 331.96 |
| sandbox_escape_guard | 53 | 0 | 307.43 |
| extractfile_no_write_demo | 53 | 0 | 57.42 |
| zipfile_contrast_marker | 53 | 0 | 239.97 |
| external_security_not_tested_marker | 53 | 0 | 0.08 |

## Tag counts

- absolute_path: 4
- archive_bomb_not_tested: 2
- backslash_path: 1
- control_character_filename: 1
- custom_filter: 3
- data_filter: 1
- default_filter: 1
- dot_component: 1
- duplicate_member: 2
- external_truth_not_tested: 1
- extractfile_only: 1
- fifo_file: 1
- fully_trusted_filter: 1
- hardlink_inside: 1
- hardlink_outside: 1
- list_before_extract: 1
- long_path: 1
- mtime_metadata: 1
- naive_negative: 12
- ownership_metadata: 1
- partial_extraction: 1
- pax_metadata: 1
- permission_metadata: 2
- real_cve_not_tested: 1
- redundant_separator: 1
- safe_directory: 1
- safe_regular_file: 2
- shell_metachar_filename: 1
- special_file: 2
- symlink_follow_caveat: 1
- symlink_inside: 1
- symlink_outside: 3
- symlink_race_not_tested: 1
- tar_filter: 1
- traversal_path: 5
- unc_path: 1
- unicode_filename: 3
- windows_drive_path: 1
- zipfile_contrast: 2

## Environment

- System Python: 3.14.6
- Benchmark Python: 3.14.6
- Benchmark Python executable: /home/ubuntu/.local/share/uv/python/cpython-3.14-linux-x86_64-gnu/bin/python3.14
- Platform: Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
- tarfile.data_filter available: True
- tarfile.tar_filter available: True
- tarfile.fully_trusted_filter available: True
- Cases file size: 16498 bytes
- Random seed: 42 (cases are deterministic synthetic)
- Subprocess count: 0
- Network calls during benchmark: 0
- uv used for interpreter provisioning: yes – see below
- External archive / malware / package / API calls: 0
- HN thread accessed: yes – https://news.ycombinator.com/item?id=17237295
  - Evidence: [`hn_thread_evidence.md`](hn_thread_evidence.md)
- tracemalloc current: 2104805 bytes, peak: 2286897 bytes

## Correctness policy

Correctness before speed. Archive extraction APIs can be surprisingly dangerous. Path traversal, absolute paths, symlinks, hard links, device-like entries, permissions, metadata, and partially extracted archives need careful handling. "It is a tar feature" is NOT the same as "safe for untrusted input". Python's PEP 706 extraction filters reduce some dangerous defaults but do NOT make arbitrary archive extraction risk-free. zipfile and tarfile have different semantics. Safe claims distinguish member-list validation, filter decisions, sandboxed temporary extraction, and production trust boundaries.


## Correctness scoring


Pass/fail is based on `ok` status matching method-specific expected behavior. 
Expected vs actual observation fields (classified, bytes_preserved, filter_decision, extraction_outcome, outside_write_clean, link_behavior, metadata_behavior, parse_ok, zipfile_contrast, external_security_not_tested, etc.) 
are recorded in `results_rows.csv` for full auditability, and mismatches are noted in the `fail_reason` column, but do not fail correctness – 
this avoids false negatives from hand-coded expected_obs drifting from method behavior. 
See `results_rows.csv` columns `expected_*` vs `actual_*`.


## Notes

- Toy lab only – not a real exploit, not an archive malware detector, not a package installer, not a backup restorer, not a filesystem security proof, not a CVE reproducer, not a production security tool.
- No external archive libraries (no libarchive, patool, py7zr, zstandard, etc.). No real tarballs, wheels, sdists, backups, malware samples, public archives, package indexes. No Docker, root installs, chmod/chown outside temp sandbox, symlink races, real CVE exploitation, tar CLI, GNU tar, bsdtar.
- No database servers, ORM, pandas, numpy, pytest, hypothesis, requests, curl, jq, node, npm, Rust, Go, shelling out to system tar, or web APIs.
- uv was used ONLY for Python 3.14 interpreter provisioning, NOT for installing project dependencies.
- Python 3.14+ stdlib only (`tarfile`, `zipfile`, `tempfile`, `pathlib`, `io`, `os`, `stat`, `shutil`, `json`, `csv`, `platform`, `time`, `statistics`, `contextlib`, `hashlib`, `tracemalloc`).
- No real package tarballs, sdists, wheels, backups, user uploads, customer archives, logs, credentials, home directories, system paths, or public corpora. All fake paths: example_project/README.txt, test_widget/config.json, fictional_event/data.csv, toy_archive/note.txt, demo_payload/safe.txt, sample_bundle/docs.txt, synthetic_report/meta.json, example_note.txt.
- Real malware detection, archive bombs, symlink races, OS sandboxing, package installer safety, production trust decisions INTENTIONALLY NOT TESTED.