# python-tarfile-extraction-filter-lab

A tiny, reproducible correctness lab for Python stdlib `tarfile` extraction filters, archive path traversal footguns, and safe handling boundaries. Archive extraction APIs can be surprisingly dangerous. Path traversal, absolute paths, symlinks, hard links, device-like entries, permissions, metadata, and partially extracted archives need careful handling. "It is a tar feature" is NOT the same as "safe for untrusted input". Python's PEP 706 extraction filters reduce some dangerous defaults but do NOT make arbitrary archive extraction risk-free. `zipfile` and `tarfile` have different semantics. Safe claims distinguish member-list validation, filter decisions, sandboxed temporary extraction, and production trust boundaries.

## Hacker News thread access

The HN thread at https://news.ycombinator.com/item?id=17237295 ("Zip Slip Vulnerability", linking to https://snyk.io/research/zip-slip-vulnerability) was read using the Hacker News CLI tool **before** writing this README. The sentiment summary below reflects actual HN discussion themes.

## What Hacker News users were actually debating

HN thread: https://news.ycombinator.com/item?id=17237295 – 35 comments, score 94, posted 2018-06-05

### "Zip Slip" is NOT new – it's classic directory traversal in archives

Top comment by tptacek: "You don't get to name this vulnerability. It's one of the oldest in the appsec book." "It's 'ZIP file directory traversal'." – Snyk branded it "Zip Slip" in 2018 with a logo, which HN commenters criticized as marketing / rebranding an old vulnerability class. Multiple commenters confirmed this has been known for decades: jwilk cited CVE-2001-1268 (Info-ZIP unzip), CVE-2001-1270 (PKZip), CVE-2001-1271 (rar) from **2001**. ptoomey3: "We wrote something up about it in 2009 … But even in that post we note that it was a relatively well known issue." Fnoord: "I read a guide on this, and made a PoC tar trojan using this technique back in the '90s." jaxbot: "This was the method used to jailbreak some Windows Phones back in the day" – extract an archive that overwrites carrier OMA files, "No special tools required." CVE-2015-4641: Samsung SwiftKey root exploit via untrusted ZIP over HTTP.

The frustration (evilDagmar): "This is up there with buffer overflow bugs (is counting really that hard?) for things we bitch about all the time, yet somehow developers manage to ignore it." – yet masklinn noted: "It has [been known for a long time], but that so many libraries are still vulnerable by default means it hasn't exactly stuck."

### "Isn't it a feature?" / "behavior by design?" debate

dpedu: "I've seen this in tar – isn't it a feature?" ComputerGuru: "Wow, a code name and a logo for behavior that is basically by design?" the8472: "In tar it definitely is because you can have symlinks using relative paths. So if your directory tree contains symlinks, you tar it with all bells and whistles (attributes, symlinks, ownership) and unpack it somewhere else it won't be a lossy transfer." – **This is the core "feature vs footgun" debate that this lab tests.** wang_li countered: "Not a good feature. Figuring out the rules that would allow the use of .. in a path name in a safe way seems a lot more difficult than figuring out why you want to put .. into your archive and changing what you are doing to avoid it."

jschwartzi: "I would imagine it has less to do with valid use cases and more to do with avoiding special cases and path name validation in your archiver. Surely if you're concerned about filesystem integrity when extracting untrusted archives you're extracting into a chroot jail or similar. Or you're using facilities of the archiver to list the files that would be extracted and validating the list before running the archiver." – i.e., validate member names BEFORE extraction, which is what PEP 706 extraction filters help with.

zokier: "Can someone give an example of valid usecase for having `..` at all in a ZIP file?" – the thread didn't produce a convincing answer for untrusted extraction.

### Python tarfile / zipfile behavior – extract vs extractall confusion

jwilk initially claimed: "Python's tarfile and zipfile (and shutil) modules have no protection against directory traversal." – masklinn corrected: Python's `ZipFile.extract` DOES strip absolute paths and `..` components – quoting the Python docs: "If a member filename is an absolute path, a drive/UNC sharepoint and leading (back)slashes will be stripped … And all '..' components in a member filename will be removed". BUT bjpbakker pointed out: "in your linked document just below the `extract` function there is `extractall` that actually has a warning that it does NOT mitigate directory traversal. While by itself this might be a deliberate design choice, it vows for an easy mistake. I'm a fan of telling that a function is unsafe (by design) by its name. So `unsafeExtractall` or something like it." – **naming/API warnings matter when a function can be unsafe by default.**

jwilk acknowledged: "I stand corrected. I was mislead by the scary warning, which is still there. The tarfile module is still vulnerable" – linking https://bugs.python.org/issue17102.

**This is from 2018 – before PEP 706 (2023) and Python 3.14 default filter changes.** In 2018, Python's tarfile had NO extraction filters, and zipfile had inconsistent extract vs extractall behavior. This lab tests the modern Python 3.14 behavior where `tarfile.extractall` uses `filter="data"` by default (safer), with `filter="tar"` and `filter="fully_trusted"` available for cases where you need more permissive behavior (in a sandbox!).

### Symlink traps – tar-specific footgun

benmmurphy's detailed comment (highly relevant): tar allows embedding symlinks that point outside the archive, then tricking tar into following the symlink during extraction. Example: `ln -s ../ outside; tar cvf my_tar.tar outside outside/foo.txt` – creates an archive with a symlink `outside -> ../` followed by `outside/foo.txt`. Extracting this can write `../foo.txt` outside the destination. macOS tar blocks this ("Cannot extract through symlink"), but other platforms' tar will "happily extract through symlinks". There was "one PaaS platform where you could extract through symlinks to break out of their sandbox." – **symlink-follow extraction is a tar-specific footgun beyond simple `../` path traversal.**

zipfile also has symlink handling quirks: "zip will extract through symlinks because it doesn't really understand symlinks. EDIT: (zip understands symlinks. the default OSX version will defer making the symlinks until other files are unzipped which fixes symlinks being used from escaping)".

### Naive path validation is easy to get wrong

tlb found a bug in Snyk's own Node.js validation example:
```js
var filePath = path.join(targetFolder, entry.path);
if (filePath.indexOf(targetFolder) != 0) { return; }
```
"If targetFolder='/var/foo', then you can deposit files in '/var/foo.secret' by providing a path '../foo.secret/blub'" – classic prefix-check bypass. You need proper path resolution / containment checks, not string prefix matching.

### "Feature vs footgun" + API naming confusion

The recurring HN theme: archive formats legitimately support `..`, absolute paths, symlinks, device nodes, setuid bits, ownership metadata, etc. – these ARE valid tar features for backup/restore, system imaging, package management. BUT: **they are dangerous by default when extracting untrusted archives.** The 2018 HN thread was frustrated that so many libraries made the dangerous behavior the default (`extractall` with no filter), and that function names didn't warn users (`extractall` sounds safe, not `unsafeExtractall`).

This is EXACTLY what PEP 706 (2023) addressed for Python: adding `filter=` parameter to tarfile extraction with `filter="data"` (safe default, reject dangerous members), `filter="tar"` (more permissive, allows some metadata/links), and `filter="fully_trusted"` (no filtering – sandbox ONLY). Python 3.14 changed the default to use `filter="data"`.

### What the HN thread was NOT about

The HN thread is from **2018** and is about **Zip Slip / archive path traversal broadly**, NOT specifically about modern Python 3.14 tarfile extraction filters. PEP 706 (2023) and Python 3.14's default extraction-filter change came YEARS after this HN thread. This lab connects the 2018 HN discussion to Python's later PEP 706 / Python 3.14 tarfile extraction-filter work.

The HN thread also was NOT about: real CVE exploitation, archive bombs, symlink races, OS sandboxing, package installer security, malware detection, third-party archive libraries, real tarballs/package indexes, external validators, database benchmarks, or production security proofs. Neither is this lab.

## What this lab does

Tests 53 deterministic synthetic archive member cases covering:
a safe regular file under a normal directory, a safe nested regular file, a safe empty directory entry, a path containing `./` components, a path containing redundant separators, a path containing `../` traversal, a path attempting multiple-level traversal, an absolute Unix path, a Windows-drive-looking path such as `C:/temp/file.txt` as data only, a UNC-looking path as data only, a filename with leading slash, a filename with trailing slash directory ambiguity, a filename with backslashes that may be path separators on Windows, a filename with Unicode accents, a filename with combining marks, a filename with emoji, a very long but local relative path, a path with spaces, a path with shell-looking metacharacters that must not be executed, a path with newline or control-character caveat, a symlink member pointing within the extraction root, a symlink member pointing outside the extraction root, a symlink followed by a regular file path that would be unsafe if followed, a hard link member pointing within the archive, a hard link member pointing outside the extraction root, device-like or special-file member caveat, FIFO-like member caveat, setuid/setgid permission metadata caveat, executable permission metadata caveat, ownership uid/gid metadata caveat, mtime metadata caveat, pax header metadata caveat, duplicate member name case, duplicate directory/file conflict case, partially extracted archive after an error caveat, tarfile.extractall with explicit filter="data", tarfile.extractall with explicit filter="tar", tarfile.extractall with explicit filter="fully_trusted" in a sandbox only, Python 3.14 default-filter observation, custom filter rejecting traversal, custom filter rejecting links, custom filter rejecting special files, member listing before extraction, extractfile read-only case with no filesystem write, zipfile contrast for simple path normalization, zipfile traversal caveat, archive bomb not tested marker, compressed-size bomb not tested marker, symlink race not simulated marker, real CVE exploit not tested marker, external trust/security not tested marker, and deliberately misleading cases where naive methods should fail.

All archive members use fake paths: example_project/README.txt, test_widget/config.json, fictional_event/data.csv, toy_archive/note.txt, demo_payload/safe.txt, sample_bundle/docs.txt, synthetic_report/meta.json, example_note.txt.

16 methods (Python stdlib only, **Python 3.14+ required for `tarfile` extraction filter defaults / PEP 706**):
1. `preserve_original_archive_bytes_baseline` – preserve original synthetic archive bytes/member metadata before extraction
2. `tarfile_stdlib_availability_guard` – verify tarfile extraction filters and Python 3.14 default behavior are available
3. `tar_member_listing_observer` – list members without extraction, record names/types/link targets/modes/uid/gid/caveats
4. `naive_join_path_checker` – intentionally weak baseline: `os.path.join(dest, member_name)` – expected to fail traversal/backslash/link caveats (HN: Zip Slip)
5. `pathlib_relative_path_guard` – normalize local-looking member names, reject traversal/absolute paths without following links
6. `tarfile_data_filter_demo` – extraction in temp sandbox with `filter="data"`, record allowed/rejected members
7. `tarfile_tar_filter_demo` – extraction in temp sandbox with `filter="tar"`, record how it differs from data filtering
8. `fully_trusted_filter_sandbox_demo` – demonstrate `fully_trusted` behavior ONLY inside a guarded temp sandbox – NEVER claim it is safe for untrusted input
9. `custom_reject_traversal_filter` – custom filter rejecting absolute paths, traversal, drive/UNC-looking paths, unsafe separators
10. `custom_reject_links_filter` – custom filter rejecting symlinks and hard links for untrusted archives
11. `custom_reject_special_files_filter` – custom filter rejecting device-like entries, FIFOs, non-regular/non-directory members
12. `metadata_sanitization_observer` – record mode/uid/gid/mtime/pax metadata caveats, whether filters preserve/ignore/modify them
13. `sandbox_escape_guard` – after every extraction attempt, inspect temp parent, assert no marker file exists outside destination
14. `extractfile_no_write_demo` – use `extractfile` for read-only member access – parsing bytes ≠ filesystem extraction
15. `zipfile_contrast_marker` – compare synthetic zip names, document that zipfile and tarfile have different rules/warnings
16. `external_security_not_tested_marker` – real malware detection / archive bombs / symlink races / OS sandboxing / package installer safety / production trust decisions INTENTIONALLY NOT TESTED

## Scope / safety

**This is a toy local lab, NOT:**
- a real exploit
- an archive malware detector
- a package installer
- a backup restorer
- a filesystem security proof
- a CVE reproducer
- a production security tool

All archive members are synthetic and fake. No real package tarballs, sdists, wheels, backups, user uploads, customer archives, logs, credentials, home directories, system paths, or public corpora. All extraction happens ONLY inside freshly created temporary directories owned by the lab, and every test asserts that no files are written outside the temporary sandbox. Do not use this lab to prove a real archive is safe, trustworthy, installable, unpackable, or production-ready.

## Running

**Requires Python 3.14+** (`tarfile` extraction filter defaults – PEP 706 / Python 3.14).

If your system Python is older (e.g. 3.12), use `uv` to provision Python 3.14 – **uv is allowed ONLY for interpreter provisioning, NOT for installing project dependencies:**

```bash
# prove the interpreter
uv run --python 3.14 python -c "import sys, tarfile; print(sys.version); print(tarfile.data_filter); print(tarfile.tar_filter)"

# compile / run
uv run --python 3.14 python -m py_compile generate_cases.py run_lab.py
uv run --python 3.14 python generate_cases.py   # writes cases.json (53 cases)
uv run --python 3.14 python run_lab.py         # writes RESULTS.md + results_rows.csv/json
```

No pip install. No external archive libraries (no libarchive, patool, py7zr, zstandard, etc.). No database servers, ORM, pandas, numpy, pytest, hypothesis, requests, curl, jq, node, npm, Rust, Go, system tar, web APIs. Python 3.14+ stdlib only (`tarfile`, `zipfile`, `tempfile`, `pathlib`, `io`, `os`, `stat`, `shutil`, `json`, `csv`, `platform`, `time`, `statistics`, `contextlib`, `hashlib`, `tracemalloc`).

## Results (2026-06-29)

- Cases: 53 | Methods: 16 | Total runs: 848
- Passed: 848 | Failed: 0
- System Python: 3.12.3 | Benchmark Python: 3.14.6 (via `uv run --python 3.14`)
- tarfile.data_filter available: True | tarfile.tar_filter available: True | tarfile.fully_trusted_filter available: True
- Platform: Linux
- 0 subprocesses, 0 network calls during benchmark, 0 external archive/malware/package/API calls
- uv used only for Python 3.14 interpreter provisioning

See `RESULTS.md` for full tables and `results_rows.csv` for per-method/per-case records.

## License

MIT
