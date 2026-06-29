# HN Thread Access Evidence

HN thread read via the Hacker News CLI tool (`hackernews get-item`) **before** writing README.md.

## Thread

- **ID:** 17237295
- **Title:** "Zip Slip Vulnerability"
- **URL:** https://news.ycombinator.com/item?id=17237295
- **Linked article:** https://snyk.io/research/zip-slip-vulnerability (Snyk / Zip Slip, 2018)
- **Score:** 94 | **Comments:** 35
- **Posted:** 2018-06-05

This HN thread is from **2018** and is about **Zip Slip / archive path traversal broadly**, NOT specifically about Python 3.14 tarfile extraction filters. PEP 706 (2023) and Python 3.14's default extraction-filter change came YEARS after this HN thread. This lab connects the 2018 HN discussion to Python's later PEP 706 / Python 3.14 tarfile extraction-filter work.

## Key HN sentiments (summarized, not quoted verbatim except where noted)

- **"Zip Slip" is NOT new – classic directory traversal in archives** (tptacek): "You don't get to name this vulnerability. It's one of the oldest in the appsec book." "It's 'ZIP file directory traversal'." – Branding criticism (Snyk branded Zip Slip in 2018). Known since at least 2001: CVE-2001-1268 (Info-ZIP unzip), CVE-2001-1270 (PKZip), CVE-2001-1271 (rar) – jwilk. Used to jailbreak Windows Phones. CVE-2015-4641: Samsung SwiftKey root exploit via untrusted ZIP over HTTP. PoC tar trojan in the '90s (Fnoord). "Every appsec tester looks for these vulnerabilities and routinely finds them" (tptacek).

- **"Isn't it a feature?" / "behavior by design?" debate** (dpedu, ComputerGuru): dpedu: "I've seen this in tar – isn't it a feature?" the8472: "In tar it definitely is because you can have symlinks using relative paths … it won't be a lossy transfer." wang_li: "Not a good feature. Figuring out the rules that would allow the use of .. in a path name in a safe way seems a lot more difficult than figuring out why you want to put .. into your archive." jschwartzi: validate member names BEFORE extraction, or use chroot jail.

- **Python tarfile / zipfile behavior – extract vs extractall confusion** – jwilk initially claimed "Python's tarfile and zipfile (and shutil) modules have no protection against directory traversal" – masklinn corrected: Python's `ZipFile.extract` DOES strip absolute paths and `..` components. BUT `extractall` has a warning that it does NOT mitigate directory traversal – bjpbakker: "it vows for an easy mistake. I'm a fan of telling that a function is unsafe (by design) by its name. So `unsafeExtractall`". jwilk: "The tarfile module is still vulnerable" – linking https://bugs.python.org/issue17102. **This is from 2018 – before PEP 706 (2023) and Python 3.14 default filter changes.**

- **Symlink traps – tar-specific footgun** (benmmurphy): tar allows embedding symlinks pointing outside the archive, then tricking tar into following the symlink during extraction. macOS tar blocks this, other platforms' tar will "happily extract through symlinks". "There was one PaaS platform where you could extract through symlinks to break out of their sandbox." zipfile also has symlink handling quirks.

- **Naive path validation is easy to get wrong** (tlb): Found a bug in Snyk's own Node.js validation example – `filePath.indexOf(targetFolder) != 0` can be bypassed: `targetFolder="/var/foo"` → deposit files in `/var/foo.secret` via path `"../foo.secret/blub"`. Need proper path resolution / containment checks, not string prefix matching.

- **API naming confusion** – `extractall` sounds safe but had no traversal protection in 2018. HN commenters argued unsafe-by-default functions should be named `unsafeExtractall` to warn users.

## What the HN thread was NOT about

The HN thread (2018) was NOT about: PEP 706 (2023), Python 3.14 tarfile extraction filter defaults (2024/2025), real CVE exploitation, archive bombs, symlink races, OS sandboxing, package installer security, malware detection, third-party archive libraries, real tarballs / package indexes, external validators, database benchmarks, or production security proofs. Neither is this lab.

This lab tests Python 3.14's `tarfile` extraction filters (`filter="data"` / `filter="tar"` / `filter="fully_trusted"`), archive path traversal footguns, symlink/hardlink/special-file caveats, metadata sanitization, and safe handling boundaries – connecting the 2018 HN Zip Slip discussion to Python's later PEP 706 / Python 3.14 default-filter work.

## Access method

```bash
python3 ./hackernews get-item --id 17237295  # story
# then ~30 top comments and replies individually:
# 17238238 (tptacek – "You don't get to name this vulnerability")
# 17237602 (jaxbot – Windows Phone jailbreak via Zip Slip)
# 17239020 (tlb – Node.js path validation bug)
# 17240481 (diamondo25 – CVE-2015-4641 Samsung SwiftKey)
# 17237667 (jwilk – path-traversal-samples repo)
# 17237878 (benmmurphy – symlink traps, tar vs zip behavior, PaaS sandbox escape)
# 17244488 (evilDagmar – "up there with buffer overflow bugs")
# 17237642 (jwilk – "Python's tarfile and zipfile have no protection")
# 17237664 (dpedu – "isn't it a feature?")
# 17238562 (ComputerGuru – "behavior that is basically by design?")
# 17240266 (zokier – "valid usecase for having `..` in a ZIP file?")
# 17237665 (masklinn – Python ZipFile.extract DOES strip .. and absolute paths)
# 17237866 (bjpbakker – extractall warning, "unsafeExtractall")
# 17238117 (jwilk – "tarfile module is still vulnerable", bugs.python.org/issue17102)
# 17240845 (tptacek – "It's 'ZIP file directory traversal'")
# …
```

Raw API responses saved in this repo:
- `hn_thread_17237295.json` – story + ~30 comments
- `hn_comments_sample.jsonl` – comment bodies

The README.md sentiment summary was written from these actual HN comments, distinguishes between what HN commenters discussed in 2018, what PEP 706 later changed, what Python's tarfile module exposes today (Python 3.14), and what this toy lab can actually prove, and does NOT pretend the HN thread was a Python 3.14 discussion.

## Date accessed

2026-06-29, before initial README.md commit.
