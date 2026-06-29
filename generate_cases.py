#!/usr/bin/env python3
"""Generate deterministic synthetic tar/zip archive member test cases.

No real untrusted archives, tarballs, package files, user uploads, customer
archives, logs, credentials, or public corpora. All fake: example_project,
test_widget, fictional_event, toy_archive, demo_payload, sample_bundle,
synthetic_report, example_note.
"""
import json

cases = []

def add(cid, category, archive_name, member_name, context, tags, expected, **kwargs):
    case = {
        "id": cid,
        "category": category,
        "archive_name": archive_name,
        "member_name": member_name,
        "context": context,
        "tags": tags,
        "expected": expected,
    }
    case.update(kwargs)
    cases.append(case)

# ── Safe regular files ─────────────────────────────
add("T001", "safe_regular_file", "example_project", "example_project/README.txt",
    "safe_member", ["safe_regular_file"], "success")
add("T002", "safe_regular_file", "test_widget", "test_widget/nested/config.json",
    "safe_member", ["safe_regular_file"], "success")
add("T003", "safe_directory", "fictional_event", "fictional_event/data/",
    "safe_member", ["safe_directory"], "success")

# ── Path normalization caveats ─────────────────────
add("T004", "dot_component", "toy_archive", "toy_archive/./note.txt",
    "safe_member", ["dot_component"], "success")
add("T005", "redundant_separator", "demo_payload", "demo_payload//safe.txt",
    "safe_member", ["redundant_separator"], "success")

# ── Traversal / absolute paths ─────────────────────
add("T006", "traversal_path", "sample_bundle", "../outside.txt",
    "traversal_member", ["traversal_path","naive_negative"], "error",
    expected_filter="reject", expected_outside_write="blocked")
add("T007", "traversal_path", "synthetic_report", "sample_bundle/../../etc/passwd",
    "traversal_member", ["traversal_path","naive_negative"], "error",
    expected_filter="reject", expected_outside_write="blocked")
add("T008", "absolute_path", "example_note", "/etc/passwd",
    "absolute_path", ["absolute_path","naive_negative"], "error",
    expected_filter="reject", expected_outside_write="blocked")
add("T009", "absolute_path", "example_project", "/tmp/evil.txt",
    "absolute_path", ["absolute_path","naive_negative"], "error",
    expected_filter="reject", expected_outside_write="blocked")

# ── Windows / UNC / backslash paths ────────────────
add("T010", "windows_drive_path", "test_widget", "C:/temp/file.txt",
    "windows_path_caveat", ["windows_drive_path"], "error",
    expected_filter="reject")
add("T011", "unc_path", "fictional_event", "//server/share/file.txt",
    "windows_path_caveat", ["unc_path"], "error",
    expected_filter="reject")
add("T012", "absolute_path", "toy_archive", "/leading/slash.txt",
    "absolute_path", ["absolute_path"], "error",
    expected_filter="reject")
add("T013", "backslash_path", "demo_payload", "demo_payload\\subdir\\file.txt",
    "windows_path_caveat", ["backslash_path"], "success",
    caveat="backslashes may be path separators on Windows")

# ── Unicode / special filenames ────────────────────
add("T014", "unicode_filename", "sample_bundle", "sample_bundle/café.txt",
    "unicode_path", ["unicode_filename"], "success")
add("T015", "unicode_filename", "synthetic_report", "synthetic_report/cafe\u0301.txt",
    "unicode_path", ["unicode_filename"], "success",
    caveat="combining marks – NFC/NFD")
add("T016", "unicode_filename", "example_note", "example_note/📦.txt",
    "unicode_path", ["unicode_filename"], "success")
add("T017", "long_path", "example_project", "example_project/" + "a/"*30 + "deep.txt",
    "unicode_path", ["long_path"], "success")
add("T018", "shell_metachar_filename", "test_widget", "test_widget/sp ace $HOME `id`.txt",
    "safe_member", ["shell_metachar_filename"], "success",
    caveat="shell metacharacters must not be executed")
add("T019", "control_character_filename", "fictional_event", "fictional_event/bad\nname.txt",
    "safe_member", ["control_character_filename"], "success",
    caveat="newline/control char in filename")

# ── Symlinks ───────────────────────────────────────
add("T020", "symlink_inside", "toy_archive", "toy_archive/link_inside",
    "symlink_caveat", ["symlink_inside"], "success",
    member_type="symlink", link_target="toy_archive/safe.txt",
    expected_filter="data_filter_reject")
add("T021", "symlink_outside", "demo_payload", "demo_payload/evil_link",
    "symlink_caveat", ["symlink_outside","naive_negative"], "error",
    member_type="symlink", link_target="/etc/passwd",
    expected_filter="reject", expected_outside_write="blocked")
add("T022", "symlink_follow_caveat", "sample_bundle", "sample_bundle/tricky.txt",
    "symlink_caveat", ["symlink_follow_caveat"], "error",
    caveat="symlink followed by regular file – unsafe if followed")

# ── Hard links ─────────────────────────────────────
add("T023", "hardlink_inside", "synthetic_report", "synthetic_report/hard_inside",
    "hardlink_caveat", ["hardlink_inside"], "success",
    member_type="hardlink", link_target="synthetic_report/safe.txt")
add("T024", "hardlink_outside", "example_note", "example_note/hard_evil",
    "hardlink_caveat", ["hardlink_outside","naive_negative"], "error",
    member_type="hardlink", link_target="/etc/passwd",
    expected_filter="reject", expected_outside_write="blocked")

# ── Special files ──────────────────────────────────
add("T025", "special_file", "example_project", "example_project/dev_null",
    "special_file_caveat", ["special_file"], "error",
    member_type="character_device",
    expected_filter="reject")
add("T026", "fifo_file", "test_widget", "test_widget/my_fifo",
    "special_file_caveat", ["fifo_file"], "error",
    member_type="fifo",
    expected_filter="reject")

# ── Metadata caveats ───────────────────────────────
add("T027", "permission_metadata", "fictional_event", "fictional_event/suid_bin",
    "metadata_caveat", ["permission_metadata"], "success",
    mode=0o4755,
    caveat="setuid/setgid permission metadata")
add("T028", "permission_metadata", "toy_archive", "toy_archive/executable.sh",
    "metadata_caveat", ["permission_metadata"], "success",
    mode=0o755)
add("T029", "ownership_metadata", "demo_payload", "demo_payload/owned.txt",
    "metadata_caveat", ["ownership_metadata"], "success",
    uid=0, gid=0,
    caveat="ownership uid/gid metadata")
add("T030", "mtime_metadata", "sample_bundle", "sample_bundle/timed.txt",
    "metadata_caveat", ["mtime_metadata"], "success",
    mtime=1234567890)
add("T031", "pax_metadata", "synthetic_report", "synthetic_report/pax.txt",
    "metadata_caveat", ["pax_metadata"], "success",
    caveat="pax header metadata")

# ── Duplicates / conflicts ─────────────────────────
add("T032", "duplicate_member", "example_note", "example_note/dup.txt",
    "safe_member", ["duplicate_member"], "success",
    caveat="duplicate member name")
add("T033", "duplicate_member", "example_project", "example_project/conflict",
    "safe_member", ["duplicate_member"], "success",
    caveat="duplicate directory/file conflict")
add("T034", "partial_extraction", "test_widget", "test_widget/partial.txt",
    "metadata_caveat", ["partial_extraction"], "success",
    caveat="partially extracted archive after error")

# ── Filter behavior ────────────────────────────────
add("T035", "data_filter", "fictional_event", "fictional_event/safe.txt",
    "filter_behavior", ["data_filter"], "success",
    expected_filter="data")
add("T036", "tar_filter", "toy_archive", "toy_archive/safe.txt",
    "filter_behavior", ["tar_filter"], "success",
    expected_filter="tar")
add("T037", "fully_trusted_filter", "demo_payload", "demo_payload/safe.txt",
    "filter_behavior", ["fully_trusted_filter"], "success",
    expected_filter="fully_trusted",
    caveat="fully_trusted in sandbox ONLY – NOT safe for untrusted input")
add("T038", "default_filter", "sample_bundle", "sample_bundle/safe.txt",
    "filter_behavior", ["default_filter"], "success",
    caveat="Python 3.14 default extraction filter")
add("T039", "custom_filter", "synthetic_report", "../traversal.txt",
    "filter_behavior", ["custom_filter","traversal_path","naive_negative"], "error",
    expected_filter="reject")
add("T040", "custom_filter", "example_note", "example_note/link_evil",
    "filter_behavior", ["custom_filter","symlink_outside","naive_negative"], "error",
    member_type="symlink", link_target="/etc/passwd",
    expected_filter="reject")
add("T041", "custom_filter", "example_project", "example_project/dev_zero",
    "filter_behavior", ["custom_filter","special_file"], "error",
    member_type="character_device",
    expected_filter="reject")

# ── Member listing / extractfile ───────────────────
add("T042", "list_before_extract", "test_widget", "test_widget/listme.txt",
    "filter_behavior", ["list_before_extract"], "success")
add("T043", "extractfile_only", "fictional_event", "fictional_event/readme.txt",
    "filter_behavior", ["extractfile_only"], "success",
    caveat="extractfile read-only – no filesystem write")

# ── Zipfile contrast ───────────────────────────────
add("T044", "zipfile_contrast", "toy_archive", "toy_archive/zip_safe.txt",
    "zipfile_contrast", ["zipfile_contrast"], "success")
add("T045", "zipfile_contrast", "demo_payload", "../zip_traversal.txt",
    "zipfile_contrast", ["zipfile_contrast","traversal_path","naive_negative"], "error",
    expected_filter="reject")

# ── Not tested markers ─────────────────────────────
add("T046", "archive_bomb_not_tested", "sample_bundle", "sample_bundle/bomb.txt",
    "external_truth_not_tested", ["archive_bomb_not_tested"], "success",
    caveat="archive bomb NOT tested")
add("T047", "archive_bomb_not_tested", "synthetic_report", "synthetic_report/size_bomb.txt",
    "external_truth_not_tested", ["archive_bomb_not_tested"], "success",
    caveat="compressed-size bomb NOT tested")
add("T048", "symlink_race_not_tested", "example_note", "example_note/race.txt",
    "external_truth_not_tested", ["symlink_race_not_tested"], "success",
    caveat="symlink race NOT simulated")
add("T049", "real_cve_not_tested", "example_project", "example_project/cve.txt",
    "external_truth_not_tested", ["real_cve_not_tested"], "success",
    caveat="real CVE exploit NOT tested")
add("T050", "external_truth_not_tested", "test_widget", "test_widget/external.txt",
    "external_truth_not_tested", ["external_truth_not_tested"], "success",
    caveat="external trust/security NOT tested")

# ── Naive negative cases ───────────────────────────
add("T051", "naive_negative", "fictional_event", "../../../etc/passwd",
    "traversal_member", ["naive_negative","traversal_path"], "error",
    expected_filter="reject", expected_outside_write="blocked")
add("T052", "naive_negative", "toy_archive", "/absolute/evil.txt",
    "absolute_path", ["naive_negative","absolute_path"], "error",
    expected_filter="reject", expected_outside_write="blocked")
add("T053", "naive_negative", "demo_payload", "demo_payload/symlink_out",
    "symlink_caveat", ["naive_negative","symlink_outside"], "error",
    member_type="symlink", link_target="../../etc/passwd",
    expected_filter="reject", expected_outside_write="blocked")

print(f"Generated {len(cases)} cases")
with open("cases.json", "w") as f:
    json.dump(cases, f, indent=2)
print(f"Wrote cases.json")
