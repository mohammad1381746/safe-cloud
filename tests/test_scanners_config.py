import pytest

from scanners import (
    ScannerConfigError,
    render_command_preview,
    validate_docker_image,
    validate_env_vars,
    validate_scan_command,
    validate_scanner_config,
)

VALID_SCANNER_FORM = {
    "name": "ClamAV",
    "slug": "clamav",
    "description": "test",
    "enabled": True,
    "docker_image": "clamav/clamav:latest",
    "scan_command": ["clamscan", "--no-summary", "{{FILE}}"],
    "env_vars": {"FOO": "bar"},
    "result_parser": "clamav_wrapper_json",
    "timeout_seconds": 120,
    "cpu_limit": 1.0,
    "memory_limit_mb": 512,
}


def test_valid_scan_command_accepted():
    assert validate_scan_command(["clamscan", "--no-summary", "{{FILE}}"]) == ["clamscan", "--no-summary", "{{FILE}}"]


def test_scan_command_must_be_a_list():
    with pytest.raises(ScannerConfigError):
        validate_scan_command("clamscan --no-summary {{FILE}}")


def test_scan_command_rejects_empty_list():
    with pytest.raises(ScannerConfigError):
        validate_scan_command([])


@pytest.mark.parametrize("bad_arg", [
    "clamscan; rm -rf /",
    "$(whoami)",
    "`whoami`",
    "clamscan && echo pwned",
    "clamscan | tee /etc/passwd",
    "clamscan > /etc/passwd",
    "clamscan\nrm -rf /",
])
def test_scan_command_rejects_shell_metacharacters(bad_arg):
    with pytest.raises(ScannerConfigError):
        validate_scan_command(["clamscan", bad_arg])


def test_scan_command_allows_placeholders_without_triggering_char_check():
    # {{FILE}} and {{OUTPUT}} contain characters ({ } /) that would
    # otherwise be rejected - the validator must strip them before
    # applying the safe-character check.
    assert validate_scan_command(["scan", "{{FILE}}", "{{OUTPUT}}"]) == ["scan", "{{FILE}}", "{{OUTPUT}}"]


def test_render_command_preview_substitutes_placeholders():
    rendered = render_command_preview(["clamscan", "{{FILE}}", "-o", "{{OUTPUT}}"], "/scan/test.pdf", "/output")
    assert rendered == ["clamscan", "/scan/test.pdf", "-o", "/output"]


def test_validate_docker_image_rejects_shell_metacharacters():
    with pytest.raises(ScannerConfigError):
        validate_docker_image("clamav/clamav:latest; rm -rf /")


def test_validate_docker_image_accepts_normal_reference():
    assert validate_docker_image("clamav/clamav:latest") == "clamav/clamav:latest"


def test_validate_env_vars_requires_upper_snake_case_keys():
    with pytest.raises(ScannerConfigError):
        validate_env_vars({"lowercase": "value"})


def test_validate_env_vars_accepts_valid_keys():
    assert validate_env_vars({"MAX_SCAN_SIZE": "100"}) == {"MAX_SCAN_SIZE": "100"}


def test_validate_scanner_config_happy_path():
    cleaned = validate_scanner_config(VALID_SCANNER_FORM)
    assert cleaned["slug"] == "clamav"
    assert cleaned["scan_command"] == ["clamscan", "--no-summary", "{{FILE}}"]


def test_validate_scanner_config_rejects_bad_slug():
    bad = {**VALID_SCANNER_FORM, "slug": "Not A Slug!"}
    with pytest.raises(ScannerConfigError):
        validate_scanner_config(bad)


def test_validate_scanner_config_rejects_out_of_range_timeout():
    bad = {**VALID_SCANNER_FORM, "timeout_seconds": 999999}
    with pytest.raises(ScannerConfigError):
        validate_scanner_config(bad)


def test_validate_scanner_config_rejects_unknown_result_parser():
    bad = {**VALID_SCANNER_FORM, "result_parser": "eval_arbitrary_python"}
    with pytest.raises(ScannerConfigError):
        validate_scanner_config(bad)
