import pytest

from security import (
    HostNotAllowedError,
    PathNotAllowedError,
    normalize_and_validate_path,
    resolve_nextcloud_host,
    validate_username,
)

ALLOWED_ROOT = "/var/www/nextcloud/data"


def test_allowed_path_accepted():
    assert normalize_and_validate_path(
        "/var/www/nextcloud/data/admin/files/test.pdf", ALLOWED_ROOT
    ) == "/var/www/nextcloud/data/admin/files/test.pdf"


def test_path_traversal_rejected():
    with pytest.raises(PathNotAllowedError):
        normalize_and_validate_path("/var/www/nextcloud/data/../../../etc/passwd", ALLOWED_ROOT)


def test_path_outside_root_rejected():
    with pytest.raises(PathNotAllowedError):
        normalize_and_validate_path("/etc/passwd", ALLOWED_ROOT)


def test_root_lookalike_prefix_rejected():
    # /var/www/nextcloud/data-evil must NOT be treated as underneath
    # /var/www/nextcloud/data just because it shares a string prefix.
    with pytest.raises(PathNotAllowedError):
        normalize_and_validate_path("/var/www/nextcloud/data-evil/test.txt", ALLOWED_ROOT)


def test_relative_path_rejected():
    with pytest.raises(PathNotAllowedError):
        normalize_and_validate_path("relative/path.txt", ALLOWED_ROOT)


def test_null_byte_rejected():
    with pytest.raises(PathNotAllowedError):
        normalize_and_validate_path("/var/www/nextcloud/data/test\x00.txt", ALLOWED_ROOT)


def test_path_valid_for_one_host_rejected_for_another():
    # A path under nextcloud01's allowed_root must NOT validate against a
    # different host's allowed_root - each Nextcloud server's files are
    # isolated from every other's.
    other_root = "/srv/nextcloud02/data"
    with pytest.raises(PathNotAllowedError):
        normalize_and_validate_path("/var/www/nextcloud/data/admin/files/test.pdf", other_root)


def test_allowed_host_resolves_with_ansible_host_and_allowed_root():
    host = resolve_nextcloud_host("nextcloud01")
    assert host.key == "nextcloud01"
    assert host.ansible_host == "192.168.150.87"
    assert host.allowed_root == "/var/www/nextcloud/data"


def test_unknown_host_rejected():
    with pytest.raises(HostNotAllowedError):
        resolve_nextcloud_host("evil-host")


def test_hostname_with_shell_metacharacters_rejected():
    with pytest.raises(HostNotAllowedError):
        resolve_nextcloud_host("nextcloud01; rm -rf /")


def test_username_valid():
    assert validate_username("admin") == "admin"


def test_username_invalid_chars_rejected():
    with pytest.raises(ValueError):
        validate_username("admin; rm -rf /")
