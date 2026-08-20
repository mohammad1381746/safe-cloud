from panel.auth import hash_password, verify_password


def test_hash_roundtrip_verifies():
    encoded = hash_password("correct-horse-battery-staple", iterations=1000)
    assert verify_password("correct-horse-battery-staple", encoded)


def test_wrong_password_rejected():
    encoded = hash_password("correct-horse-battery-staple", iterations=1000)
    assert not verify_password("wrong-password", encoded)


def test_malformed_hash_rejected_not_raised():
    assert not verify_password("anything", "not-a-valid-hash")
    assert not verify_password("anything", "pbkdf2_sha256$notanumber$salt$hash")


def test_wrong_algorithm_prefix_rejected():
    assert not verify_password("anything", "md5$1$salt$hash")


def test_different_iterations_still_verify_correctly():
    encoded = hash_password("another-password", iterations=5000)
    assert "$5000$" in encoded
    assert verify_password("another-password", encoded)
