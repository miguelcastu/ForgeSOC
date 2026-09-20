from datetime import UTC, datetime, timedelta

import pytest

from forgesoc.api.security import (
    InvalidTokenError,
    UserIdentity,
    create_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_password_hash_is_salted_and_verifiable() -> None:
    first = hash_password("a-secure-local-password")
    second = hash_password("a-secure-local-password")

    assert first != second
    assert verify_password("a-secure-local-password", first)
    assert not verify_password("wrong-password", first)


def test_signed_session_rejects_expiration_and_tampering() -> None:
    now = datetime(2026, 9, 20, tzinfo=UTC)
    identity = UserIdentity("user-id", "analyst", "analyst")
    token = create_token(identity, now)

    assert decode_token(token, now + timedelta(hours=1)) == identity
    with pytest.raises(InvalidTokenError):
        decode_token(token + "broken", now)
    with pytest.raises(InvalidTokenError):
        decode_token(token, now + timedelta(hours=9))
