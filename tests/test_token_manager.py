"""Tests for the token manager"""

from datetime import datetime, timedelta
from bareasgi_auth_common import TokenManager


def test_smoke():
    token_manager = TokenManager(
        "a secret of more than 15 characters",
        timedelta(hours=1),
        "example.com",
        "bareasgi-auth",
        "example.com",
        "/",
        timedelta(days=1)
    )

    user = 'jane.doe@example.com'
    now = datetime(2021, 1, 1, 12, 15, 30)
    token = token_manager.encode(user, now, now, None)
    roundtrip = token_manager.decode(token)
    assert roundtrip['sub'] == user
    assert roundtrip['iat'] == now
    assert roundtrip['exp'] == now + token_manager.lease_expiry
    assert roundtrip['iss'] == token_manager.issuer
