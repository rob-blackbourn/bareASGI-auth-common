"""Tests"""

from bareasgi_auth_common.utils.header import _find_first_header


def test_find_first_header():
    """Test find first header"""
    host = b'www.example.com'
    names = (b'x-forwarded-host', b'host', b':authority')
    for name in names:
        headers = [
            (name, host)
        ]
        found = _find_first_header(names, headers)
        assert found == host
