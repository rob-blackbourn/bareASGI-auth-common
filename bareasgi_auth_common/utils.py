"""Utilities"""

from typing import List, Sequence, Optional

from baretypes import Scope, Header


def _find_first_header(
    names: Sequence[bytes],
    headers: Sequence[Header],
    default: Optional[bytes] = None
) -> Optional[bytes]:
    for name in names:
        for key, value in headers:
            if key == name and value:
                return value
    return default


def get_host(scope: Scope) -> bytes:
    host = _find_first_header((b'x-forwarded-host', b'host'), scope['headers'])
    assert host is not None
    return host


def get_scheme(scope: Scope) -> bytes:
    scheme = _find_first_header((b'x-forwarded-proto',), scope['headers'])
    if scheme is None:
        scheme = scope['scheme'].encode()
    return scheme
