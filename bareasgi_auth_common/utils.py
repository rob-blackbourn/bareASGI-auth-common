"""Utilities"""

from typing import Iterable, Optional, Tuple

from asgi_typing import HTTPScope


def _find_first_header(
    names: Iterable[bytes],
    headers: Iterable[Tuple[bytes, bytes]],
    default: Optional[bytes] = None
) -> Optional[bytes]:
    for name in names:
        for key, value in headers:
            if key == name and value:
                return value
    return default


def get_host(scope: HTTPScope) -> bytes:
    host = _find_first_header((b'x-forwarded-host', b'host'), scope['headers'])
    assert host is not None
    return host


def get_scheme(scope: HTTPScope) -> bytes:
    scheme = _find_first_header((b'x-forwarded-proto',), scope['headers'])
    if scheme is None:
        scheme = scope['scheme'].encode()
    return scheme
