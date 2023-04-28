"""Utilities"""

from typing import Iterable, Optional, Tuple

from bareasgi import HttpRequest, WebSocketRequest


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


def get_host(headers: Iterable[Tuple[bytes, bytes]]) -> bytes:
    host = _find_first_header(
        (b'x-forwarded-host', b'host'),
        headers
    )
    assert host is not None
    return host


def get_scheme(headers: Iterable[Tuple[bytes, bytes]], scheme: str) -> str:
    forwarded_scheme = _find_first_header(
        (b'x-forwarded-proto',),
        headers
    )
    if forwarded_scheme is not None:
        return forwarded_scheme.decode('ascii')

    return scheme
