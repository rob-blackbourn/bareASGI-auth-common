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


def get_host(request: HttpRequest) -> bytes:
    host = _find_first_header(
        (b'x-forwarded-host', b'host'),
        request.scope['headers']
    )
    assert host is not None
    return host


def get_http_scheme(request: HttpRequest) -> str:
    scheme = _find_first_header(
        (b'x-forwarded-proto',),
        request.scope['headers']
    )
    if scheme is not None:
        return scheme.decode('ascii')

    return request.scope['scheme']


def get_ws_scheme(request: WebSocketRequest) -> str:
    scheme = _find_first_header(
        (b'x-forwarded-proto',),
        request.scope['headers']
    )
    if scheme is not None:
        return scheme.decode('ascii')

    return request.scope['scheme']
