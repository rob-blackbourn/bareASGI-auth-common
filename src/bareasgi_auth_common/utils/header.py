"""
Header utilities
"""

from typing import List, Sequence, Optional

from baretypes import (
    Scope,
    Header
)
import bareutils.header as header


def _find_first_header(
        names: Sequence[bytes],
        headers: List[Header],
        default: Optional[bytes] = None
) -> Optional[bytes]:
    return next(
        (
            host
            for host in (
                header.find(name, headers)
                for name in names
            ) if host
        ),
        default
    )

def get_host(scope: Scope) -> bytes:
    """Get the host from the scope"""
    host = _find_first_header(
        (b'x-forwarded-host', b'host', b':authority'),
        scope['headers']
    )
    if host is None:
        raise KeyError()
    return host

def get_scheme(scope: Scope) -> bytes:
    """Get the scheme from the scope"""
    scheme = _find_first_header(
        (b'x-forwarded-proto', b':scheme'),
        scope['headers'],
        scope['scheme'].encode()
    )
    if scheme is None:
        raise KeyError()
    return scheme
