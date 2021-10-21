"""Types"""

from enum import Enum, auto
from typing import List, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import parse_qs

from asgi_typing import HTTPScope
import bareutils.response_code as response_code

from .utils import get_host, get_scheme


class TokenStatus(Enum):
    VALID = auto()
    EXPIRED = auto()
    INVALID = auto()
    MISSING = auto()


class BareASGIError(HTTPError):

    def __init__(
            self,
            scope: HTTPScope,
            code: int,
            hdrs: Optional[List[Tuple[bytes, bytes]]],
            msg: Optional[str]
    ) -> None:
        host = get_host(scope).decode('ascii')
        scheme = get_scheme(scope).decode('ascii')
        url = f'{scheme}://{host}{scope["path"]}'

        super().__init__(
            url,
            code,
            msg,  # type: ignore
            hdrs,  # type: ignore
            None
        )


class ForbiddenError(BareASGIError):

    def __init__(self, scope: HTTPScope, msg: str) -> None:
        super().__init__(
            scope,
            response_code.FORBIDDEN,
            [(b'content_type', b'text/plain')],
            msg
        )


class UnauthorisedError(BareASGIError):

    def __init__(self, scope: HTTPScope, msg: str) -> None:
        super().__init__(
            scope,
            response_code.UNAUTHORIZED,
            [(b'content_type', b'text/plain')],
            msg
        )
