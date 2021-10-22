"""Types"""

from enum import Enum, auto
from typing import List, Optional, Tuple

from bareasgi import HttpRequest
import bareutils.response_code as response_code

from .utils import get_host, get_scheme


class TokenStatus(Enum):
    VALID = auto()
    EXPIRED = auto()
    INVALID = auto()
    MISSING = auto()


class BareASGIError(Exception):

    def __init__(
            self,
            request: HttpRequest,
            status: int,
            headers: Optional[List[Tuple[bytes, bytes]]],
            message: Optional[str]
    ) -> None:
        super().__init__(message)
        host = get_host(request).decode('ascii')
        scheme = get_scheme(request)
        self.url = f'{scheme}://{host}{request.scope["path"]}'
        self.status = status
        self.headers = headers
        self.message = message


class ForbiddenError(BareASGIError):

    def __init__(self, request: HttpRequest, message: str) -> None:
        super().__init__(
            request,
            response_code.FORBIDDEN,
            [(b'content_type', b'text/plain')],
            message
        )


class UnauthorizedError(BareASGIError):

    def __init__(self, request: HttpRequest, message: str) -> None:
        super().__init__(
            request,
            response_code.UNAUTHORIZED,
            [(b'content_type', b'text/plain')],
            message
        )
