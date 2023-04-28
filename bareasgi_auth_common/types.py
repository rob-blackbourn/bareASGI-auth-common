"""Types"""

from enum import Enum, auto
from typing import List, Optional, Tuple

from bareasgi import HttpRequest, WebSocketRequest
import bareutils.response_code as response_code

from .utils import get_host, get_scheme


class TokenStatus(Enum):
    """The token status"""
    VALID = auto()
    EXPIRED = auto()
    INVALID = auto()
    MISSING = auto()


class BareASGIHttpError(Exception):

    def __init__(
            self,
            request: HttpRequest,
            status: int,
            headers: Optional[List[Tuple[bytes, bytes]]],
            message: Optional[str]
    ) -> None:
        super().__init__(message)
        host = get_host(request.scope['headers']).decode('ascii')
        scheme = get_scheme(request.scope['headers'], request.scope['scheme'])
        self.url = f'{scheme}://{host}{request.scope["path"]}'
        self.status = status
        self.headers = headers
        self.message = message


class ForbiddenHttpError(BareASGIHttpError):

    def __init__(self, request: HttpRequest, message: str) -> None:
        super().__init__(
            request,
            response_code.FORBIDDEN,
            [(b'content_type', b'text/plain')],
            message
        )


class UnauthorizedHttpError(BareASGIHttpError):

    def __init__(self, request: HttpRequest, message: str) -> None:
        super().__init__(
            request,
            response_code.UNAUTHORIZED,
            [(b'content_type', b'text/plain')],
            message
        )


class BareASGIWebSocketError(Exception):

    def __init__(
            self,
            request: WebSocketRequest,
            status: int,
            headers: Optional[List[Tuple[bytes, bytes]]],
            message: Optional[str]
    ) -> None:
        super().__init__(message)
        host = get_host(request.scope['headers']).decode('ascii')
        scheme = get_scheme(request.scope['headers'], request.scope['scheme'])
        self.url = f'{scheme}://{host}{request.scope["path"]}'
        self.status = status
        self.headers = headers
        self.message = message


class ForbiddenWebSocketError(BareASGIWebSocketError):

    def __init__(self, request: WebSocketRequest, message: str) -> None:
        super().__init__(
            request,
            response_code.FORBIDDEN,
            [(b'content_type', b'text/plain')],
            message
        )


class UnauthorizedWebSocketError(BareASGIWebSocketError):

    def __init__(self, request: WebSocketRequest, message: str) -> None:
        super().__init__(
            request,
            response_code.UNAUTHORIZED,
            [(b'content_type', b'text/plain')],
            message
        )
