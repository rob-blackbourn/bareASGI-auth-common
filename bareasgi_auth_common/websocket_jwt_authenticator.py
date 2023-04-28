"""JWT Authenticator
"""

from datetime import timedelta
import logging
from typing import Sequence

from bareasgi import WebSocketRequest, WebSocketRequestCallback

from .token_manager import TokenManager
from .types import (
    TokenStatus,
    UnauthorizedWebSocketError,
    ForbiddenWebSocketError
)

LOGGER = logging.getLogger(__name__)


class WebSocketJwtAuthenticator(TokenManager):
    """WebSocket JTW authentication middleware"""

    def __init__(
            self,
            secret: str,
            lease_expiry: timedelta,
            issuer: str,
            cookie_name: str,
            domain: str,
            path: str,
            session_expiry: timedelta,
            whitelist: Sequence[str] = ()
    ) -> None:
        """Initialise the JWT Authenticator

        Args:
            secret (str): The secret used for signing the JWT token.
            lease_expiry (timedelta): The token expiry
            issuer (str): The cookie issuer
            cookie_name (str): The cookie name
            domain (str): The cookie domain
            path (str): The cookie path
            session_expiry (timedelta): The maximum age of the cookie.
            whitelist (Sequence[str], optional): Routes for which
                authentication is not required. Defaults to None.
        """
        super().__init__(
            secret,
            lease_expiry,
            issuer,
            cookie_name,
            domain,
            path,
            session_expiry
        )
        self.whitelist = whitelist

    def _is_whitelisted(self, path: str) -> bool:
        for path_prefix in self.whitelist:
            if path.startswith(path_prefix):
                return True
        return False

    async def get_token(
            self,
            request: WebSocketRequest,
            token_status: TokenStatus
    ) -> bytes:
        """Get the token

        Args:
            request (WebSocketRequest): The request.
            token_status (TokenStatus): The token status.

        Raises:
            UnauthorizedWebSocketError: For unauthorized requests.
            ForbiddenWebSocketError: For forbidden requests.

        Returns:
            bytes: The token.
        """
        token = self.get_token_from_headers(request.scope['headers'])
        if token_status == TokenStatus.VALID:
            LOGGER.debug('Cookie still valid')
            assert token is not None
            return token

        if token_status == TokenStatus.EXPIRED and token is not None:
            raise UnauthorizedWebSocketError(request, "Expired cookie")

        LOGGER.warning('The token was invalid')
        raise ForbiddenWebSocketError(request, 'Invalid cookie')

    async def _handle_authentication(
            self,
            request: WebSocketRequest,
            handler: WebSocketRequestCallback
    ) -> None:
        LOGGER.debug("Handling authentication request")
        try:
            token = self.get_token_from_headers(request.scope['headers'])
            token_status = self.get_token_status(token)

            if token_status == TokenStatus.MISSING:
                LOGGER.debug("No token - closing websocket")
                await request.web_socket.close()
                return

            token = await self.get_token(request, token_status)

            request.context['jwt'] = self.decode(token)

            await handler(request)

        except:  # pylint: disable=bare-except
            LOGGER.exception("JWT authentication failed")
            raise

    async def _handle_whitelisted(
            self,
            request: WebSocketRequest,
            handler: WebSocketRequestCallback
    ) -> None:
        LOGGER.debug(
            'The path is whitelisted: "%s"',
            request.scope['path']
        )
        await handler(request)

    async def __call__(
            self,
            request: WebSocketRequest,
            handler: WebSocketRequestCallback
    ) -> None:

        LOGGER.debug('Jwt Authentication Request: %s', request.scope["path"])

        if self._is_whitelisted(request.scope['path']):
            await self._handle_whitelisted(request, handler)
        else:
            await self._handle_authentication(request, handler)
