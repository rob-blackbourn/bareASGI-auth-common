"""JWT Authenticator
"""

import logging
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlencode

from asgi_typing import HTTPScope
from bareasgi import HttpRequest, HttpRequestCallback, HttpResponse
from bareclient import HttpClient
from bareutils import header, response_code, encode_set_cookie

from .token_manager import TokenManager
from .types import TokenStatus, UnauthorisedError, ForbiddenError
from .utils import get_scheme, get_host

LOGGER = logging.getLogger(__name__)


class JwtAuthenticator:
    """JTW authentication middleware"""

    def __init__(
            self,
            token_renewal_path: str,
            token_manager: TokenManager,
            authentication_path: Optional[str] = None,
            whitelist: Sequence[str] = ()
    ) -> None:
        """Initialise the JWT Authenticator

        Args:
            token_renewal_path (str): The path at which tokens can be renewed
            token_manager (TokenManager): The token manager instance
            authentication_path (Optional[str], optional): The authentication
                path. Defaults to None.
            whitelist (Sequence[str], optional): Routes for which
                authentication is not required. Defaults to None.
        """
        self.token_renewal_path = token_renewal_path
        self.token_manager = token_manager
        self.authentication_path = authentication_path
        self.whitelist = whitelist

    async def _renew_cookie(
            self,
            scope: HTTPScope,
            token: bytes
    ) -> Optional[Mapping[str, Any]]:

        scheme_str = get_scheme(scope).decode('ascii')
        host_bytes = get_host(scope)
        host_str = host_bytes.decode('ascii')

        referer_url = f'{scheme_str}://{host_str}{scope["path"]}'
        if scope['query_string']:
            referer_url += '?' + scope['query_string'].decode('utf-8')
        referer = header.find(
            b'referer',
            scope['headers'],
            referer_url.encode('ascii')
        )
        assert referer is not None

        headers: List[Tuple[bytes, bytes]] = [
            (b'host', host_bytes),
            (b'referer', referer),
            (b'content-length', b'0'),
            (b'connection', b'close')
        ]
        if token is not None:
            cookie = self.token_manager.cookie_name + b'=' + token
            headers.append((b'cookie', cookie))

        renewal_url = f'{scheme_str}://{host_str}{self.token_renewal_path}'

        LOGGER.debug(
            'Renewing cookie at %s with headers %s',
            renewal_url,
            headers
        )

        async with HttpClient(
                renewal_url,
                method='POST',
                headers=headers
        ) as response:

            if response.status == response_code.NO_CONTENT:
                LOGGER.debug('Cookie renewed')
                all_set_cookies = header.set_cookie(response.headers)
                auth_set_cookies = all_set_cookies.get(
                    self.token_manager.cookie_name
                )
                if auth_set_cookies is None:
                    raise RuntimeError('No cookie returned')
                return auth_set_cookies[0]
            elif response.status == response_code.UNAUTHORIZED:
                LOGGER.debug(
                    'Cookie not renewed - client requires authentication'
                )
                return None

        LOGGER.debug('Cookie not renewed - failed to authenticate')
        raise UnauthorisedError(scope, 'Failed to authenticate')

    def _make_authenticate_location(self, scope: HTTPScope) -> bytes:
        scheme: str = get_scheme(scope).decode('ascii')
        host = get_host(scope).decode('ascii')
        path: str = scope['path']
        if scope['query_string']:
            path += '?' + scope['query_string'].decode()
        url = f'{scheme}://{host}{path}'
        query_string = urlencode([('redirect', url)])
        location = f'{scheme}://{host}{self.authentication_path}?{query_string}'
        return location.encode()

    def _is_whitelisted(self, path: str) -> bool:
        for path_prefix in self.whitelist:
            if path.startswith(path_prefix):
                return True
        return False

    async def get_token_and_cookie(
            self,
            scope: HTTPScope,
            token_status: TokenStatus
    ) -> Tuple[bytes, Optional[bytes]]:
        token = self.token_manager.get_token_from_headers(scope['headers'])
        if token_status == TokenStatus.VALID:
            LOGGER.debug('Cookie still valid')
            assert token is not None
            return token, None

        if token_status == TokenStatus.EXPIRED:
            LOGGER.debug('Attempting to renew cookie')
            assert token is not None
            cookie_kwargs = await self._renew_cookie(scope, token)
            if cookie_kwargs is None:
                raise UnauthorisedError(scope, 'Unable to renew cookie')
            token = cookie_kwargs['value']
            assert token is not None
            cookie = encode_set_cookie(**cookie_kwargs)
            return token, cookie

        LOGGER.warning('The token was invalid')
        raise ForbiddenError(scope, 'Invalid cookie')

    async def __call__(
            self,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:

        LOGGER.debug('Jwt Authentication Request: %s', request.scope["path"])

        if self._is_whitelisted(request.scope['path']):
            LOGGER.debug(
                'The path is whitelisted: "%s"',
                request.scope['path']
            )
            return await handler(request)

        try:
            token = self.token_manager.get_token_from_headers(
                request.scope['headers']
            )
            token_status = self.token_manager.get_token_status(token)

            if token_status == TokenStatus.MISSING:
                if not self.authentication_path:
                    return HttpResponse(response_code.UNAUTHORIZED)

                # Redirect the client ot the authenticator.
                location = self._make_authenticate_location(request.scope)
                return HttpResponse(response_code.FOUND, [(b'location', location)])

            token, cookie = await self.get_token_and_cookie(request.scope, token_status)

            session_info: Dict[str, Any] = {}
            session_info.update(request.info)

            assert token is not None
            session_info['jwt_token'] = token
            session_info['jwt'] = self.token_manager.decode(token)

            new_request = HttpRequest(
                request.scope, session_info, request.context, request.matches, request.body)
            response = await handler(new_request)

            if cookie:
                if response.headers is None:
                    response.headers = []
                response.headers.append((b"set-cookie", cookie))

            return response

        except:  # pylint: disable=bare-except
            LOGGER.exception("JWT authentication failed")
            raise
