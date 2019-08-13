"""
JWT Authenticator
"""

from datetime import datetime
import logging
import ssl
from typing import List, Optional
from urllib.parse import urlencode

from baretypes import (
    Scope,
    Header,
    Info,
    RouteMatches,
    Content,
    HttpResponse,
    HttpRequestCallback
)
from bareutils import response_code, encode_set_cookie
import bareutils.header as header
from bareclient import HttpClient
from .token_manager import TokenManager

# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


class JwtAuthenticator:
    """JTW authentication middleware"""

    def __init__(
            self,
            token_renewal_path: str,
            token_manager: TokenManager,
            authentication_path: Optional[str] = None
    ) -> None:
        """Initialise the JWT Authenticator

        :param token_renewal_path: The path at which tokens can be renewed
        :type token_renewal_path: str
        :param token_manager: The token manager instance
        :type token_manager: TokenManager
        """
        self.token_renewal_path = token_renewal_path
        self.token_manager = token_manager
        self.authentication_path = authentication_path


    async def _renew_cookie(self, scope: Scope, token: bytes) -> Optional[bytes]:
        scope_server_host, scope_server_port = scope['server']

        scheme = header.find(
            b'x-forwarded-proto',
            scope['headers'],
            scope['scheme'].encode()
        ).decode()
        host = header.find(
            b'x-forwarded-host',
            scope['headers'],
            scope_server_host.encode()
        ).decode()
        port = int(
            header.find(
                b'x-forwarded-port',
                scope['headers'],
                str(scope_server_port).encode()
            ).decode()
        )

        renewal_url = f'{scheme}://{host}{self.token_renewal_path}'
        url = f'{scheme}://{host}:{port}{scope["path"]}'
        referer = header.find(b'referer', scope['headers'], url.encode('ascii'))

        headers: List[Header] = [
            (b'host', host.encode()),
            (b'referer', referer),
            (b'content-length', b'0'),
            (b'connection', b'close')
        ]
        if token is not None:
            cookie = self.token_manager.cookie_name + b'=' + token
            headers.append((b'cookie', cookie))

        ssl_context = ssl.SSLContext() if scheme == 'https' else None

        logger.debug('Renewing cookie at %s with headers %s', renewal_url, headers)
        async with HttpClient(
                renewal_url,
                method='POST',
                headers=headers,
                ssl=ssl_context
        ) as (response, body):

            if response.status_code == response_code.NO_CONTENT:
                logger.debug('Cookie renewed')
                all_set_cookies = header.set_cookie(response.headers)
                auth_set_cookies = all_set_cookies.get(self.token_manager.cookie_name)
                if auth_set_cookies is None:
                    raise RuntimeError('No cookie returned')
                kwargs = auth_set_cookies[0]
                set_cookie = encode_set_cookie(**kwargs)
                return set_cookie
            elif response.status_code == response_code.UNAUTHORIZED:
                logger.debug('Cookie not renewed - client requires authentication')
                return None
            else:
                logger.debug('Cookie not renewed - failed to authenticate')
                raise Exception()

    def _make_authenticate_location(self, scope: Scope) -> bytes:
        host_header = b':authority' if scope['http_version'] == '2' else b'host'
        scheme = scope['scheme']
        host = header.find(host_header, scope['headers']).decode()
        path = scope['path']
        if scope['query_string']:
            path += '?' + scope['query_string'].decode()
        url = f'{scheme}://{host}{path}'
        query_string = urlencode([('redirect', url)])
        location = f'{scheme}://{host}{self.authentication_path}?{query_string}'
        return location

    async def __call__(
            self,
            scope: Scope,
            info: Info,
            matches: RouteMatches,
            content: Content,
            handler: HttpRequestCallback
    ) -> HttpResponse:

        logger.debug('Jwt Authentication Request: %s', scope["path"])

        try:
            token = self.token_manager.get_token_from_headers(scope['headers'])
            if token is None:
                if self.authentication_path:
                    location = self._make_authenticate_location(scope)
                    return response_code.FOUND, [(b'location', location.encode())]
                return response_code.UNAUTHORIZED

            now = datetime.utcnow()

            payload = self.token_manager.decode(token)
            if payload['exp'] > now:
                logger.debug('Cookie still valid')
                cookie = None
            else:
                logger.debug('Renewing cookie')
                cookie = await self._renew_cookie(scope, token)
                if cookie is None:
                    return response_code.UNAUTHORIZED

            if info is None:
                info = dict()
            info['jwt'] = payload

            status, headers, body, pushes = await handler(scope, info, matches, content)

            if cookie:
                if headers is None:
                    headers = []
                headers.append((b"set-cookie", cookie))

            return status, headers, body, pushes

        except: # pylint: disable=bare-except
            logger.exception("JWT authentication failed")
            return response_code.INTERNAL_SERVER_ERROR
