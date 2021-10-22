"""JWT Authenticator
"""

from datetime import timedelta
import logging
from typing import Any, List, Mapping, Optional, Sequence, Tuple, cast
from urllib.parse import urlencode

from bareasgi import HttpRequest, HttpRequestCallback, HttpResponse, text_writer
from bareclient import HttpClient
from bareutils import header, response_code, encode_set_cookie

from .token_manager import TokenManager
from .types import TokenStatus, BareASGIError, UnauthorizedError, ForbiddenError
from .utils import get_scheme, get_host

LOGGER = logging.getLogger(__name__)


class JwtAuthenticator(TokenManager):
    """JTW authentication middleware"""

    def __init__(
            self,
            secret: str,
            lease_expiry: timedelta,
            issuer: str,
            cookie_name: str,
            domain: str,
            path: str,
            session_expiry: timedelta,
            token_renewal_path: str,
            authentication_path: Optional[str] = None,
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
            token_renewal_path (str): The path at which tokens can be renewed
            authentication_path (Optional[str], optional): The authentication
                path. Defaults to None.
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
        self.token_renewal_path = token_renewal_path
        self.authentication_path = authentication_path
        self.whitelist = whitelist

    async def _renew_cookie(
            self,
            request: HttpRequest,
            token: bytes
    ) -> Optional[Mapping[str, Any]]:

        host = get_host(request)
        base_url = f'{get_scheme(request)}://{host.decode("ascii")}'

        referer_url = base_url + request.scope["path"]
        if request.scope['query_string']:
            referer_url += '?' + request.scope['query_string'].decode('utf-8')
        referer = header.find(
            b'referer',
            request.scope['headers'],
            referer_url.encode('ascii')
        )
        assert referer is not None

        headers: List[Tuple[bytes, bytes]] = [
            (b'host', host),
            (b'referer', referer),
            (b'content-length', b'0'),
            (b'connection', b'close')
        ]
        if token is not None:
            cookie = self.cookie_name + b'=' + token
            headers.append((b'cookie', cookie))

        renewal_url = base_url + self.token_renewal_path

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
                    self.cookie_name
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
        raise UnauthorizedError(request, 'Failed to authenticate')

    def _make_authenticate_location(self, request: HttpRequest) -> bytes:
        if self.authentication_path is None:
            LOGGER.debug("No path for authentication redirect")
            raise UnauthorizedError(request, "Cannot authorize")

        path = request.scope['path']
        if request.scope['query_string']:
            path += '?' + request.scope['query_string'].decode()

        scheme = get_scheme(request)
        host = get_host(request).decode('ascii')
        base_url = f'{scheme}://{host}'

        redirect_url = base_url+path
        query_string = urlencode([('redirect', redirect_url)])
        location = base_url + self.authentication_path + '?' + query_string
        return location.encode()

    def _is_whitelisted(self, path: str) -> bool:
        for path_prefix in self.whitelist:
            if path.startswith(path_prefix):
                return True
        return False

    async def get_token_and_cookie(
            self,
            request: HttpRequest,
            token_status: TokenStatus
    ) -> Tuple[bytes, Optional[bytes]]:
        token = self.get_token_from_headers(request)
        if token_status == TokenStatus.VALID:
            LOGGER.debug('Cookie still valid')
            assert token is not None
            return token, None

        if token_status == TokenStatus.EXPIRED and token is not None:
            LOGGER.debug('Attempting to renew cookie')

            cookie_kwargs = await self._renew_cookie(request, token)
            if cookie_kwargs is None:
                LOGGER.debug("Unable to renew cookie")
                raise UnauthorizedError(request, 'Unable to renew cookie')

            token = cast(bytes, cookie_kwargs['value'])
            cookie = encode_set_cookie(**cookie_kwargs)
            return token, cookie

        LOGGER.warning('The token was invalid')
        raise ForbiddenError(request, 'Invalid cookie')

    async def _handle_authentication(
            self,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:
        LOGGER.debug("Handling authentication request")
        try:
            token = self.get_token_from_headers(request)
            token_status = self.get_token_status(token)

            if token_status == TokenStatus.MISSING:
                LOGGER.debug("No token - redirecting for authentication")
                headers = [
                    (b'location', self._make_authenticate_location(request))
                ]
                return HttpResponse(response_code.FOUND, headers)

            token, cookie = await self.get_token_and_cookie(request, token_status)

            request.context['jwt'] = self.decode(token)

            response = await handler(request)

            if cookie:
                if response.headers is None:
                    response.headers = []
                response.headers.append((b"set-cookie", cookie))

            return response

        except BareASGIError as error:
            return HttpResponse(
                error.status,
                error.headers,
                text_writer(error.message) if error.message else None
            )
        except:  # pylint: disable=bare-except
            LOGGER.exception("JWT authentication failed")
            raise

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
        else:
            return await self._handle_authentication(request, handler)
