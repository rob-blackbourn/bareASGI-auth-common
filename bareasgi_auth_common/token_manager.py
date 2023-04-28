"""Token Manager"""

from datetime import datetime, timedelta
import logging
from typing import Any, Iterable, Mapping, Optional, Tuple

from bareutils import encode_set_cookie, header
import jwt

from .types import TokenStatus

LOGGER = logging.getLogger(__name__)


class TokenManager:
    """Token Manager"""

    def __init__(
            self,
            secret: str,
            lease_expiry: timedelta,
            issuer: str,
            cookie_name: str,
            domain: str,
            path: str,
            session_expiry: timedelta
    ) -> None:
        """A token manager

        Args:
            secret (str): The secret used for signing the JWT token.
            lease_expiry (timedelta): The token expiry
            issuer (str): The cookie issuer
            cookie_name (str): The cookie name
            domain (str): The cookie domain
            path (str): The cookie path
            session_expiry (timedelta): The maximum age of the cookie.
        """
        self.secret = secret
        self.lease_expiry = lease_expiry
        self.issuer = issuer
        self.cookie_name = cookie_name.encode()
        self.domain = domain.encode()
        self.path = path.encode()
        self.session_expiry = session_expiry

    def encode(
            self,
            user: str,
            now: datetime,
            issued_at: datetime,
            lease_expiry: Optional[timedelta],
            **kwargs
    ) -> bytes:
        """Encode the JSON web token.

        Args:
            user (str): The user identification
            now (datetime): The current time
            issued_at (datetime): When the token was originally issued
            lease_expiry (Optional[timedelta]): An optional expiry.

        Returns:
            str: The information encoded as a JSON web token.
        """
        if lease_expiry is None:
            lease_expiry = self.lease_expiry
        expiry = now + lease_expiry
        LOGGER.debug("Token will expire at %s", expiry)
        payload = {
            'iss': self.issuer,
            'sub': user,
            'exp': expiry,
            'iat': issued_at
        }
        payload.update(kwargs)
        token = jwt.encode(payload, key=self.secret, algorithm="HS256")
        return token.encode('ascii')

    def decode(self, token: bytes) -> Mapping[str, Any]:
        """Decode the JSON web token

        Args:
            token (bytes): The token

        Returns:
            Mapping[str, Any]: A mapping of the payload.
        """
        payload = jwt.decode(
            token.decode('ascii'),
            key=self.secret,
            options={'verify_exp': False},
            algorithms=["HS256"]
        )
        payload['exp'] = datetime.utcfromtimestamp(payload['exp'])
        payload['iat'] = datetime.utcfromtimestamp(payload['iat'])
        return payload

    def get_token_from_headers(
            self,
            headers: Iterable[Tuple[bytes, bytes]]
    ) -> Optional[bytes]:
        """Gets the token from the headers if present.

        Args:
            headers (Iterable[Tuple[bytes, bytes]]): The headers

        Returns:
            Optional[bytes]: The token or None if not found.
        """
        tokens = header.cookie(headers).get(self.cookie_name)
        if tokens is None or not tokens:
            return None
        if len(tokens) > 1:
            LOGGER.warning('Multiple tokens in header - using first')
        token = tokens[0]
        return token

    def get_jwt_payload_from_headers(
            self,
            headers: Iterable[Tuple[bytes, bytes]]
    ) -> Optional[Mapping[str, Any]]:
        """Gets the payload of the JSON web token from the headers

        Args:
            headers (Iterable[Tuple[bytes, bytes]]): The headers

        Returns:
            Optional[Mapping[str, Any]]: The payload of the JSON web token if
                present; otherwise None.
        """
        token = self.get_token_from_headers(headers)
        payload = self.decode(token) if token is not None else None
        return payload

    def generate_cookie(self, user: str) -> bytes:
        """Generate a new cookie

        Args:
            user (str): The user identification

        Returns:
            bytes: The cookie
        """
        now = datetime.utcnow()
        token = self.encode(user, now, now, None)
        return self.make_cookie(token)

    def make_cookie(self, token: bytes) -> bytes:
        """Make a cookie from a token

        Args:
            token (bytes): The token

        Returns:
            bytes: The cookie
        """
        cookie = encode_set_cookie(
            self.cookie_name,
            token,
            max_age=self.session_expiry,
            domain=self.domain,
            path=self.path,
            http_only=True
        )
        return cookie

    def get_token_status(self, token: Optional[bytes]) -> TokenStatus:
        """Get the status of the token.

        Args:
            token (Optional[bytes]): The token.

        Returns:
            TokenStatus: The status of the token.
        """
        try:
            if token is None:
                LOGGER.debug('Token missing')
                return TokenStatus.MISSING

            now = datetime.utcnow()

            payload = self.decode(token)
            expiry = payload['exp']
            if expiry < now:
                LOGGER.debug('Token expired')
                return TokenStatus.EXPIRED

            LOGGER.debug('Token valid for %s', expiry - now)
            return TokenStatus.VALID
        except:  # pylint: disable=bare-except
            LOGGER.exception('Invalid token')
            return TokenStatus.INVALID
