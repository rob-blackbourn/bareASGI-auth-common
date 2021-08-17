"""Token Manager"""

from datetime import datetime, timedelta
import logging
from typing import Mapping, Any, List, Optional, Sequence

from baretypes import Header
from bareutils import encode_set_cookie
import bareutils.header as header
import jwt

# pylint: disable=invalid-name
LOGGER = logging.getLogger(__name__)


class TokenManager:
    """Token Manager"""

    def __init__(
            self,
            secret: str,
            token_expiry: timedelta,
            issuer: str,
            cookie_name: str,
            domain: str,
            path: str,
            max_age: timedelta
    ) -> None:
        """A token manager

        Args:
            secret (str): The secret used for signing the JWT token.
            token_expiry (timedelta): The token expiry
            issuer (str): The cookie issuer
            cookie_name (str): The cookie name
            domain (str): The cookie domain
            path (str): The cookie path
            max_age (timedelta): The maximum age of the cookie.
        """
        self.secret = secret
        self.token_expiry = token_expiry
        self.issuer = issuer
        self.cookie_name = cookie_name.encode()
        self.domain = domain.encode()
        self.path = path.encode()
        self.max_age = max_age

    def encode(
            self,
            email: str,
            now: datetime,
            issued_at: datetime,
            token_expiry: Optional[timedelta],
            **kwargs
    ) -> bytes:
        """Encode the JSON web token.

        Args:
            email (str): The user identification
            now (datetime): The current time
            issued_at (datetime): When the token was originally issued
            token_expiry (Optional[timedelta]): An optional expiry.

        Returns:
            bytes: The information encoded as a JSON web token.
        """
        if token_expiry is None:
            token_expiry = self.token_expiry
        expiry = now + token_expiry
        LOGGER.debug("Token will expire at %s", expiry)
        payload = {
            'iss': self.issuer,
            'sub': email,
            'exp': expiry,
            'iat': issued_at
        }
        payload.update(kwargs)
        return jwt.encode(payload, key=self.secret)

    def decode(self, token: bytes) -> Mapping[str, Any]:
        """Decode the JSON web token

        Args:
            token (bytes): The token

        Returns:
            Mapping[str, Any]: A mapping of the payload.
        """
        payload = jwt.decode(
            token,
            key=self.secret,
            options={'verify_exp': False}
        )
        payload['exp'] = datetime.utcfromtimestamp(payload['exp'])
        payload['iat'] = datetime.utcfromtimestamp(payload['iat'])
        return payload

    def get_token_from_headers(self, headers: List[Header]) -> Optional[bytes]:
        """Gets the token from the headers if present.

        Args:
            headers (Sequence[Header]): The headers

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
            headers: List[Header]
    ) -> Optional[Mapping[str, Any]]:
        """Gets the payload of the JSON web token from the headers

        Args:
            headers (List[Header]): The headers

        Returns:
            Optional[Mapping[str, Any]]: The payload of the JSON web token if
                present; otherwise None.
        """
        token = self.get_token_from_headers(headers)
        payload = self.decode(token) if token is not None else None
        return payload

    def generate_cookie(self, email: str) -> bytes:
        """Generate a new cookie

        Args:
            email (str): The user identification

        Returns:
            bytes: The cookie
        """
        now = datetime.utcnow()
        token = self.encode(email, now, now, None)
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
            max_age=self.max_age,
            domain=self.domain,
            path=self.path,
            http_only=True
        )
        return cookie
