"""Helper functions"""

from datetime import timedelta
from typing import Optional, Sequence

from bareasgi import Application

from .http_jwt_authenticator import HttpJwtAuthenticator
from .websocket_jwt_authenticator import WebSocketJwtAuthenticator


def add_jwt_auth_middleware(
        app: Application,
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
) -> Application:
    """Add JWT authentication middleware.

    Args:
        app (Application): The ASGI application.
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

    Returns:
        Application: The ASGI application.
    """
    http_jwt_authenticator = HttpJwtAuthenticator(
        secret,
        lease_expiry,
        issuer,
        cookie_name,
        domain,
        path,
        session_expiry,
        token_renewal_path,
        authentication_path,
        whitelist
    )
    app.middlewares.append(http_jwt_authenticator)

    ws_jwt_authenticator = WebSocketJwtAuthenticator(
        secret,
        lease_expiry,
        issuer,
        cookie_name,
        domain,
        path,
        session_expiry,
        whitelist
    )
    app.ws_middlewares.append(ws_jwt_authenticator)

    return app
