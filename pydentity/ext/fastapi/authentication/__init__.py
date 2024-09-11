from fastapi import FastAPI
from starlette.responses import PlainTextResponse
from starlette.types import ExceptionHandler

from pydentity.authentication import AuthenticationError, AuthenticationSchemeProvider
from pydentity.ext.fastapi.authentication.middlewares import AuthenticationMiddleware


def use_authentication(app: FastAPI, on_error: ExceptionHandler | None = None):
    app.add_middleware(AuthenticationMiddleware, schemes=AuthenticationSchemeProvider())

    if on_error:
        app.add_exception_handler(AuthenticationError, on_error)
    else:
        app.add_exception_handler(
            AuthenticationError,
            lambda req, exc: PlainTextResponse('Unauthorized', status_code=401)
        )
