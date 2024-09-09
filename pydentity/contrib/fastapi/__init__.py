import inspect
from collections.abc import Iterable
from typing import get_origin, Annotated, get_args, Union, Generic

from fastapi import Depends, FastAPI
from starlette.responses import PlainTextResponse
from starlette.types import ExceptionHandler

from pydentity import (
    Argon2PasswordHasher,
    DefaultUserConfirmation,
    IdentityErrorDescriber,
    IdentityOptions,
    PasswordValidator,
    RoleManager,
    RoleValidator,
    SignInManager,
    UpperLookupNormalizer,
    UserClaimsPrincipalFactory,
    UserManager,
    UserValidator, IdentityConstants,
)
from pydentity.abc import (
    ILogger,
    ILookupNormalizer,
    IPasswordHasher,
    IPasswordValidator,
    IRoleValidator,
    IUserClaimsPrincipalFactory,
    IUserConfirmation,
    IUserValidator,
)
from pydentity.abc.stores import IUserStore, IRoleStore
from pydentity.authentication import AuthenticationOptions, AuthenticationSchemeProvider, AuthenticationError
from pydentity.authentication.abc import IAuthenticationSchemeProvider
from pydentity.authorization import AuthorizationOptions, AuthorizationPolicyProvider, AuthorizationError
from pydentity.contrib.fastapi.authentication import AuthenticationBuilder, AuthenticationMiddleware
from pydentity.contrib.fastapi.authorization import AuthorizationBuilder
from pydentity.contrib.fastapi.dependencies import (
    Dependencies,
    PasswordValidatorCollection,
    RoleValidatorCollection,
    singleton,
    UserValidatorCollection,
)
from pydentity.contrib.fastapi.dependencies.http import HttpContext as FastAPIHttpContext, HttpContextAccessor
from pydentity.contrib.fastapi.identity.builder import IdentityBuilder
from pydentity.http.context import HttpContext, IHttpContextAccessor
from pydentity.types import TUser, TRole


class PydentityBuilder:
    def __init__(self):
        self._dependencies = Dependencies()

    @property
    def dependencies(self) -> Dependencies:
        return self._dependencies

    def add_authentication(self) -> AuthenticationBuilder:
        self._dependencies.update({
            IAuthenticationSchemeProvider: AuthenticationSchemeProvider,
            HttpContext: FastAPIHttpContext,
            IHttpContextAccessor: HttpContextAccessor,
        })
        options = AuthenticationOptions()
        options.default_authentication_scheme = IdentityConstants.ApplicationScheme
        options.default_sign_in_scheme = IdentityConstants.ExternalScheme
        AuthenticationSchemeProvider.options = options
        return AuthenticationBuilder(options)

    def add_authorization(self) -> AuthorizationBuilder:
        options = AuthorizationOptions()
        AuthorizationPolicyProvider.options = options
        return AuthorizationBuilder(options)

    def add_identity(
            self,
            user_store: type[IUserStore],
            role_store: type[IRoleStore],
    ) -> IdentityBuilder:
        self.add_authentication().add_identity_cookies()
        self._dependencies.update({
            ILogger["UserManager"]: None,
            ILogger["RoleManager"]: None,
            ILogger["SignInManager"]: None,
            IdentityOptions: singleton(IdentityOptions),
            IUserStore[TUser]: user_store,
            IRoleStore[TRole]: role_store,
            IdentityErrorDescriber: IdentityErrorDescriber,
            IPasswordHasher[TUser]: Argon2PasswordHasher,
            Iterable[IPasswordValidator[TUser]]: PasswordValidatorCollection,
            Iterable[IUserValidator[TUser]]: UserValidatorCollection,
            Iterable[IRoleValidator[TRole]]: RoleValidatorCollection,
            ILookupNormalizer: UpperLookupNormalizer,
            UserManager[TUser]: UserManager,
            RoleManager[TRole]: RoleManager,
            IUserConfirmation[TUser]: DefaultUserConfirmation,
            IUserClaimsPrincipalFactory[TUser]: UserClaimsPrincipalFactory,
            SignInManager[TUser]: SignInManager,
        })
        return IdentityBuilder(self._dependencies)

    def add_default_identity(
            self,
            user_store: type[IUserStore],
            role_store: type[IRoleStore],
    ) -> IdentityBuilder:
        builder = self.add_identity(user_store, role_store)
        builder.add_default_token_providers()
        PasswordValidatorCollection.validators.update((PasswordValidator,))
        UserValidatorCollection.validators.update((UserValidator,))
        RoleValidatorCollection.validators.update((RoleValidator,))
        return builder

    def build(self):
        for cls in self._dependencies.values():
            if cls is None:
                continue

            signature = inspect.signature(cls)
            parameters = []

            for parameter in signature.parameters.values():
                if get_origin(parameter.annotation) is Annotated:
                    parameters.append(parameter)
                    continue

                if get_origin(parameter.annotation) in (Union, Generic,):
                    args = get_args(parameter.annotation)
                    if self._dependencies.get(args[0]):
                        parameters.append(
                            parameter.replace(
                                annotation=Annotated[parameter.annotation, Depends(self._dependencies[args[0]])]
                            )
                        )
                else:
                    if depends := self._dependencies.get(parameter.annotation):
                        parameters.append(
                            parameter.replace(
                                annotation=Annotated[parameter.annotation, Depends(depends)]
                            )
                        )
                    else:
                        parameters.append(parameter)

            cls.__signature__ = signature.replace(parameters=parameters)


def use_authentication(app: FastAPI, on_error: ExceptionHandler | None = None):
    app.add_middleware(AuthenticationMiddleware, schemes=AuthenticationSchemeProvider)

    if on_error:
        app.add_exception_handler(AuthenticationError, on_error)
    else:
        app.add_exception_handler(
            AuthenticationError,
            lambda req, exc: PlainTextResponse('Unauthorized', status_code=401)
        )


def use_authorization(app: FastAPI, on_error: ExceptionHandler | None = None):
    if on_error:
        app.add_exception_handler(AuthorizationError, on_error)
    else:
        app.add_exception_handler(
            AuthorizationError,
            lambda req, exc: PlainTextResponse('Forbidden', status_code=403)
        )
