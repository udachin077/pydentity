from typing import Any

from itsdangerous import URLSafeSerializer, BadSignature

from pydentity.exc import DataProtectorError, ArgumentNoneException
from pydentity.interfaces import IPersonalDataProtector
from pydentity.utils import is_none_or_empty

__all__ = ('DefaultPersonalDataProtector',)


class DefaultPersonalDataProtector(IPersonalDataProtector):
    """Default implementation of ``IPersonalDataProtector``."""

    __slots__ = ('_serializer',)

    def __init__(self, purpose: str, salt: str | None = None) -> None:
        if is_none_or_empty(purpose):
            raise ArgumentNoneException("purpose")

        if is_none_or_empty(salt):
            try:
                import machineid  # noqa
                salt = machineid.hashed_id()  # MachineIdNotFound(RuntimeError)
            except (ImportError, RuntimeError):
                salt = "DefaultPersonalDataProtector"

        self._serializer = URLSafeSerializer(purpose, salt)

    def protect(self, data: Any) -> str:
        return self._serializer.dumps(data)

    def unprotect(self, data: str) -> Any:
        try:
            return self._serializer.loads(data)
        except BadSignature as ex:
            raise DataProtectorError(ex.message)
