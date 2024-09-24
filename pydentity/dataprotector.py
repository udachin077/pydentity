from typing import Any

from itsdangerous import URLSafeSerializer, BadSignature

from pydentity.interfaces import IPersonalDataProtector
from pydentity.exc import DataProtectorError, ArgumentNoneException

__all__ = ("DefaultPersonalDataProtector",)


class DefaultPersonalDataProtector(IPersonalDataProtector):
    """Default implementation of ``IPersonalDataProtector``."""

    __slots__ = ("_serializer",)

    def __init__(self, purpose: str, salt: str | None = None) -> None:
        if not purpose:
            raise ArgumentNoneException("purpose")

        self._serializer = URLSafeSerializer(
            purpose,
            salt or f"{self.__class__.__module__}.{self.__class__.__name__}"
        )

    def protect(self, data: Any) -> str:
        return self._serializer.dumps(data)

    def unprotect(self, data: str) -> Any:
        try:
            return self._serializer.loads(data)
        except BadSignature as ex:
            raise DataProtectorError(ex.message)
