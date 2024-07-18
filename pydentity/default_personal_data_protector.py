import base64
import hashlib
import hmac
from typing import Any

from pydentity.abc import IPersonalDataProtector
from pydentity.exc import InvalidAlgorithm, DataProtectorError


def salted_hmac(key_salt, value, secret, *, algorithm="sha1"):
    key_salt = key_salt.encode()
    secret = secret.encode()
    try:
        hasher = getattr(hashlib, algorithm)
    except AttributeError as e:
        raise InvalidAlgorithm(
            "%r is not an algorithm accepted by the hashlib module." % algorithm
        ) from e
    key = hasher(key_salt + secret).digest()
    return hmac.new(key, msg=value.encode(), digestmod=hasher)


def b64_encode(s):
    return base64.urlsafe_b64encode(s).strip(b"=")


def b64_decode(s):
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def base64_hmac(salt, value, key, algorithm="sha1"):
    return b64_encode(
        salted_hmac(salt, value, key, algorithm=algorithm).digest()
    ).decode()


class DefaultPersonalDataProtector(IPersonalDataProtector):
    def __init__(self, purpose: str, salt: str = None):
        self._purpose = purpose
        self._salt = salt or f"{self.__class__.__module__}.{self.__class__.__name__}"
        self._sep = ':'

    @staticmethod
    def create_protector(purpose: str, salt: str = None) -> "IPersonalDataProtector":
        return DefaultPersonalDataProtector(purpose, salt)

    def protect(self, data: str) -> Any:
        signing = base64_hmac(self._salt, data, self._purpose)
        return f"{data}{self._sep}{signing}"

    def unprotect(self, data: str) -> Any:
        value, sig = data.rsplit(self._sep, 1)
        if hmac.compare_digest(sig, base64_hmac(self._salt, value, self._purpose)):
            return value
        raise DataProtectorError()
