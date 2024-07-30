import base64
from typing import cast

import pyotp

__all__ = ('Rfc6238AuthenticationService',)


def _apply_modifier(input_: bytes, modifier_bytes: bytes | None = None) -> str:
    return cast(str, base64.b32encode(input_ + modifier_bytes if modifier_bytes else input_))


class Rfc6238AuthenticationService:

    @staticmethod
    def generate_code(security_token: bytes, modifier: bytes | None = None, interval: int = 30) -> str:
        b32secret = _apply_modifier(security_token, modifier)
        totp = pyotp.TOTP(b32secret, interval=interval)
        return totp.now()

    @staticmethod
    def validate_code(security_token: bytes, code: str, modifier: bytes | None = None, interval: int = 30) -> bool:
        b32secret = _apply_modifier(security_token, modifier)
        totp = pyotp.TOTP(b32secret, interval=interval)
        return totp.verify(code)
