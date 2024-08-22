from dataclasses import dataclass
from datetime import timedelta
from typing import Literal


@dataclass
class CookieAuthenticationOptions:
    name: str | None = None
    max_age: int | None = None
    timespan: timedelta = timedelta(days=14)
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    httponly: bool = True
    samesite: Literal["lax", "strict", "none"] = "lax"
