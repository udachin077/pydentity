from itsdangerous import URLSafeSerializer

from pydentity.contrib.fastapi.authentication.cookie.abc import ICookieAuthenticationSerializer


class DefaultCookieAuthenticationSerializer(ICookieAuthenticationSerializer):
    __slots__ = ('_serializer',)

    def __init__(self):
        self._serializer = URLSafeSerializer(self.__class__.__name__)

    def deserialize(self, data: str | None) -> dict | None:
        return self._serializer.loads(data) if data else data

    def serialize(self, data: dict | None) -> str | None:
        return self._serializer.dumps(data) if data else data
