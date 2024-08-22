from abc import ABC, abstractmethod


class ICookieAuthenticationSerializer(ABC):
    @abstractmethod
    def deserialize(self, data: str | None) -> dict | None:
        pass

    @abstractmethod
    def serialize(self, data: dict | None) -> str | None:
        pass
