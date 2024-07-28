class IdentityError:
    __slots__ = ('_code', '_description',)

    def __init__(self, code: str, description: str):
        self._code = code
        self._description = description

    @property
    def code(self) -> str:
        return self._code

    @property
    def description(self) -> str:
        return self._description

    def __str__(self):
        return f"{self.code}: {self.description}"
