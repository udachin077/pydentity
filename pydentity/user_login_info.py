class UserLoginInfo:
    __slots__ = ('_login_provider', '_provider_key', '_display_name',)

    def __init__(self, login_provider: str, provider_key: str, display_name: str | None = None) -> None:
        self._login_provider = login_provider
        self._provider_key = provider_key
        self._display_name = display_name

    @property
    def login_provider(self) -> str:
        return self._login_provider

    @property
    def provider_key(self) -> str:
        return self._provider_key

    @property
    def display_name(self) -> str | None:
        return self._display_name
