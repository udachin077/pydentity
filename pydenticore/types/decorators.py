class _Singleton:
    def __init__(self, cls: type):
        self.__wrapped__ = cls
        self._instance = None

    def __call__(self, *args, **kwargs):
        if self._instance is None:
            self._instance = self.__wrapped__(*args, **kwargs)
        return self._instance


def singleton(cls: type):
    return _Singleton(cls)
