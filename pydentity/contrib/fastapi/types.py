from typing import TypeVar, Union
from collections.abc import Callable, Generator, AsyncIterator, AsyncGenerator, Coroutine

TReturnType = TypeVar('TReturnType')
TOptions = TypeVar('TOptions')
THandler = TypeVar('THandler')
TService = TypeVar('TService')
TImplementation = TypeVar('TImplementation')

DependencyCallable = Callable[
    ...,
    Union[
        TReturnType,
        Coroutine[None, None, TReturnType],
        AsyncGenerator[TReturnType, None],
        Generator[TReturnType, None, None],
        AsyncIterator[TReturnType]
    ]
]
