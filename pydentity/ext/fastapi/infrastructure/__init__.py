from collections.abc import Iterable, Iterator
from typing import Any


class CollectionDependency[T](Iterable[T]):
    def __init__(self):
        self.collection: set[T] = set()
        self.kwargs = {}

    def add(self, item: type[T]):
        self.collection.update((item,))

    def __iter__(self) -> Iterator[T]:
        for item in self.collection:
            yield item(**self.kwargs)


class DependenciesContainer(dict[type, Any]):
    def __init__(self):
        super().__init__()
