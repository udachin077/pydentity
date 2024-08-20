from abc import ABC, abstractmethod

from pydentity.contrib.fastapi.types import DependencyCallable, TImplementation, TService


class IServiceCollection(dict[type, DependencyCallable[TImplementation]], ABC):

    @abstractmethod
    def add_service(self, service_type: type[TService], factory: DependencyCallable[TImplementation]):
        ...

    @abstractmethod
    def get(self, service_type: type[TService]):
        ...

    @abstractmethod
    def get_all(self):
        ...
