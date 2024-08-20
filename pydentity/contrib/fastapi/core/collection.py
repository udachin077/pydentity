from pydentity.contrib.fastapi.core.abc import IServiceCollection
from pydentity.contrib.fastapi.types import TService, TImplementation, DependencyCallable


class ServiceCollection(IServiceCollection):
    def __init__(self):
        super().__init__()

    def _add(self, service_type: type[TService], factory: DependencyCallable[TImplementation]):
        self[service_type] = factory

    def add_service(self, service_type: type[TService], factory: DependencyCallable[TImplementation]):
        self._add(service_type, factory)

    def get(self, service_type: type[TService]):
        return self.get(service_type)

    def get_all(self):
        return self
