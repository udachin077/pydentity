import pytest
import pytest_asyncio
from pydentity_db_sqlalchemy.stores import UserStore
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from pydentity.user_manager import UserManager


@pytest.fixture(scope='session')
def engine():
    return create_async_engine('sqlite+aiosqlite://', echo=True)


@pytest.fixture(scope='session')
def async_session_maker(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def session(async_session_maker):
    async with async_session_maker() as session:
        yield session


@pytest_asyncio.fixture(scope='session')
async def user_store(async_session_maker):
    async with async_session_maker() as session:
        yield UserStore(session)


@pytest_asyncio.fixture
async def user_manager(user_store):
    yield UserManager(store=user_store)
