from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from pydentity_db_sqlalchemy.models import Model

from example.fastapi.api import router
from example.fastapi.api.dependencies import get_engine, cookie_handler
from pydentity.http.context import HttpContext
from pydentity.identity_constants import IdentityConstants


@asynccontextmanager
async def lifespan(app):
    async with get_engine().begin() as conn:
        await conn.run_sync(Model.metadata.create_all)
    yield


app = FastAPI(lifespan=lifespan, )
app.include_router(router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_headers=['*'],
    allow_methods=['*'],
    allow_credentials=True,
)


@app.middleware("http")
async def authentication(request: Request, call_next):
    context = HttpContext(request, None)
    result = await cookie_handler.authenticate(context, IdentityConstants.ApplicationScheme)
    context.user = result.principal
    response = await call_next(request)
    return response


if __name__ == '__main__':
    uvicorn.run(
        '__main__:app',
        host='localhost',
        # ssl_keyfile="E:/Projects/key.pem",
        # ssl_certfile="E:/Projects/cert.pem"
    )
