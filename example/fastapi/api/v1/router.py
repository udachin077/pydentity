from fastapi import APIRouter
from example.fastapi.api.v1.account._router import router as account_router

router = APIRouter(prefix='/v1')
router.include_router(account_router)
