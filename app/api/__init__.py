from app.api.v1 import auth_router
from fastapi import APIRouter

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/api/v1")

__all__ = ["api_router"]