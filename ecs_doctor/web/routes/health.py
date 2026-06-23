
from fastapi import APIRouter

router = APIRouter()


@router.get("/healthz")
async def health_check() -> dict:
    return {"status": "ok"}
