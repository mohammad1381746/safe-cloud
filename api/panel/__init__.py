from __future__ import annotations

from fastapi import APIRouter

from panel.admin_profiles import router as profiles_router
from panel.admin_scanners import router as scanners_router
from panel.admin_settings import router as settings_router
from panel.auth import router as auth_router
from panel.routes import router as pages_router
from panel.upload import router as upload_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(pages_router)
router.include_router(scanners_router)
router.include_router(profiles_router)
router.include_router(settings_router)
router.include_router(upload_router)

__all__ = ["router"]
