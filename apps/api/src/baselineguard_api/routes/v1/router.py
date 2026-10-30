from fastapi import APIRouter, Depends, Request

from baselineguard_api.routes.v1.auth import router as auth_router
from baselineguard_api.routes.v1.collector import router as collector_router
from baselineguard_api.routes.v1.inventory import router as inventory_router
from baselineguard_api.routes.v1.live import router as live_router
from baselineguard_api.routes.v1.pipeline import router as pipeline_router
from baselineguard_api.routes.v1.policies import router as policies_router
from baselineguard_api.routes.v1.scans import router as scans_router
from baselineguard_api.routes.v1.schedules import router as schedules_router
from baselineguard_api.security import SESSION_COOKIE, Principal, csrf_token, require_principal

router = APIRouter(prefix="/api/v1")
router.include_router(inventory_router)
router.include_router(scans_router)
router.include_router(auth_router)
router.include_router(policies_router)
router.include_router(pipeline_router)
router.include_router(schedules_router)
router.include_router(collector_router)
router.include_router(live_router)


@router.get("/me", tags=["identity"])
def get_me(
    request: Request, principal: Principal = Depends(require_principal)
) -> dict[str, object]:
    return {
        "user_id": str(principal.user_id),
        "org_id": str(principal.org_id),
        "roles": sorted(principal.roles),
        "site_ids": sorted(str(site_id) for site_id in principal.site_ids),
        "csrf_token": csrf_token(request.cookies.get(SESSION_COOKIE, "")),
    }
