import uvicorn

from baselineguard_api.config import get_settings

settings = get_settings()
uvicorn.run(
    "baselineguard_api.main:app", host=settings.api_host, port=settings.api_port, reload=False
)
