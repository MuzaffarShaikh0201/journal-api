from fastapi import APIRouter
from fastapi.requests import Request

from ..middleware.logging import logger
from ..controllers.utility_services import home
from ..schemas.responses import CustomJSONResponse
from ..schemas.default_schemas import HOME_RESPONSE_MODEL

router = APIRouter(tags=["Utility APIs"])


@router.get("/", responses=HOME_RESPONSE_MODEL)
async def default(request: Request) -> CustomJSONResponse:
    """
    ```text
    Default endpoint that serves as the entry point for the API.
    ```
    """
    logger.info(
        "%s - %s - %s",
        request.method,
        "public",
        "Default API is being called",
    )
    return await home()