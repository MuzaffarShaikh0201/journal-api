from fastapi import APIRouter
from fastapi.requests import Request

from ..middleware.logging import logger
from ..controllers.home_services import home
from ..schemas.home import HOME_RESPONSE_MODEL

router = APIRouter(tags=["Utility APIs"])


@router.get("/", responses=HOME_RESPONSE_MODEL)
def default(request: Request):
    """
    ```text
    Default route that serves as the entry point for the API.
    ```
    """
    logger.info(
        "%s - %s - %s",
        request.method,
        "public",
        "Default API is being called",
    )
    return home()
