from fastapi import status
from sqlalchemy.orm import Session

from ..database.connect import engine
from ..middleware.logging import logger
from ..schemas.responses import CustomJSONResponse, CustomBackendErrorResponse


async def home() -> CustomJSONResponse:
    """
    Returns a JSON response for the initial route.

    # Returns:
        `CustomJSONResponse:` A JSON response with a dict and HTTP status code 200.
    """
    return CustomJSONResponse(
        success=True,
        status_code=status.HTTP_200_OK,
        message="This is initial route",
    )
