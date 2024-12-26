from fastapi import status
from ..schemas.responses import CustomJSONResponse


def home() -> CustomJSONResponse:
    """
    Returns a JSON response for the initial route.

    # Returns:
        `JSONResponse:` A JSON response with a message and HTTP status code 200.
    """
    return CustomJSONResponse(
        success=True,
        status_code=status.HTTP_200_OK,
        message="This is initial route",
    )
