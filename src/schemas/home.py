from pydantic import BaseModel


class HomeSuccessResponse(BaseModel):
    success: bool = True
    status_code: int = 200
    message: str = "This is initial route!"


class HomeErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 500
    message: str = "Internal Server Error"
    error: dict = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "An unexpected error occurred. Please try again later or contact support if the issue persists.",
    }


HOME_RESPONSE_MODEL = {
    200: {"model": HomeSuccessResponse},
    500: {"model": HomeErrorResponse},
}
