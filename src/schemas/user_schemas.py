from pydantic import BaseModel, Field

from .default_schemas import (
    ForbiddenErrorResponse,
    SuccessfulResponse,
    BackendErrorResponse,
    NotFoundErrorResponse,
    TooManyRequestsError,
    UnauthorizedErrorResponse,
    ValidationErrorResponse,
)


class UserProfileData(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str


class GetUserSuccessfulResponse(SuccessfulResponse):
    message: str = "User profile retrieved successfully"
    data: UserProfileData = Field(
        ...,
        examples=[
            {
                "id": 1,
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
            }
        ],
        json_schema_extra={
            "id": "user_id",
            "email": "user_email",
            "first_name": "user_first_name",
            "last_name": "user_last_name",
        },
    )


class GetUserNotFoundErrorResponse(NotFoundErrorResponse):
    message: str = "User not found"
    error: dict = {
        "code": "NOT_FOUND_ERROR",
        "details": "The user could not be found. Please try again later.",
    }


class GetUserBackendErrorResponse(BackendErrorResponse):
    message: str = "Failed to retrieve user profile"
    error: dict = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "Something went wrong while retrieving the user profile. Please try again.",
    }


GET_USER_RESPONSE_MODEL = {
    200: {"model": GetUserSuccessfulResponse},
    401: {"model": UnauthorizedErrorResponse},
    403: {"model": ForbiddenErrorResponse},
    404: {"model": GetUserNotFoundErrorResponse},
    422: {"model": ValidationErrorResponse},
    429: {"model": TooManyRequestsError},
    500: {"model": GetUserBackendErrorResponse},
}
