from typing import Any, Dict
from pydantic import BaseModel, Field


class SuccessfulResponse(BaseModel):
    success: bool = True
    status_code: int = 200
    message: str = "This is initial route!"
    data: None
    error: None
    meta: None


class CreatedResponse(BaseModel):
    success: bool = True
    status_code: int = 201
    message: str = "Created"
    data: None
    error: None
    meta: None


class UnauthorizedErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 401
    message: str = "Unauthorized"
    data: None
    error: Dict[str, str] = {
        "code": "UNAUTHORIZED",
        "details": "Authentication required",
    }
    meta: None


class ForbiddenErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 403
    message: str = "Forbidden"
    data: None
    error: Dict[str, str] = {
        "code": "FORBIDDEN",
        "details": "You are not authorized to access this resource.",
    }
    meta: None


class NotFoundErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 404
    message: str = "Not Found"
    data: None
    error: Dict[str, str] = {
        "code": "NOT_FOUND",
        "details": "The requested resource could not be found.",
    }
    meta: None


class ConflictErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 409
    message: str = "Conflict Error"
    data: None
    error: Dict[str, str] = {
        "code": "CONFLICT_ERROR",
        "details": "The resource you are trying to access is already in use.",
    }
    meta: None


class ValidationErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 422
    message: str = "Validation Error"
    data: None
    error: Dict[str, Any] = Field(
        ...,
        examples=[
            {
                "code": "VALIDATION_ERROR",
                "details": [{"field": "field_name", "error": "Field is required"}],
            }
        ],
        json_schema_extra={
            "code": "VALIDATION_ERROR",
            "details": [{"field": "field_name", "error": "Field is required"}],
        },
    )
    meta: None


class TooManyRequestsError(BaseModel):
    success: bool = False
    status_code: int = 429
    message: str = "Too Many Requests"
    data: None
    error: Dict[str, str] = {
        "code": "TOO_MANY_REQUESTS",
        "details": "Rate limit exceeded. Try again later.",
    }
    meta: None


class BackendErrorResponse(BaseModel):
    success: bool = False
    status_code: int = 500
    message: str = "Internal Server Error"
    data: None
    error: Dict[str, str] = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "An unexpected error occurred. Please try again later or contact support if the issue persists.",
    }
    meta: None


HOME_RESPONSE_MODEL = {
    200: {"model": SuccessfulResponse},
    429: {"model": TooManyRequestsError},
    500: {"model": BackendErrorResponse},
}
