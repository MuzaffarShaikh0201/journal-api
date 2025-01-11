from typing import Dict, TypedDict
from pydantic import BaseModel, Field

from .default_schemas import (
    CreatedResponse,
    SuccessfulResponse,
    BackendErrorResponse,
    NotFoundErrorResponse,
    ConflictErrorResponse,
    ForbiddenErrorResponse,
    ValidationErrorResponse,
    UnauthorizedErrorResponse,
)


class TokenData(BaseModel):
    id: str
    access_token: str
    refresh_token: str
    token_type: str


class SessionData(TypedDict):
    session_id: str
    user_id: int


class LoginSuccessfulResponse(SuccessfulResponse):
    message: str = "User logged in successfully"
    data: TokenData = Field(
        ...,
        examples=[
            {
                "id": "session_id",
                "access_token": "user_access_token",
                "refresh_token": "user_refresh_token",
                "token_type": "Bearer",
            }
        ],
        json_schema_extra={
            "id": "session_id",
            "access_token": "user_access_token",
            "refresh_token": "user_refresh_token",
            "token_type": "Bearer",
        },
    )
    meta: Dict[str, str] = Field(
        ...,
        examples=[
            {
                "user": {
                    "id": "user_id",
                    "email": "user_email",
                    "first_name": "user_first_name",
                    "last_name": "user_last_name",
                },
            }
        ],
        json_schema_extra={
            "user": {
                "id": "user_id",
                "email": "user_email",
                "first_name": "user_first_name",
                "last_name": "user_last_name",
            },
        },
    )


class LoginUnauthorizedErrorResponse(UnauthorizedErrorResponse):
    message: str = "Invalid credentials"
    error: Dict[str, str] = {
        "code": "INVALID_CREDENTIALS_ERROR",
        "details": "The provided credentials are incorrect. Please check your email and password.",
    }


class LoginNotFoundErrorResponse(NotFoundErrorResponse):
    message: str = "User not found"
    error: Dict[str, str] = {
        "code": "NOT_FOUND_ERROR",
        "details": "User with the provided email does not exist. Please register or try with a different email.",
    }


class LoginBackendErrorResponse(BackendErrorResponse):
    message: str = "User login failed"
    error: Dict[str, str] = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "Something went wrong while trying to log in. Please try again.",
    }


LOGIN_RESPONSE_MODEL = {
    200: {"model": LoginSuccessfulResponse},
    401: {"model": LoginUnauthorizedErrorResponse},
    404: {"model": LoginNotFoundErrorResponse},
    422: {"model": ValidationErrorResponse},
    500: {"model": LoginBackendErrorResponse},
}


class RegistrationSuccessfulResponse(CreatedResponse):
    message: str = "User registered successfully. Please login with same email."


class RegistrationConflictErrorResponse(ConflictErrorResponse):
    message: str = "User already exists"
    error: Dict[str, str] = {
        "code": "CONFLICT_ERROR",
        "details": "User with the provided email already exists. Please login or try with a different email.",
    }


class RegistrationBackendErrorResponse(BackendErrorResponse):
    message: str = "User registration failed"
    error: Dict[str, str] = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "Something went wrong while registering the user. Please try again.",
    }


REGISTRATION_RESPONSE_MODEL = {
    201: {"model": RegistrationSuccessfulResponse},
    409: {"model": RegistrationConflictErrorResponse},
    422: {"model": ValidationErrorResponse},
    500: {"model": RegistrationBackendErrorResponse},
}


class LogoutSuccessResponse(SuccessfulResponse):
    message: str = "User logged out successfully"


class LogoutBackendErrorResponse(BackendErrorResponse):
    message: str = "User logout failed"
    error: Dict[str, str] = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "Something went wrong while trying to log out. Please try again.",
    }


LOGOUT_RESPONSE_MODEL = {
    200: {"model": LogoutSuccessResponse},
    401: {"model": UnauthorizedErrorResponse},
    403: {"model": ForbiddenErrorResponse},
    422: {"model": ValidationErrorResponse},
    500: {"model": LogoutBackendErrorResponse},
}


class TokenForbiddenErrorResponse(ForbiddenErrorResponse):
    message: str = "You are not authorized to access this resource"
    error: Dict[str, str] = {
        "code": "FORBIDDEN",
        "details": "You are not authorized to access this resource. Please contact support if needed.",
    }


TOKEN_RESPONSE_MODEL = {
    200: {"model": TokenData},
    401: {"model": LoginUnauthorizedErrorResponse},
    403: {"model": TokenForbiddenErrorResponse},
    404: {"model": LoginNotFoundErrorResponse},
    422: {"model": ValidationErrorResponse},
    500: {"model": LoginBackendErrorResponse},
}


class RefreshTokenBackendErrorResponse(BackendErrorResponse):
    message: str = "Failed to verify refresh token"
    error: Dict[str, str] = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "Something went wrong while verifying the refresh token. Please try again.",
    }


REFRESH_TOKEN_RESPONSE_MODEL = {
    200: {"model": LoginSuccessfulResponse},
    401: {"model": UnauthorizedErrorResponse},
    403: {"model": ForbiddenErrorResponse},
    422: {"model": ValidationErrorResponse},
    500: {"model": RefreshTokenBackendErrorResponse},
}
