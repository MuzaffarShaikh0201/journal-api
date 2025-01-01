from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any, List, TypedDict

from .default_schemas import (
    SuccessfulResponse,
    BackendErrorResponse,
    NotFoundErrorResponse,
    ConflictErrorResponse,
    ForbiddenErrorResponse,
    ValidationErrorResponse,
    UnauthorizedErrorResponse,
)


class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class LoginSuccessfulResponse(SuccessfulResponse):
    message: str = "User logged in successfully"
    data: TokenData = Field(
        ...,
        examples=[
            {
                "access_token": "user_access_token",
                "refresh_token": "user_refresh_token",
                "token_type": "Bearer",
            }
        ],
        json_schema_extra={
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
                    "username": "user_name",
                },
            }
        ],
        json_schema_extra={
            "user": {
                "id": "user_id",
                "email": "user_email",
                "username": "user_name",
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


class RegistrationSuccessfulResponse(SuccessfulResponse):
    status_code: int = 201
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
