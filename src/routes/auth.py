import json
from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm

from ..core.config import settings
from ..database.connect import get_db
from ..middleware.logging import logger
from ..schemas.responses import CustomJSONResponse
from ..middleware.authorization import oauth2_scheme
from ..schemas.requests import LoginForm, RefreshTokenForm, RegistrationForm
from ..controllers.auth_services import (
    user_login,
    user_refresh_token,
    user_registration,
    user_logout,
)
from ..schemas.auth_schemas import (
    LOGIN_RESPONSE_MODEL,
    REFRESH_TOKEN_RESPONSE_MODEL,
    REGISTRATION_RESPONSE_MODEL,
    LOGOUT_RESPONSE_MODEL,
    TOKEN_RESPONSE_MODEL,
    SessionData,
    TokenData,
)


router = APIRouter(tags=["Auth APIs"], prefix="/auth")


@router.post("/register", responses=REGISTRATION_RESPONSE_MODEL)
async def register(
    creds: RegistrationForm = Depends(), db: Session = Depends(get_db)
) -> CustomJSONResponse:
    """
    ```text
    This endpoint handles the user registration functionality.
    ```
    """
    logger.info("Register API is being called")
    return await user_registration(creds=creds, db=db)


@router.post(
    "/login",
    responses=LOGIN_RESPONSE_MODEL,
)
async def login(
    request: Request,
    form_data: LoginForm = Depends(),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    ```text
    This endpoint handles the user login functionality.
    ```
    """
    logger.info("Login API is being called")
    return await user_login(
        request=request,
        email=form_data.email,
        password=form_data.password.get_secret_value(),
        db=db,
    )


@router.post("/token", responses=TOKEN_RESPONSE_MODEL)
async def token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> TokenData:
    """
    ```text
    This endpoint handles the token generation functionality for swagger UI.
    NOte: This is not a part of the actual API. Use /auth/login in actual usecases.
    ```
    """
    logger.info("Token API is being called")

    if form_data.username not in settings.DEVELOPERS_EMAIL:
        return CustomJSONResponse(
            success=False,
            status_code=403,
            message="You are not authorized to access this resource",
            error={
                "code": "FORBIDDEN",
                "details": "You are not authorized to access this resource. Please contact support if needed.",
            },
        )

    token_response = await user_login(
        request=request, email=form_data.username, password=form_data.password, db=db
    )

    if token_response.status_code == 200:
        token_data = json.loads(token_response.body.decode("utf-8"))
        reponse = TokenData(**token_data["data"])
    else:
        reponse = token_data

    return reponse


@router.post("/refresh", responses=REFRESH_TOKEN_RESPONSE_MODEL)
async def refresh_auth(
    request: Request,
    form_data: RefreshTokenForm = Depends(),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    ```text
    This endpoint handles the token refresh functionality.
    ```
    """
    logger.info("Refresh Token API is being called")
    return await user_refresh_token(
        request=request, refresh_token=form_data.refresh_token, db=db
    )


@router.get("/logout", responses=LOGOUT_RESPONSE_MODEL)
async def logout(
    session_data: SessionData = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    ```text
    This endpoint handles the user logout functionality.
    ```
    """
    logger.info("Logout API is being called")
    return await user_logout(session_id=session_data["session_id"], db=db)
