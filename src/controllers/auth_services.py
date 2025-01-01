import uuid
from jose import jwt
from sqlalchemy.orm import Session
from pydantic import EmailStr, SecretStr
from fastapi import status, Request
from typing import Any, Dict, Literal, Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

from ..core.config import settings
from ..middleware.logging import logger
from ..schemas.auth_schemas import TokenData
from ..database.models import User, UserSession
from ..schemas.responses import CustomJSONResponse
from ..schemas.requests import RegistrationForm, LoginForm


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_token(data: Dict, expires_delta: timedelta) -> str:
    """
    Creates a JWT token with the provided data and expiration time.

    # Args:
        `data` (Dict): The data to be included in the JWT token.
        `expires_delta` (timedelta): The expiration time for the token.

    # Returns:
        `str`: The JWT token.
    """
    to_encode = data.copy()
    expire_time = datetime.now(timezone.utc) + expires_delta

    to_encode.update({"exp": expire_time})
    encoded_jwt = jwt.encode(
        claims=to_encode, key=settings.PRIVATE_KEY, algorithm=settings.JWT_ALGORITHM
    )

    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any] | Literal["expired_token"] | None:
    """
    Decodes a JWT token and returns the decoded data.

    # Args:
        `token` (str): The JWT token to be decoded.

    # Returns:
        `Dict[str, Any] | Literal["expired_token"] | None`: The decoded data or "expired_token" if the token is expired.
    """
    logger.info(f"Decoding JWT token: {token}")

    try:
        decoded_jwt = jwt.decode(
            token, key=settings.PUBLIC_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return decoded_jwt
    except jwt.ExpiredSignatureError:
        logger.error("Expired token")
        return "expired_token"
    except Exception as e:
        logger.error(f"Error decoding token: {e}")
        return None


def user_login(
    request: Request, email: str, password: str, db: Session
) -> CustomJSONResponse:
    logger.info(f"User login execution started - email: {email}")

    try:
        user = db.query(User).filter(User.email == email).first()

        # Validating user
        if not user:
            logger.error("User not found")
            return CustomJSONResponse(
                success=False,
                status_code=status.HTTP_404_NOT_FOUND,
                message="User not found",
                error={
                    "code": "NOT_FOUND_ERROR",
                    "details": "User with the provided email does not exist. Please register or try with a different email.",
                },
            )

        # Validating password
        if not password_context.verify(password, user.hashed_password):
            logger.error("Password mismatch")
            return CustomJSONResponse(
                success=False,
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Invalid credentials",
                error={
                    "code": "INVALID_CREDENTIALS_ERROR",
                    "details": "The provided credentials are incorrect. Please check your email and password.",
                },
                headers={"WWW-Authenticate": 'Bearer error="invalid_credentials"'},
            )

        logger.info("User Authorized, deleting old sessions and generating new tokens")

        # Deleting all existing sessions for the user
        db.query(UserSession).filter(UserSession.user_id == user.id).delete()
        db.commit()

        # Generating a new session ID
        session_id = str(uuid.uuid4())

        # Generating tokens with session ID in the claims
        token_claims = {
            "user_id": user.id,
            "session_id": session_id,
            "allowed_ips": [request.client.host],
        }
        access_token = create_token(
            data=token_claims,
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        refresh_token = create_token(
            data=token_claims,
            expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )

        logger.info("Tokens generated successfully")

        # Creating a new session entry in the database
        new_session = UserSession(
            id=session_id,
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            created_at=datetime.now(timezone.utc),
        )
        db.add(new_session)
        db.commit()

        # Updating the user's last login timestamp
        user.last_login = datetime.now(timezone.utc)
        db.commit()

        return CustomJSONResponse(
            success=True,
            status_code=status.HTTP_200_OK,
            message="User logged in successfully",
            data={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            },
            meta={
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": f"{user.first_name} {user.last_name}",
                },
            },
        )

    except Exception as e:
        logger.error(f"Error occurred during user login: {e}")
        return CustomJSONResponse(
            success=False,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="User login failed",
            error={
                "code": "INTERNAL_SERVER_ERROR",
                "details": "Something went wrong while trying to log in. Please try again.",
            },
        )

    finally:
        db.close()
        logger.info("User login execution completed")


def user_registration(creds: RegistrationForm, db: Session) -> CustomJSONResponse:
    """
    Registers a new user in the database.

    # Args:
        `creds` (RegistrationForm): The registration form containing user details.
        `db` (Session): The database session for performing database operations.

    # Returns:
        `CustomJSONResponse`: A custom JSON response indicating the success or failure of the registration process.
    """
    logger.info("User registration execution started")

    try:
        # Checking if user already exists
        if db.query(User).filter(User.email == creds.email).first():
            logger.error("User already exists")

            return CustomJSONResponse(
                success=False,
                status_code=status.HTTP_409_CONFLICT,
                message="User already exists",
                error={
                    "code": "CONFLICT_ERROR",
                    "details": "User with the provided email already exists. Please login or try with a different email.",
                },
            )

        # Creating hashed password
        hashed_password = password_context.hash(creds.password.get_secret_value())

        new_user = User(
            first_name=creds.first_name.capitalize(),
            last_name=creds.last_name.capitalize(),
            email=creds.email,
            auth_type="email",
            hashed_password=hashed_password,
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logger.info(f"Created new user: {new_user.__repr__()}")

        return CustomJSONResponse(
            success=True,
            status_code=status.HTTP_201_CREATED,
            message="User registered successfully. Please login with same email.",
        )

    except Exception as e:
        logger.error(f"User registration failed: {e}")

        return CustomJSONResponse(
            success=False,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="User registration failed",
            error={
                "code": "INTERNAL_SERVER_ERROR",
                "details": "Something went wrong while registering the user. Please try again.",
            },
        )

    finally:
        db.close()
        logger.info("User registration execution completed")


def user_logout(session_id: int, db: Session) -> CustomJSONResponse:
    """
    Deletes the user session from the database based on the provided JWT token data.

    # Args:
        `token_data` (TokenData): The token data containing user ID and session ID.
        `db` (Session): The database session for performing database operations.

    # Returns:
        `CustomJSONResponse`: A custom JSON response indicating the success or failure of the logout process.
    """
    logger.info(f"User logout execution started")

    try:
        user_session = (
            db.query(UserSession)
            .filter(
                UserSession.id == session_id,
            )
            .one()
        )

        db.delete(user_session)
        db.commit()

        logger.info(f"Deleted user session: {user_session.__repr__()}")
        return CustomJSONResponse(
            success=True,
            status_code=status.HTTP_200_OK,
            message="User logged out successfully",
        )

    except Exception as e:
        return CustomJSONResponse(
            success=False,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="User logout failed",
            error={
                "code": "INTERNAL_SERVER_ERROR",
                "details": "Something went wrong while trying to log out. Please try again.",
            },
        )

    finally:
        db.close()
        logger.info("User logout execution completed")