from typing import Annotated
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi import Request, HTTPException, status, Depends, Header


from ..database.connect import get_db
from ..database.models import UserSession
from ..schemas.auth_schemas import SessionData
from ..schemas.responses import CustomHttpException
from ..controllers.auth_services import decode_token


class OAuth2PasswordBearerHeader(OAuth2PasswordBearer):
    def __init__(
        self,
        token_url: str = "/auth/token",
        scheme_name: str = "bearer",
        scopes: dict = None,
        description: str = "OAuth2 Password Grant",
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}

        super().__init__(
            tokenUrl=token_url,
            scheme_name=scheme_name,
            scopes=scopes,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(
        self,
        request: Request,
        Authorization: Annotated[
            str | None,
            Header(description="Authorization header", example="Bearer <token>"),
        ] = None,
        db: Session = Depends(get_db),
    ) -> HTTPException | SessionData:
        try:
            authorization_header = Authorization
            ip_address = request.client.host

            if not authorization_header:
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized",
                        error_code="UNAUTHORIZED",
                        error_details="Missing Authorization header. Please provide a valid Bearer token.",
                    )

            scheme, param = get_authorization_scheme_param(authorization_header)

            if not param or scheme.lower() != "bearer":
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid Authorization header. Please provide a valid Bearer token.",
                    )

            token_data = decode_token(token=param)

            if not token_data:
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid token. Please provide a valid Bearer token.",
                    )

            if token_data == "expired_token":
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized",
                        error_code="UNAUTHORIZED",
                        error_details="Token expired. Please refresh the token or login again.",
                    )

            if not all(
                keys in token_data.keys()
                for keys in ["user_id", "session_id", "allowed_ips"]
            ):
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid token structure. Please provide a valid Bearer token.",
                    )

            user_session = (
                db.query(UserSession)
                .filter(UserSession.id == token_data.get("session_id"))
                .one_or_none()
            )

            if (
                not user_session
                or user_session.user_id != token_data.get("user_id")
                or user_session.access_token != param
            ):
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid token data. Please provide a valid Bearer token.",
                    )

            if ip_address not in token_data.get("allowed_ips", []):
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        message="Forbidden",
                        error_code="FORBIDDEN",
                        error_details="Access from this IP address is not allowed. Please contact support if needed.",
                        headers={"X-RateLimit-Policy": "IP-Restriction"},
                    )

            session_id: int = token_data.get("session_id")
            user_id: int = token_data.get("user_id")

            return {"session_id": session_id, "user_id": user_id}
        except CustomHttpException as e:
            print("Error in OAuth2PasswordBearerHeader middleware:", e)
            raise e
        except Exception as e:
            print("Error in OAuth2PasswordBearerHeader middleware:", e)
            raise CustomHttpException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Internal Server Error",
                error_code="INTERNAL_SERVER_ERROR",
                error_details="An unexpected error occurred. Please try again later or contact support if the issue persists.",
            )
        finally:
            db.close()


oauth2_scheme = OAuth2PasswordBearerHeader()
