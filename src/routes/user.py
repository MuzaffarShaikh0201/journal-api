from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends

from ..database.connect import get_db
from ..middleware.logging import logger
from ..schemas.auth_schemas import SessionData
from ..schemas.responses import CustomJSONResponse
from ..middleware.authorization import oauth2_scheme
from ..controllers.user_services import get_user_profile
from ..schemas.user_schemas import GET_USER_RESPONSE_MODEL


router = APIRouter(tags=["User APIs"], prefix="/user")


@router.get(path="", responses=GET_USER_RESPONSE_MODEL)
async def user_profile(
    session_data: SessionData = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    ```text
    This endpoint returns the user profile data.
    ```
    """
    logger.info("User Profile API is being called")
    return await get_user_profile(session_id=session_data["user_id"], db=db)
