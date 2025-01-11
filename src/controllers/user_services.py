from fastapi import status
from sqlalchemy.orm import Session

from ..database.models import User
from ..middleware.logging import logger
from ..schemas.responses import CustomJSONResponse


async def get_user_profile(user_id: int, db: Session) -> CustomJSONResponse:
    """
    Retrieves the user profile based on the provided user ID from the database.
    # Args:
        `user_id` (int): The ID of the user whose profile needs to be retrieved.
        `db` (Session): The database session for performing database operations.
    # Returns:
        `CustomJSONResponse`: A custom JSON response containing the user profile data.
    """
    logger.info("Get user profile execution started")
    try:
        user = db.query(User).filter(User.id == user_id).one_or_none()

        if not user:
            return CustomJSONResponse(
                success=False,
                status_code=status.HTTP_404_NOT_FOUND,
                message="User not found",
                error={
                    "code": "NOT_FOUND_ERROR",
                    "details": "The user could not be found. Please try again later.",
                },
            )

        return CustomJSONResponse(
            success=True,
            status_code=status.HTTP_200_OK,
            message="User profile retrieved successfully",
            data={
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
        )
    except Exception as e:
        logger.error(f"Failed to retrieve user profile: {e}")
        return CustomJSONResponse(
            success=False,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="Failed to retrieve user profile",
            error={
                "code": "INTERNAL_SERVER_ERROR",
                "details": "Something went wrong while retrieving the user profile. Please try again.",
            },
        )
    finally:
        db.close()
        logger.info("Get user profile execution completed")
