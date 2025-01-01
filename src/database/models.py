import enum
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    Text,
    TIMESTAMP,
    func,
    Enum,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import CITEXT

from .connect import Base


# ENUM for Auth Type
class AuthTypeEnum(enum.Enum):
    email = "email"
    oauth = "oauth"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(CITEXT, unique=True, nullable=False)
    auth_type = Column(Enum(AuthTypeEnum, name="auth_type_enum"), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    hashed_password = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_login = Column(TIMESTAMP(timezone=True), nullable=True)

    sessions = relationship("UserSession", back_populates="user")

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, auth_type={self.auth_type})>"


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Text, primary_key=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user = relationship("User", back_populates="sessions")

    # Unique constraint
    __table_args__ = (UniqueConstraint("user_id", name="unique_user_session"),)

    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id})>"
