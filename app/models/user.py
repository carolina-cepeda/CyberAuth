import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, Boolean, Index
from sqlalchemy.sql import func
from app.database import Base


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    LOCKED = "locked"
    INACTIVE = "inactive"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    accepted_privacy_policy = Column(Boolean, default=False, nullable=False)
    privacy_policy_accepted_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_users_email_status", "email", "status"),
    )

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, status={self.status})>"