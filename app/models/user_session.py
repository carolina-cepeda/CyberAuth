import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index, Boolean, UUID
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from app.database import Base


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    jti = Column(PG_UUID(as_uuid=True), unique=True, nullable=False, index=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_activity = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked = Column(Boolean, default=False, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    __table_args__ = (
        Index("ix_user_sessions_user_revoked_expires", "user_id", "revoked", "expires_at"),
        Index("ix_user_sessions_jti_revoked", "jti", "revoked"),
    )

    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id}, jti={self.jti}, revoked={self.revoked})>"