from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
from app.models.user import UserStatus


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None


class UserCreate(UserBase):
    pass


class UserUpdate(BaseModel):
    full_name: Optional[str] = None


class UserResponse(UserBase):
    id: int
    status: UserStatus
    last_login: Optional[datetime] = None
    created_at: datetime
    accepted_privacy_policy: bool
    privacy_policy_accepted_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserWithToken(UserResponse):
    token: Optional[str] = None