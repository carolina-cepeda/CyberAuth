from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="Correo electrónico del usuario")
    password: str = Field(..., min_length=10, max_length=128, description="Contraseña (mín 10 chars, 1 mayúscula, 1 número)")
    full_name: Optional[str] = Field(None, max_length=255, description="Nombre completo")
    accept_privacy_policy: bool = Field(..., description="Aceptación de la política de tratamiento de datos (Ley 1581/2012)")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("La contraseña debe contener al menos una mayúscula")
        if not any(c.isdigit() for c in v):
            raise ValueError("La contraseña debe contener al menos un número")
        return v

    @field_validator("accept_privacy_policy")
    @classmethod
    def validate_policy_accepted(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Debe aceptar la política de tratamiento de datos (Ley 1581 de 2012)")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="Correo electrónico del usuario")
    password: str = Field(..., min_length=1, description="Contraseña")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="Token de acceso JWT")
    token_type: str = Field(default="bearer", description="Tipo de token")
    expires_in: int = Field(..., description="Segundos hasta expiración")


class RegisterResponse(BaseModel):
    message: str = Field(..., description="Mensaje de confirmación")
    user_id: int = Field(..., description="ID del usuario creado")
    token: Optional[TokenResponse] = Field(None, description="Token de sesión (si auto-login)")


class ErrorResponse(BaseModel):
    error_code: str = Field(..., description="Código de error para la interfaz")
    message: str = Field(..., description="Mensaje genérico para el usuario")
    details: Optional[str] = Field(None, description="Detalles adicionales (solo en debug)")


class MessageResponse(BaseModel):
    message: str = Field(..., description="Mensaje de confirmación")


class LogoutRequest(BaseModel):
    token: str = Field(..., description="Token de sesión a invalidar")


class SessionValidationResponse(BaseModel):
    valid: bool = Field(..., description="Si la sesión es válida")
    user_id: Optional[int] = Field(None, description="ID del usuario si la sesión es válida")
    expires_at: Optional[datetime] = Field(None, description="Fecha de expiración del token")