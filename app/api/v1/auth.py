"""
Rutas de API para autenticación (v1).
Endpoints: register, login, logout, validate session.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.auth_service import AuthService
from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    RegisterResponse,
    ErrorResponse,
    MessageResponse,
    SessionValidationResponse,
    LogoutRequest,
)
from app.core.exceptions import (
    ValidationError,
    AuthenticationError,
    AccountLockedError,
    AccountNotFoundError,
    DuplicateEmailError,
    PolicyNotAcceptedError,
    SessionExpiredError,
    InvalidTokenError,
)
from app.core.security import get_client_ip, get_user_agent, create_generic_error_response


router = APIRouter(prefix="/auth", tags=["Autenticación"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    """Dependencia para obtener el servicio de autenticación."""
    return AuthService(db)


def handle_auth_error(error: Exception) -> HTTPException:
    """Convierte excepciones de auth a HTTPException con respuesta estandarizada."""
    error_response = create_generic_error_response(error)
    status_code = getattr(error, "status_code", 500)
    return HTTPException(status_code=status_code, detail=error_response)


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Datos de entrada inválidos"},
        409: {"model": ErrorResponse, "description": "Email ya registrado"},
        422: {"model": ErrorResponse, "description": "Error de validación"},
    },
    summary="Registrar nuevo usuario",
    description="""
    Registra un nuevo usuario en el sistema.
    
    Requisitos:
    - Email único
    - Contraseña: mínimo 10 caracteres, 1 mayúscula, 1 número
    - Aceptación obligatoria de política de tratamiento de datos (Ley 1581/2012)
    
    Retorna token de sesión para auto-login tras registro exitoso.
    """
)
async def register(
    request: RegisterRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> RegisterResponse:
    try:
        ip = get_client_ip(http_request)
        ua = get_user_agent(http_request)
        return await auth_service.register(request, ip_address=ip, user_agent=ua)
    except (ValidationError, PolicyNotAcceptedError, DuplicateEmailError) as e:
        raise handle_auth_error(e)
    except Exception as e:
        # Log interno (no exponer detalles)
        raise handle_auth_error(e)


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Credenciales inválidas"},
        423: {"model": ErrorResponse, "description": "Cuenta bloqueada temporalmente"},
        429: {"model": ErrorResponse, "description": "Demasiados intentos"},
    },
    summary="Iniciar sesión",
    description="""
    Autentica un usuario y genera token de acceso JWT.
    
    Protecciones:
    - Rate limiting: 5 intentos fallidos = 15 min bloqueo (por IP y por usuario)
    - Mensajes genéricos (no revela si email existe)
    - Hash de contraseña con Argon2 (tiempo constante)
    """
)
async def login(
    request: LoginRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        ip = get_client_ip(http_request)
        ua = get_user_agent(http_request)
        return await auth_service.login(request, ip_address=ip, user_agent=ua)
    except (AuthenticationError, AccountLockedError, AccountNotFoundError) as e:
        raise handle_auth_error(e)
    except Exception as e:
        raise handle_auth_error(e)


@router.post(
    "/logout",
    response_model=MessageResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Token inválido o expirado"},
    },
    summary="Cerrar sesión",
    description="Registra el evento de logout en auditoría. El cliente debe descartar el token."
)
async def logout(
    http_request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=create_generic_error_response(InvalidTokenError("Falta token"))
        )
    
    try:
        # Extraer user_id del token para auditoría
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            from app.services.token_service import token_service
            is_valid, user_id, _ = token_service.validate_token(parts[1])
            if is_valid and user_id:
                ip = get_client_ip(http_request)
                ua = get_user_agent(http_request)
                await auth_service.logout(user_id, ip_address=ip, user_agent=ua)
    except Exception:
        pass  # No fallar logout por errores de auditoría
    
    return MessageResponse(message="Sesión cerrada exitosamente")


@router.get(
    "/validate",
    response_model=SessionValidationResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Token inválido o expirado"},
    },
    summary="Validar token de sesión",
    description="Verifica si un token de sesión es válido y no ha expirado."
)
async def validate_session(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    auth_service: AuthService = Depends(get_auth_service),
) -> SessionValidationResponse:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=create_generic_error_response(InvalidTokenError("Falta token"))
        )
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=create_generic_error_response(InvalidTokenError("Formato inválido"))
        )
    
    try:
        is_valid, user_id, expires_at = await auth_service.validate_session(parts[1])
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=create_generic_error_response(SessionExpiredError())
            )
        
        return SessionValidationResponse(
            valid=True,
            user_id=user_id,
            expires_at=expires_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise handle_auth_error(e)


@router.get(
    "/me",
    response_model=SessionValidationResponse,
    summary="Obtener info de sesión actual",
    description="Alias de /validate para compatibilidad."
)
async def get_current_session(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    auth_service: AuthService = Depends(get_auth_service),
) -> SessionValidationResponse:
    return await validate_session(authorization, auth_service)