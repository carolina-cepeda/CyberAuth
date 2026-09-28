"""
Utilidades de seguridad para el servicio de autenticación.
Incluye extracción de IP, user-agent, y helpers de seguridad.
"""
from typing import Optional
from fastapi import Request, HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED
from app.core.exceptions import InvalidTokenError, SessionExpiredError
from app.services.token_service import token_service


def get_client_ip(request: Request) -> str:
    """
    Extrae la IP real del cliente considerando proxies.
    
    Args:
        request: Request de FastAPI
        
    Returns:
        IP del cliente
    """
    # Verificar headers de proxy comunes
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Tomar la primera IP (cliente original)
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback a client host
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> Optional[str]:
    """
    Obtiene el User-Agent del cliente.
    
    Args:
        request: Request de FastAPI
        
    Returns:
        User-Agent string o None
    """
    return request.headers.get("User-Agent")


async def get_current_user_id(
    request: Request,
    authorization: Optional[str] = None
) -> int:
    """
    Extrae y valida el token de autorización del header.
    
    Args:
        request: Request de FastAPI
        authorization: Header Authorization (Bearer token)
        
    Returns:
        user_id del token válido
        
    Raises:
        InvalidTokenError: Si el token es inválido
        SessionExpiredError: Si el token ha expirado
    """
    if not authorization:
        raise InvalidTokenError("Falta el token de autorización")
    
    # Esperar formato "Bearer <token>"
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise InvalidTokenError("Formato de token inválido. Use: Bearer <token>")
    
    token = parts[1]
    
    # Validar token
    is_valid, user_id, expires_at = token_service.validate_token(token)
    
    if not is_valid:
        raise InvalidTokenError()
    
    if expires_at and expires_at < request.state.get("now", __import__("datetime").datetime.now(__import__("datetime").timezone.utc)):
        raise SessionExpiredError()
    
    return user_id


def create_generic_error_response(error: Exception) -> dict:
    """
    Crea respuesta de error genérica (no revela información sensible).
    
    Args:
        error: Excepción capturada
        
    Returns:
        Dict con error_code y message genéricos
    """
    from app.core.exceptions import AuthError
    
    if isinstance(error, AuthError):
        return {
            "error_code": error.error_code,
            "message": error.message,
        }
    
    # Error genérico para excepciones no controladas
    return {
        "error_code": "INTERNAL_ERROR",
        "message": "Error interno del servidor. Intente más tarde",
    }


def sanitize_log_data(data: dict) -> dict:
    """
    Elimina datos sensibles de logs.
    
    Args:
        data: Diccionario con datos
        
    Returns:
        Diccionario sin campos sensibles
    """
    sensitive_fields = {"password", "token", "secret", "authorization", "cookie"}
    sanitized = {}
    
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_fields):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value
    
    return sanitized