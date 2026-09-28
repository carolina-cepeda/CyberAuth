"""
Servicio de gestión de tokens JWT.
Maneja creación, validación y expiración de tokens de sesión.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
from app.config import get_settings


class TokenService:
    """
    Servicio para manejar tokens de acceso JWT.
    
    Características:
    - Tokens firmados con HS256 (clave simétrica)
    - Expiración configurable (30 min por defecto)
    - Claims estándar: sub, exp, iat, jti
    """

    def __init__(self):
        settings = get_settings()
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes

    def create_access_token(
        self,
        user_id: int,
        email: str,
        expires_delta: Optional[timedelta] = None
    ) -> tuple[str, datetime]:
        """
        Crea un token de acceso JWT.
        
        Args:
            user_id: ID del usuario
            email: Email del usuario (para auditoría)
            expires_delta: Duración personalizada (opcional)
            
        Returns:
            Tupla (token_jwt, fecha_expiración)
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode = {
            "sub": str(user_id),
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access",
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt, expire

    def decode_token(self, token: str) -> Optional[dict]:
        """
        Decodifica y valida un token JWT.
        
        Args:
            token: Token JWT
            
        Returns:
            Payload decodificado o None si es inválido/expirado
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None

    def validate_token(self, token: str) -> tuple[bool, Optional[int], Optional[datetime]]:
        """
        Valida un token y extrae información del usuario.
        
        Args:
            token: Token JWT
            
        Returns:
            Tupla (es_válido, user_id, fecha_expiración)
        """
        payload = self.decode_token(token)
        if not payload:
            return False, None, None
        
        # Verificar tipo de token
        if payload.get("type") != "access":
            return False, None, None
        
        try:
            user_id = int(payload.get("sub", 0))
            exp_timestamp = payload.get("exp")
            if exp_timestamp:
                expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            else:
                expires_at = None
            
            return True, user_id, expires_at
        except (ValueError, TypeError):
            return False, None, None

    def get_token_remaining_seconds(self, token: str) -> Optional[int]:
        """
        Obtiene los segundos restantes de validez del token.
        
        Args:
            token: Token JWT
            
        Returns:
            Segundos restantes o None si inválido
        """
        payload = self.decode_token(token)
        if not payload:
            return None
        
        exp_timestamp = payload.get("exp")
        if not exp_timestamp:
            return None
        
        expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        if expires_at <= now:
            return 0
        
        return int((expires_at - now).total_seconds())

    def is_token_expired(self, token: str) -> bool:
        """
        Verifica si un token ha expirado sin lanzar excepciones.
        
        Args:
            token: Token JWT
            
        Returns:
            True si expirado o inválido
        """
        remaining = self.get_token_remaining_seconds(token)
        return remaining is None or remaining <= 0


# Instancia singleton
token_service = TokenService()