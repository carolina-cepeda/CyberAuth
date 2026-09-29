"""
Servicio de gestión de tokens JWT.
Maneja creación, validación y expiración de tokens de sesión.

Características de seguridad:
- Claims completos: iss, aud, sub, jti, iat, exp
- Validación estricta de algoritmo (fijado a HS256, rechaza "none" y confusión)
- Ejecución en threadpool para no bloquear event loop
- SECRET_KEY validada al arranque (mín 32 chars)
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
import anyio
from jose import jwt, JWTError
from app.config import get_settings


class TokenService:
    """
    Servicio para manejar tokens de acceso JWT.
    
    Características:
    - Tokens firmados con HS256 (clave simétrica)
    - Claims: iss, aud, sub, jti, iat, exp
    - Validación estricta: algoritmo fijado, require claims, rechaza "none"
    - Operaciones crypto en threadpool (no bloquea event loop)
    """

    def __init__(self):
        settings = get_settings()
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.issuer = settings.jwt_issuer
        self.audience = settings.jwt_audience

    async def create_access_token(
        self,
        user_id: int,
        email: str,
        jti: Optional[uuid.UUID] = None,
        expires_delta: Optional[timedelta] = None
    ) -> tuple[str, datetime, uuid.UUID]:
        """
        Crea un token de acceso JWT con claims completos.
        
        Args:
            user_id: ID del usuario
            email: Email del usuario (para auditoría)
            jti: JWT ID único (se genera si no se proporciona)
            expires_delta: Duración personalizada (opcional)
            
        Returns:
            Tupla (token_jwt, fecha_expiración, jti_usado)
        """
        if jti is None:
            jti = uuid.uuid4()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        
        now = datetime.now(timezone.utc)
        to_encode = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": str(user_id),
            "email": email,
            "jti": str(jti),
            "exp": expire,
            "iat": now,
            "type": "access",
        }
        
        # Ejecutar en threadpool para no bloquear
        encoded_jwt = await anyio.to_thread.run_sync(
            jwt.encode, to_encode, self.secret_key, self.algorithm
        )
        return encoded_jwt, expire, jti

    async def decode_token(self, token: str) -> Optional[dict]:
        """
        Decodifica y valida un token JWT con validación estricta.
        
        Validaciones:
        - Algoritmo fijado a HS256 (rechaza confusión de algoritmos)
        - Requiere claims: exp, iat, sub, jti, iss, aud
        - Rechaza alg: "none"
        - Verifica issuer y audience
        
        Args:
            token: Token JWT
            
        Returns:
            Payload decodificado o None si es inválido/expirado
        """
        def _decode():
            return jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],  # Fijado, no configurable por token
                options={
                    "require_exp": True,
                    "require_iat": True,
                    "require_sub": True,
                    "require_jti": True,
                    "require_iss": True,
                    "require_aud": True,
                },
                issuer=self.issuer,
                audience=self.audience,
            )
        
        try:
            payload = await anyio.to_thread.run_sync(_decode)
            return payload
        except JWTError:
            return None

    async def validate_token(self, token: str) -> tuple[bool, Optional[int], Optional[datetime], Optional[uuid.UUID]]:
        """
        Valida un token y extrae información completa.
        
        Args:
            token: Token JWT
            
        Returns:
            Tupla (es_válido, user_id, fecha_expiración, jti)
        """
        payload = await self.decode_token(token)
        if not payload:
            return False, None, None, None
        
        # Verificar tipo de token
        if payload.get("type") != "access":
            return False, None, None, None
        
        try:
            user_id = int(payload.get("sub", 0))
            exp_timestamp = payload.get("exp")
            jti_str = payload.get("jti")
            
            expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc) if exp_timestamp else None
            jti = uuid.UUID(jti_str) if jti_str else None
            
            return True, user_id, expires_at, jti
        except (ValueError, TypeError):
            return False, None, None, None

    async def get_token_remaining_seconds(self, token: str) -> Optional[int]:
        """Obtiene los segundos restantes de validez del token."""
        payload = await self.decode_token(token)
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

    async def is_token_expired(self, token: str) -> bool:
        """Verifica si un token ha expirado sin lanzar excepciones."""
        remaining = await self.get_token_remaining_seconds(token)
        return remaining is None or remaining <= 0


# Instancia singleton
token_service = TokenService()