"""
Servicio de limitación de tasa (rate limiting) para intentos fallidos de login.
Implementa bloqueo de cuenta tras 5 intentos fallidos por 15 minutos.
Usa Redis en producción, memoria en desarrollo.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
import json
import asyncio
from app.config import get_settings


class RateLimitService:
    """
    Servicio para rastrear y limitar intentos fallidos de autenticación.
    
    Políticas:
    - Máximo 5 intentos fallidos por usuario/IP
    - Bloqueo de 15 minutos tras exceder límite
    - Limpieza automática de entradas expiradas
    """

    def __init__(self):
        settings = get_settings()
        self.max_attempts = settings.max_failed_attempts
        self.window_minutes = settings.rate_limit_window_minutes
        self.redis_url = settings.redis_url
        
        # Almacenamiento en memoria para desarrollo (reemplazar con Redis en prod)
        self._memory_store: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        
        # Intentar conectar a Redis
        self._redis = None
        self._init_redis()

    def _init_redis(self) -> None:
        """Inicializa conexión a Redis si está disponible."""
        try:
            import redis.asyncio as redis
            self._redis = redis.from_url(self.redis_url, decode_responses=True)
        except Exception:
            # Redis no disponible, usar memoria
            self._redis = None

    def _get_key(self, identifier: str, by_ip: bool = False) -> str:
        """Genera clave de almacenamiento."""
        prefix = "ip" if by_ip else "user"
        return f"ratelimit:{prefix}:{identifier}"

    async def _get_store(self, key: str) -> Optional[dict]:
        """Obtiene datos del almacén (Redis o memoria)."""
        if self._redis:
            try:
                data = await self._redis.get(key)
                return json.loads(data) if data else None
            except Exception:
                pass
        
        async with self._lock:
            return self._memory_store.get(key)

    async def _set_store(self, key: str, data: dict, ttl_seconds: int) -> None:
        """Guarda datos en el almacén con TTL."""
        if self._redis:
            try:
                await self._redis.setex(key, ttl_seconds, json.dumps(data))
                return
            except Exception:
                pass
        
        async with self._lock:
            self._memory_store[key] = data
            # Limpiar entradas expiradas periódicamente
            if len(self._memory_store) > 10000:
                await self._cleanup_memory()

    async def _cleanup_memory(self) -> None:
        """Limpia entradas expiradas de memoria."""
        now = datetime.now(timezone.utc)
        expired_keys = [
            k for k, v in self._memory_store.items()
            if v.get("locked_until") and datetime.fromisoformat(v["locked_until"]) < now
        ]
        for k in expired_keys:
            del self._memory_store[k]

    async def record_failed_attempt(
        self,
        identifier: str,
        by_ip: bool = False
    ) -> tuple[int, Optional[datetime]]:
        """
        Registra un intento fallido y retorna estado actual.
        
        Args:
            identifier: Email de usuario o IP
            by_ip: Si True, limita por IP; si False, por usuario
            
        Returns:
            Tupla (intentos_restantes, fecha_desbloqueo_si_bloqueado)
        """
        key = self._get_key(identifier, by_ip)
        now = datetime.now(timezone.utc)
        window_seconds = self.window_minutes * 60
        
        data = await self._get_store(key)
        
        if not data:
            data = {
                "attempts": 1,
                "first_attempt": now.isoformat(),
                "locked_until": None
            }
        else:
            # Verificar si está bloqueado
            if data.get("locked_until"):
                locked_until = datetime.fromisoformat(data["locked_until"])
                if locked_until > now:
                    remaining = int((locked_until - now).total_seconds())
                    return 0, locked_until
                # Bloqueo expirado, resetear
                data = {"attempts": 1, "first_attempt": now.isoformat(), "locked_until": None}
            else:
                data["attempts"] += 1
        
        # Verificar si debe bloquearse
        locked_until = None
        if data["attempts"] >= self.max_attempts:
            locked_until = now + timedelta(minutes=self.window_minutes)
            data["locked_until"] = locked_until.isoformat()
        
        await self._set_store(key, data, window_seconds * 2)
        
        attempts_remaining = max(0, self.max_attempts - data["attempts"])
        return attempts_remaining, locked_until

    async def record_success(self, identifier: str, by_ip: bool = False) -> None:
        """
        Registra un login exitoso (resetea contador).
        
        Args:
            identifier: Email de usuario o IP
            by_ip: Si True, resetea por IP; si False, por usuario
        """
        key = self._get_key(identifier, by_ip)
        
        if self._redis:
            try:
                await self._redis.delete(key)
                return
            except Exception:
                pass
        
        async with self._lock:
            self._memory_store.pop(key, None)

    async def is_locked(self, identifier: str, by_ip: bool = False) -> tuple[bool, Optional[datetime]]:
        """
        Verifica si un identificador está bloqueado.
        
        Args:
            identifier: Email de usuario o IP
            by_ip: Si True, verifica por IP; si False, por usuario
            
        Returns:
            Tupla (está_bloqueado, fecha_desbloqueo)
        """
        key = self._get_key(identifier, by_ip)
        now = datetime.now(timezone.utc)
        
        data = await self._get_store(key)
        if not data or not data.get("locked_until"):
            return False, None
        
        locked_until = datetime.fromisoformat(data["locked_until"])
        if locked_until > now:
            return True, locked_until
        
        # Bloqueo expirado, limpiar
        if self._redis:
            try:
                await self._redis.delete(key)
            except Exception:
                pass
        else:
            async with self._lock:
                self._memory_store.pop(key, None)
        
        return False, None

    async def get_remaining_attempts(self, identifier: str, by_ip: bool = False) -> int:
        """
        Obtiene intentos restantes antes de bloqueo.
        
        Args:
            identifier: Email de usuario o IP
            by_ip: Si True, por IP; si False, por usuario
            
        Returns:
            Intentos restantes (0 si bloqueado)
        """
        key = self._get_key(identifier, by_ip)
        data = await self._get_store(key)
        
        if not data:
            return self.max_attempts
        
        if data.get("locked_until"):
            locked_until = datetime.fromisoformat(data["locked_until"])
            if locked_until > datetime.now(timezone.utc):
                return 0
        
        return max(0, self.max_attempts - data.get("attempts", 0))


# Instancia singleton
rate_limit_service = RateLimitService()