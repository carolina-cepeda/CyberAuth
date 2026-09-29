"""
Servicio de gestión de sesiones de usuario.
Implementa sliding expiration (ventana de inactividad), revocación por JTI (denylist),
y tope absoluto de vida de sesión.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import redis.asyncio as redis
import json

from app.config import get_settings
from app.models.user_session import UserSession
from app.services.audit_service import AuditService
from app.core.security import get_client_ip, get_user_agent


settings = get_settings()


class SessionService:
    """
    Servicio para gestionar sesiones de usuario con sliding expiration.
    
    Características:
    - Sesiones persistidas en PostgreSQL (tabla user_sessions)
    - Caché de last_activity en Redis para lectura rápida
    - Sliding window: renueva expires_at en cada request válida (30 min inactividad)
    - Tope absoluto: MAX_SESSION_LIFETIME_HOURS desde created_at
    - Revocación real por JTI (denylist en Redis con TTL)
    - Limpieza periódica de sesiones expiradas/revocadas
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = AuditService(db)
        self._redis: Optional[redis.Redis] = None
        self._init_redis()

    def _init_redis(self) -> None:
        """Inicializa conexión a Redis para denylist y caché de actividad."""
        try:
            self._redis = redis.from_url(settings.redis_url, decode_responses=True)
        except Exception:
            self._redis = None

    # --- Claves Redis ---
    def _denylist_key(self, jti: uuid.UUID) -> str:
        return f"session:denylist:{jti}"

    def _activity_key(self, jti: uuid.UUID) -> str:
        return f"session:activity:{jti}"

    # --- Crear sesión ---
    async def create_session(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserSession:
        """
        Crea una nueva sesión para el usuario.
        
        Returns:
            UserSession con jti generado
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
        
        session = UserSession(
            user_id=user_id,
            jti=uuid.uuid4(),
            created_at=now,
            last_activity=now,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        self.db.add(session)
        await self.db.flush()
        await self.db.refresh(session)
        
        # Caché inicial en Redis
        await self._cache_activity(session.jti, now, settings.access_token_expire_minutes * 60)
        
        return session

    # --- Validar y renovar sesión (sliding window) ---
    async def validate_and_renew_session(self, jti: uuid.UUID) -> tuple[bool, Optional[UserSession]]:
        """
        Valida una sesión y renueva su ventana de inactividad si es válida.
        
        Lógica:
        1. Verifica denylist en Redis (revocación inmediata por logout)
        2. Busca sesión en BD
        3. Verifica: no revocada, expires_at > now, created_at < MAX_SESSION_LIFETIME_HOURS
        4. Si válida: actualiza last_activity y extends expires_at (sliding)
        5. Actualiza caché Redis
        
        Returns:
            Tupla (es_válida, sesión_actualizada_o_None)
        """
        # 1. Verificar denylist (revocación inmediata)
        if self._redis:
            try:
                if await self._redis.exists(self._denylist_key(jti)):
                    return False, None
            except Exception:
                pass  # Fallback a BD
        
        # 2. Buscar en BD
        stmt = select(UserSession).where(UserSession.jti == jti)
        result = await self.db.execute(stmt)
        session = result.scalar_one_or_none()
        
        if not session:
            return False, None
        
        now = datetime.now(timezone.utc)
        
        # 3. Verificaciones de validez
        if session.revoked:
            return False, None
        
        if session.expires_at <= now:
            # Expiró por inactividad
            return False, None
        
        # Tope absoluto de vida de sesión
        max_lifetime = session.created_at + timedelta(hours=settings.max_session_lifetime_hours)
        if max_lifetime <= now:
            # Expiró por tope absoluto
            return False, None
        
        # 4. Renovar ventana deslizante (sliding expiration)
        new_expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
        
        # Solo actualizar si la nueva expiración es mayor (evitar race conditions)
        if new_expires_at > session.expires_at:
            session.last_activity = now
            session.expires_at = new_expires_at
            
            await self.db.flush()
            
            # Actualizar caché Redis
            await self._cache_activity(session.jti, now, settings.access_token_expire_minutes * 60)
        
        return True, session

    # --- Revocar sesión (logout) ---
    async def revoke_session(
        self,
        jti: uuid.UUID,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """
        Revoca una sesión por JTI (denylist).
        
        - Marca revoked=true en BD
        - Añade JTI a denylist en Redis con TTL = tiempo restante hasta expires_at
        - Registra en auditoría
        
        Returns:
            True si la sesión existía y fue revocada
        """
        stmt = select(UserSession).where(
            and_(UserSession.jti == jti, UserSession.user_id == user_id)
        )
        result = await self.db.execute(stmt)
        session = result.scalar_one_or_none()
        
        if not session or session.revoked:
            return False
        
        now = datetime.now(timezone.utc)
        
        # Marcar revocada en BD
        session.revoked = True
        await self.db.flush()
        
        # Denylist en Redis con TTL = tiempo restante hasta expires_at
        if self._redis and session.expires_at > now:
            try:
                ttl_seconds = int((session.expires_at - now).total_seconds())
                if ttl_seconds > 0:
                    await self._redis.setex(
                        self._denylist_key(jti),
                        ttl_seconds,
                        "revoked"
                    )
            except Exception:
                pass
        
        # Auditoría
        await self.audit.log_event(
            action="logout",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Sesión revocada (jti={jti})"
        )
        
        await self.db.commit()
        return True

    # --- Revocar todas las sesiones de un usuario ---
    async def revoke_all_user_sessions(
        self,
        user_id: int,
        except_jti: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> int:
        """
        Revoca todas las sesiones activas de un usuario (excepto opcionalmente una).
        Útil para "cerrar sesión en todos los dispositivos".
        
        Returns:
            Número de sesiones revocadas
        """
        stmt = select(UserSession).where(
            and_(
                UserSession.user_id == user_id,
                UserSession.revoked == False,
                UserSession.expires_at > datetime.now(timezone.utc)
            )
        )
        if except_jti:
            stmt = stmt.where(UserSession.jti != except_jti)
        
        result = await self.db.execute(stmt)
        sessions = result.scalars().all()
        
        revoked_count = 0
        for session in sessions:
            session.revoked = True
            revoked_count += 1
            
            # Denylist en Redis
            if self._redis and session.expires_at > datetime.now(timezone.utc):
                try:
                    ttl_seconds = int((session.expires_at - datetime.now(timezone.utc)).total_seconds())
                    if ttl_seconds > 0:
                        await self._redis.setex(
                            self._denylist_key(session.jti),
                            ttl_seconds,
                            "revoked"
                        )
                except Exception:
                    pass
        
        if revoked_count > 0:
            await self.audit.log_event(
                action="logout",
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=f"Revocation masiva: {revoked_count} sesiones revocadas"
            )
            await self.db.commit()
        
        return revoked_count

    # --- Obtener sesiones activas de un usuario ---
    async def get_user_sessions(self, user_id: int) -> List[UserSession]:
        """Obtiene todas las sesiones activas (no revocadas, no expiradas) de un usuario."""
        now = datetime.now(timezone.utc)
        stmt = select(UserSession).where(
            and_(
                UserSession.user_id == user_id,
                UserSession.revoked == False,
                UserSession.expires_at > now
            )
        ).order_by(UserSession.last_activity.desc())
        
        result = await self.db.execute(stmt)
        return result.scalars().all()

    # --- Caché de actividad en Redis ---
    async def _cache_activity(self, jti: uuid.UUID, last_activity: datetime, ttl_seconds: int) -> None:
        """Actualiza last_activity en Redis con TTL."""
        if not self._redis:
            return
        try:
            await self._redis.setex(
                self._activity_key(jti),
                ttl_seconds,
                last_activity.isoformat()
            )
        except Exception:
            pass

    # --- Limpieza de sesiones expiradas (job periódico) ---
    async def cleanup_expired_sessions(self) -> int:
        """
        Elimina sesiones revocadas y expiradas de la BD.
        Debe ejecutarse periódicamente (cron/APScheduler).
        
        Returns:
            Número de sesiones eliminadas
        """
        now = datetime.now(timezone.utc)
        
        # Eliminar sesiones revocadas y expiradas
        stmt = delete(UserSession).where(
            or_(
                and_(UserSession.revoked == True, UserSession.expires_at < now),
                UserSession.expires_at < now - timedelta(days=1)  # expiradas hace más de 1 día
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()
        
        return result.rowcount