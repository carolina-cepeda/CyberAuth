"""
Servicio de logging de auditoría para eventos de autenticación.
Registra todos los eventos relevantes para cumplimiento y seguridad.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.audit_log import AuditLog, AuditAction
from app.models.user import User


class AuditService:
    """
    Servicio para registrar eventos de auditoría de autenticación.
    
    Eventos registrados:
    - Registro de usuario
    - Login exitoso/fallido
    - Logout
    - Bloqueo/desbloqueo de cuenta
    - Cambio de contraseña
    - Expiración de sesión
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_event(
        self,
        action: AuditAction,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[str] = None
    ) -> AuditLog:
        """
        Registra un evento de auditoría.
        
        Args:
            action: Tipo de acción realizada
            user_id: ID del usuario (None para eventos anónimos)
            ip_address: Dirección IP del cliente
            user_agent: User-Agent del cliente
            details: Detalles adicionales en formato JSON string
            
        Returns:
            El registro de auditoría creado
        """
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )
        
        self.db.add(audit_log)
        await self.db.flush()
        return audit_log

    async def log_register(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Registra evento de registro de usuario."""
        return await self.log_event(
            action=AuditAction.REGISTER,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Usuario registrado exitosamente"
        )

    async def log_login(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True
    ) -> AuditLog:
        """Registra evento de login."""
        action = AuditAction.LOGIN if success else AuditAction.LOGIN_FAILED
        details = "Login exitoso" if success else "Credenciales inválidas"
        
        return await self.log_event(
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )

    async def log_logout(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Registra evento de logout."""
        return await self.log_event(
            action=AuditAction.LOGOUT,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Cierre de sesión voluntario"
        )

    async def log_account_locked(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason: str = "Exceso de intentos fallidos"
    ) -> AuditLog:
        """Registra evento de bloqueo de cuenta."""
        return await self.log_event(
            action=AuditAction.ACCOUNT_LOCKED,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Cuenta bloqueada: {reason}"
        )

    async def log_account_unlocked(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Registra evento de desbloqueo de cuenta."""
        return await self.log_event(
            action=AuditAction.ACCOUNT_UNLOCKED,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Cuenta desbloqueada tras expiración de bloqueo"
        )

    async def log_password_changed(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Registra evento de cambio de contraseña."""
        return await self.log_event(
            action=AuditAction.PASSWORD_CHANGED,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Contraseña actualizada exitosamente"
        )

    async def log_session_expired(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Registra evento de expiración de sesión."""
        return await self.log_event(
            action=AuditAction.SESSION_EXPIRED,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Sesión expirada por inactividad (30 min)"
        )

    async def get_user_audit_logs(
        self,
        user_id: int,
        limit: int = 100,
        offset: int = 0
    ) -> list[AuditLog]:
        """
        Obtiene logs de auditoría de un usuario.
        
        Args:
            user_id: ID del usuario
            limit: Límite de resultados
            offset: Desplazamiento para paginación
            
        Returns:
            Lista de logs de auditoría
        """
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def get_recent_failed_logins(
        self,
        user_id: int,
        minutes: int = 60
    ) -> int:
        """
        Cuenta intentos fallidos recientes para un usuario.
        
        Args:
            user_id: ID del usuario
            minutes: Ventana de tiempo en minutos
            
        Returns:
            Número de intentos fallidos
        """
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        
        stmt = (
            select(AuditLog)
            .where(
                AuditLog.user_id == user_id,
                AuditLog.action == AuditAction.LOGIN_FAILED,
                AuditLog.created_at >= cutoff
            )
        )
        result = await self.db.execute(stmt)
        return len(result.scalars().all())