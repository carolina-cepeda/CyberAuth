"""
Servicio principal de autenticación.
Implementa la lógica de negocio para registro, login, logout y validación de sesión.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.user import User, UserStatus
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, RegisterResponse
from app.services.password_service import password_service
from app.services.token_service import token_service
from app.services.rate_limit_service import rate_limit_service
from app.services.audit_service import AuditService
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
from app.core.security import get_client_ip, get_user_agent


class AuthService:
    """
    Servicio de autenticación con lógica de negocio completa.
    
    Flujos implementados:
    1. Registro de usuario con validaciones y hash de contraseña
    2. Login con verificación de credenciales y rate limiting
    3. Logout e invalidación de sesión
    4. Validación de token de sesión
    5. Auditoría de todos los eventos
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = AuditService(db)

    async def register(
        self,
        request: RegisterRequest,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> RegisterResponse:
        """
        Registra un nuevo usuario.
        
        Reglas de negocio:
        - Email único
        - Contraseña: min 10 chars, 1 mayúscula, 1 número
        - Aceptación obligatoria de política de datos (Ley 1581/2012)
        - Hash seguro de contraseña (Argon2)
        - Auditoría del evento
        
        Args:
            request: Datos de registro validados
            ip_address: IP del cliente
            user_agent: User-Agent del cliente
            
        Returns:
            RegisterResponse con confirmación y token de sesión
            
        Raises:
            ValidationError: Si datos no cumplen validaciones
            PolicyNotAcceptedError: Si no acepta política
            DuplicateEmailError: Si email ya existe (mensaje genérico)
        """
        # Validar fortaleza de contraseña (doble validación: schema + service)
        is_valid, errors = password_service.check_password_strength(request.password)
        if not is_valid:
            raise ValidationError(
                message="Contraseña no cumple requisitos de seguridad",
                field="password",
                details="; ".join(errors)
            )
        
        # Verificar aceptación de política (validado en schema, pero doble check)
        if not request.accept_privacy_policy:
            raise PolicyNotAcceptedError()
        
        # Hashear contraseña
        hashed_password = password_service.hash_password(request.password)
        
        # Crear usuario
        now = datetime.now(timezone.utc)
        user = User(
            email=request.email.lower().strip(),
            hashed_password=hashed_password,
            full_name=request.full_name.strip() if request.full_name else None,
            accepted_privacy_policy=True,
            privacy_policy_accepted_at=now,
            status=UserStatus.ACTIVE,
        )
        
        self.db.add(user)
        
        try:
            await self.db.flush()
            await self.db.refresh(user)
        except IntegrityError:
            await self.db.rollback()
            # Mensaje genérico para no revelar si email existe
            raise DuplicateEmailError()
        
        # Crear token de sesión (auto-login tras registro)
        access_token, expires_at = token_service.create_access_token(
            user_id=user.id,
            email=user.email
        )
        
        # Registrar en auditoría
        await self.audit.log_register(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.db.commit()
        
        return RegisterResponse(
            message="Registro exitoso. Bienvenido a CyberAuth",
            user_id=user.id,
            token=TokenResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=int((expires_at - datetime.now(timezone.utc)).total_seconds())
            )
        )

    async def login(
        self,
        request: LoginRequest,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> TokenResponse:
        """
        Autentica un usuario y genera token de sesión.
        
        Reglas de negocio:
        - Verifica credenciales (hash constante-time)
        - Rate limiting: 5 intentos fallidos = 15 min bloqueo
        - Bloqueo por IP y por usuario
        - Actualiza last_login en éxito
        - Auditoría de login exitoso/fallido
        
        Args:
            request: Credenciales de login
            ip_address: IP del cliente
            user_agent: User-Agent del cliente
            
        Returns:
            TokenResponse con access_token
            
        Raises:
            AuthenticationError: Credenciales inválidas (mensaje genérico)
            AccountLockedError: Cuenta bloqueada por intentos fallidos
            AccountNotFoundError: Usuario no existe (mensaje genérico)
        """
        email = request.email.lower().strip()
        
        # Verificar rate limiting por IP (primera capa de defensa)
        ip_attempts_left, ip_locked_until = await rate_limit_service.record_failed_attempt(
            identifier=ip_address or "unknown",
            by_ip=True
        )
        
        if ip_locked_until:
            raise AccountLockedError(locked_until=ip_locked_until.isoformat())
        
        # Buscar usuario (sin revelar si existe)
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        # Verificar rate limiting por usuario
        user_attempts_left, user_locked_until = await rate_limit_service.record_failed_attempt(
            identifier=email,
            by_ip=False
        )
        
        if user_locked_until:
            # Registrar intento fallido en auditoría
            if user:
                await self.audit.log_login(
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False
                )
                await self.db.commit()
            raise AccountLockedError(locked_until=user_locked_until.isoformat())
        
        # Verificar usuario existe
        if not user:
            # Registrar intento fallido anónimo en auditoría
            await self.audit.log_event(
                action="login_failed",
                user_id=None,
                ip_address=ip_address,
                user_agent=user_agent,
                details=f"Intento de login con email no registrado: {email}"
            )
            await self.db.commit()
            # Mensaje genérico para no revelar existencia de cuenta
            raise AccountNotFoundError()
        
        # Verificar estado de cuenta
        if user.status == UserStatus.LOCKED:
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                raise AccountLockedError(locked_until=user.locked_until.isoformat())
            # Bloqueo expirado, desbloquear automáticamente
            user.status = UserStatus.ACTIVE
            user.failed_attempts = 0
            user.locked_until = None
        
        if user.status != UserStatus.ACTIVE:
            raise AuthenticationError("Cuenta inactiva")
        
        # Verificar contraseña
        if not password_service.verify_password(request.password, user.hashed_password):
            # Incrementar contador de intentos fallidos en BD
            user.failed_attempts += 1
            
            # Bloquear si excede límite
            if user.failed_attempts >= 5:
                user.status = UserStatus.LOCKED
                user.locked_until = datetime.now(timezone.utc) + rate_limit_service.window_minutes * 60
                await self.audit.log_account_locked(
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            
            await self.audit.log_login(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False
            )
            await self.db.commit()
            
            # Mensaje genérico
            raise AuthenticationError()
        
        # Login exitoso - resetear contadores
        user.failed_attempts = 0
        user.status = UserStatus.ACTIVE
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        
        # Resetear rate limiting
        await rate_limit_service.record_success(email, by_ip=False)
        await rate_limit_service.record_success(ip_address or "unknown", by_ip=True)
        
        # Generar token
        access_token, expires_at = token_service.create_access_token(
            user_id=user.id,
            email=user.email
        )
        
        # Auditoría
        await self.audit.log_login(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        
        await self.db.commit()
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=int((expires_at - datetime.now(timezone.utc)).total_seconds())
        )

    async def logout(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """
        Cierra la sesión del usuario (registro en auditoría).
        
        Nota: Con JWT stateless, el logout real es del lado cliente.
        Aquí solo registramos el evento para auditoría.
        
        Args:
            user_id: ID del usuario
            ip_address: IP del cliente
            user_agent: User-Agent del cliente
        """
        await self.audit.log_logout(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.db.commit()

    async def validate_session(
        self,
        token: str
    ) -> tuple[bool, Optional[int], Optional[datetime]]:
        """
        Valida un token de sesión.
        
        Args:
            token: Token JWT
            
        Returns:
            Tupla (es_válido, user_id, fecha_expiración)
        """
        is_valid, user_id, expires_at = token_service.validate_token(token)
        
        if not is_valid or not user_id:
            return False, None, None
        
        # Verificar que el usuario existe y está activo
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or user.status != UserStatus.ACTIVE:
            return False, None, None
        
        return True, user_id, expires_at

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Obtiene usuario por ID."""
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def unlock_account_if_expired(self, user: User) -> bool:
        """
        Desbloquea cuenta si el bloqueo ha expirado.
        
        Args:
            user: Usuario a verificar
            
        Returns:
            True si se desbloqueó
        """
        if user.status == UserStatus.LOCKED and user.locked_until:
            if user.locked_until <= datetime.now(timezone.utc):
                user.status = UserStatus.ACTIVE
                user.failed_attempts = 0
                user.locked_until = None
                await self.audit.log_account_unlocked(user_id=user.id)
                await self.db.commit()
                return True
        return False