"""
Tests para el servicio principal de autenticación.
"""
import pytest
from datetime import datetime, timezone
from sqlalchemy import select
from app.models.user import User, UserStatus
from app.models.audit_log import AuditLog, AuditAction
from app.services.auth_service import AuthService
from app.services.password_service import password_service
from app.schemas.auth import RegisterRequest, LoginRequest
from app.core.exceptions import (
    ValidationError,
    AuthenticationError,
    AccountLockedError,
    DuplicateEmailError,
    PolicyNotAcceptedError,
)


class TestAuthServiceRegister:
    """Tests de registro de usuarios."""

    @pytest.fixture
    async def auth_service(self, db_session):
        return AuthService(db_session)

    @pytest.mark.asyncio
    async def test_register_success(self, auth_service, valid_register_data):
        """Verifica registro exitoso con auto-login."""
        request = RegisterRequest(**valid_register_data)
        
        response = await auth_service.register(request, ip_address="127.0.0.1")
        
        assert response.message == "Registro exitoso. Bienvenido a CyberAuth"
        assert response.user_id is not None
        assert response.token is not None
        assert response.token.access_token is not None
        assert response.token.token_type == "bearer"
        assert response.token.expires_in > 0
        
        # Verificar usuario en BD
        from sqlalchemy import select
        stmt = select(User).where(User.id == response.user_id)
        result = await auth_service.db.execute(stmt)
        user = result.scalar_one()
        
        assert user.email == valid_register_data["email"]
        assert user.full_name == valid_register_data["full_name"]
        assert user.accepted_privacy_policy is True
        assert user.privacy_policy_accepted_at is not None
        assert user.status == UserStatus.ACTIVE
        assert user.failed_attempts == 0
        
        # Verificar hash de contraseña
        assert password_service.verify_password(valid_register_data["password"], user.hashed_password)

    @pytest.mark.asyncio
    async def test_register_audit_log_created(self, auth_service, valid_register_data, db_session):
        """Verifica creación de log de auditoría en registro."""
        request = RegisterRequest(**valid_register_data)
        
        response = await auth_service.register(request, ip_address="127.0.0.1", user_agent="TestAgent")
        
        # Verificar audit log
        stmt = select(AuditLog).where(AuditLog.user_id == response.user_id)
        result = await db_session.execute(stmt)
        logs = result.scalars().all()
        
        assert len(logs) == 1
        assert logs[0].action == AuditAction.REGISTER
        assert logs[0].ip_address == "127.0.0.1"
        assert logs[0].user_agent == "TestAgent"

    @pytest.mark.asyncio
    async def test_register_duplicate_email_fails(self, auth_service, valid_register_data, db_session):
        """Verifica rechazo de email duplicado (mensaje genérico)."""
        request = RegisterRequest(**valid_register_data)
        
        # Primer registro exitoso
        await auth_service.register(request)
        
        # Segundo registro con mismo email
        request2 = RegisterRequest(**valid_register_data)
        
        with pytest.raises(DuplicateEmailError) as exc_info:
            await auth_service.register(request2)
        
        # Mensaje genérico para no revelar existencia
        assert "otro correo" in exc_info.value.message.lower()

    @pytest.mark.asyncio
    async def test_register_invalid_password_fails(self, auth_service):
        """Verifica rechazo de contraseña inválida."""
        data = {
            "email": "test@example.com",
            "password": "weak",  # Muy corta, sin mayúscula, sin número
            "full_name": "Test",
            "accept_privacy_policy": True,
        }
        request = RegisterRequest(**data)
        
        with pytest.raises(ValidationError) as exc_info:
            await auth_service.register(request)
        
        assert exc_info.value.error_code == "VALIDATION_ERROR_PASSWORD"

    @pytest.mark.asyncio
    async def test_register_without_policy_fails(self, auth_service):
        """Verifica rechazo si no acepta política."""
        data = {
            "email": "test@example.com",
            "password": "SecurePass123",
            "full_name": "Test",
            "accept_privacy_policy": False,
        }
        request = RegisterRequest(**data)
        
        with pytest.raises(PolicyNotAcceptedError):
            await auth_service.register(request)

    @pytest.mark.asyncio
    async def test_register_email_normalization(self, auth_service):
        """Verifica normalización de email (lowercase, strip)."""
        data = {
            "email": "  TEST@EXAMPLE.COM  ",
            "password": "SecurePass123",
            "full_name": "Test",
            "accept_privacy_policy": True,
        }
        request = RegisterRequest(**data)
        
        response = await auth_service.register(request)
        
        stmt = select(User).where(User.id == response.user_id)
        result = await auth_service.db.execute(stmt)
        user = result.scalar_one()
        
        assert user.email == "test@example.com"


class TestAuthServiceLogin:
    """Tests de inicio de sesión."""

    @pytest.fixture
    async def auth_service(self, db_session):
        return AuthService(db_session)

    @pytest.fixture
    async def registered_user(self, auth_service, valid_register_data):
        """Crea un usuario registrado para tests de login."""
        request = RegisterRequest(**valid_register_data)
        response = await auth_service.register(request)
        
        # Obtener usuario de BD
        stmt = select(User).where(User.id == response.user_id)
        result = await auth_service.db.execute(stmt)
        user = result.scalar_one()
        return user

    @pytest.mark.asyncio
    async def test_login_success(self, auth_service, registered_user, valid_login_data):
        """Verifica login exitoso."""
        request = LoginRequest(**valid_login_data)
        
        response = await auth_service.login(request, ip_address="127.0.0.1")
        
        assert response.access_token is not None
        assert response.token_type == "bearer"
        assert response.expires_in > 0
        
        # Verificar last_login actualizado
        await auth_service.db.refresh(registered_user)
        assert registered_user.last_login is not None
        assert registered_user.failed_attempts == 0

    @pytest.mark.asyncio
    async def test_login_audit_log_created(self, auth_service, registered_user, valid_login_data, db_session):
        """Verifica log de auditoría en login exitoso."""
        request = LoginRequest(**valid_login_data)
        
        await auth_service.login(request, ip_address="127.0.0.1", user_agent="TestAgent")
        
        stmt = select(AuditLog).where(
            AuditLog.user_id == registered_user.id,
            AuditLog.action == AuditAction.LOGIN
        )
        result = await db_session.execute(stmt)
        logs = result.scalars().all()
        
        assert len(logs) >= 1
        last_log = logs[-1]
        assert last_log.action == AuditAction.LOGIN
        assert last_log.ip_address == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_login_wrong_password_fails(self, auth_service, registered_user):
        """Verifica rechazo de contraseña incorrecta."""
        request = LoginRequest(
            email=registered_user.email,
            password="WrongPass123"
        )
        
        with pytest.raises(AuthenticationError):
            await auth_service.login(request)
        
        # Verificar incremento de failed_attempts
        await auth_service.db.refresh(registered_user)
        assert registered_user.failed_attempts == 1

    @pytest.mark.asyncio
    async def test_login_nonexistent_user_generic_error(self, auth_service):
        """Verifica mensaje genérico para usuario inexistente."""
        request = LoginRequest(
            email="nonexistent@example.com",
            password="SecurePass123"
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.login(request)
        
        # Mensaje genérico
        assert exc_info.value.message == "Credenciales inválidas"
        assert exc_info.value.error_code == "AUTHENTICATION_FAILED"

    @pytest.mark.asyncio
    async def test_login_account_locked_after_5_failures(self, auth_service, registered_user):
        """Verifica bloqueo tras 5 intentos fallidos."""
        request = LoginRequest(
            email=registered_user.email,
            password="WrongPass123"
        )
        
        # 5 intentos fallidos
        for i in range(5):
            with pytest.raises(AuthenticationError):
                await auth_service.login(request)
        
        # 6to intento debe bloquear
        with pytest.raises(AccountLockedError) as exc_info:
            await auth_service.login(request)
        
        assert "bloqueada" in exc_info.value.message.lower()
        
        # Verificar estado en BD
        await auth_service.db.refresh(registered_user)
        assert registered_user.status == UserStatus.LOCKED
        assert registered_user.locked_until is not None
        assert registered_user.failed_attempts >= 5

    @pytest.mark.asyncio
    async def test_login_locked_account_rejects(self, auth_service, registered_user):
        """Verifica rechazo de cuenta bloqueada."""
        # Bloquear manualmente
        registered_user.status = UserStatus.LOCKED
        registered_user.locked_until = datetime.now(timezone.utc) + \
            __import__("datetime").timedelta(minutes=15)
        await auth_service.db.commit()
        
        request = LoginRequest(
            email=registered_user.email,
            password="SecurePass123"  # Contraseña correcta
        )
        
        with pytest.raises(AccountLockedError):
            await auth_service.login(request)

    @pytest.mark.asyncio
    async def test_login_success_resets_failed_attempts(self, auth_service, registered_user):
        """Verifica que login exitoso resetea intentos fallidos."""
        # Generar algunos fallos
        wrong_request = LoginRequest(
            email=registered_user.email,
            password="WrongPass123"
        )
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                await auth_service.login(wrong_request)
        
        await auth_service.db.refresh(registered_user)
        assert registered_user.failed_attempts == 3
        
        # Login exitoso
        correct_request = LoginRequest(**{
            "email": registered_user.email,
            "password": "SecurePass123"
        })
        await auth_service.login(correct_request)
        
        await auth_service.db.refresh(registered_user)
        assert registered_user.failed_attempts == 0
        assert registered_user.status == UserStatus.ACTIVE


class TestAuthServiceSession:
    """Tests de validación de sesión."""

    @pytest.fixture
    async def auth_service(self, db_session):
        return AuthService(db_session)

    @pytest.fixture
    async def registered_user(self, auth_service, valid_register_data):
        request = RegisterRequest(**valid_register_data)
        response = await auth_service.register(request)
        stmt = select(User).where(User.id == response.user_id)
        result = await auth_service.db.execute(stmt)
        return result.scalar_one()

    @pytest.mark.asyncio
    async def test_validate_session_valid_token(self, auth_service, registered_user, valid_login_data):
        """Verifica validación de token válido."""
        login_request = LoginRequest(**valid_login_data)
        token_response = await auth_service.login(login_request)
        
        is_valid, user_id, expires_at = await auth_service.validate_session(token_response.access_token)
        
        assert is_valid is True
        assert user_id == registered_user.id
        assert expires_at is not None

    @pytest.mark.asyncio
    async def test_validate_session_invalid_token(self, auth_service):
        """Verifica rechazo de token inválido."""
        is_valid, user_id, _ = await auth_service.validate_session("invalid.token.here")
        
        assert is_valid is False
        assert user_id is None

    @pytest.mark.asyncio
    async def test_validate_session_expired_token(self, auth_service, registered_user, valid_login_data):
        """Verifica rechazo de token expirado."""
        from freezegun import freeze_time
        from app.services.token_service import token_service
        
        with freeze_time("2024-01-01 12:00:00"):
            login_request = LoginRequest(**valid_login_data)
            token_response = await auth_service.login(login_request)
            token = token_response.access_token
        
        with freeze_time("2024-01-01 13:00:00"):  # Expirado (30 min)
            is_valid, user_id, _ = await auth_service.validate_session(token)
            assert is_valid is False
            assert user_id is None

    @pytest.mark.asyncio
    async def test_validate_session_deleted_user(self, auth_service, registered_user, valid_login_data):
        """Verifica rechazo si usuario fue eliminado."""
        login_request = LoginRequest(**valid_login_data)
        token_response = await auth_service.login(login_request)
        
        # Eliminar usuario
        await auth_service.db.delete(registered_user)
        await auth_service.db.commit()
        
        is_valid, user_id, _ = await auth_service.validate_session(token_response.access_token)
        assert is_valid is False
        assert user_id is None

    @pytest.mark.asyncio
    async def test_validate_session_inactive_user(self, auth_service, registered_user, valid_login_data):
        """Verifica rechazo si usuario está inactivo."""
        login_request = LoginRequest(**valid_login_data)
        token_response = await auth_service.login(login_request)
        
        # Marcar usuario inactivo
        registered_user.status = UserStatus.INACTIVE
        await auth_service.db.commit()
        
        is_valid, user_id, _ = await auth_service.validate_session(token_response.access_token)
        assert is_valid is False
        assert user_id is None


class TestAuthServiceLogout:
    """Tests de cierre de sesión."""

    @pytest.fixture
    async def auth_service(self, db_session):
        return AuthService(db_session)

    @pytest.fixture
    async def registered_user(self, auth_service, valid_register_data, db_session):
        request = RegisterRequest(**valid_register_data)
        response = await auth_service.register(request)
        stmt = select(User).where(User.id == response.user_id)
        result = await db_session.execute(stmt)
        return result.scalar_one()

    @pytest.mark.asyncio
    async def test_logout_creates_audit_log(self, auth_service, registered_user, db_session):
        """Verifica creación de log de auditoría en logout."""
        await auth_service.logout(registered_user.id, ip_address="127.0.0.1", user_agent="TestAgent")
        
        stmt = select(AuditLog).where(
            AuditLog.user_id == registered_user.id,
            AuditLog.action == AuditAction.LOGOUT
        )
        result = await db_session.execute(stmt)
        logs = result.scalars().all()
        
        assert len(logs) == 1
        assert logs[0].action == AuditAction.LOGOUT
        assert logs[0].ip_address == "127.0.0.1"