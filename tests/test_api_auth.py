"""
Tests de integración para endpoints de API de autenticación.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models.user import User, UserStatus
from app.models.audit_log import AuditLog, AuditAction
from app.services.token_service import token_service


class TestRegisterEndpoint:
    """Tests del endpoint POST /api/v1/auth/register."""

    @pytest.mark.asyncio
    async def test_register_success(self, client, valid_register_data):
        """Verifica registro exitoso via API."""
        response = await client.post("/api/v1/auth/register", json=valid_register_data)
        
        assert response.status_code == 201
        data = response.json()
        
        assert data["message"] == "Registro exitoso. Bienvenido a CyberAuth"
        assert "user_id" in data
        assert "token" in data
        assert data["token"]["access_token"] is not None
        assert data["token"]["token_type"] == "bearer"
        assert data["token"]["expires_in"] > 0

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client, valid_register_data):
        """Verifica rechazo de email duplicado."""
        # Primer registro
        await client.post("/api/v1/auth/register", json=valid_register_data)
        
        # Segundo registro
        response = await client.post("/api/v1/auth/register", json=valid_register_data)
        
        assert response.status_code == 409
        data = response.json()
        # Manejar ambos formatos: con y sin wrapper 'detail'
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "REGISTRATION_FAILED"
        assert "otro correo" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_register_invalid_password(self, client):
        """Verifica validación de contraseña débil."""
        data = {
            "email": "test@example.com",
            "password": "weak",
            "full_name": "Test",
            "accept_privacy_policy": True,
        }
        response = await client.post("/api/v1/auth/register", json=data)
        
        assert response.status_code == 422
        data = response.json()
        # Manejar ambos formatos
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "VALIDATION_ERROR_PASSWORD"

    @pytest.mark.asyncio
    async def test_register_without_policy(self, client):
        """Verifica rechazo sin aceptar política."""
        data = {
            "email": "test@example.com",
            "password": "SecurePass123",
            "full_name": "Test",
            "accept_privacy_policy": False,
        }
        response = await client.post("/api/v1/auth/register", json=data)
        
        # Pydantic validation devuelve 422
        assert response.status_code == 422
        data = response.json()
        # Manejar ambos formatos
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "POLICY_NOT_ACCEPTED"

    @pytest.mark.asyncio
    async def test_register_invalid_email(self, client):
        """Verifica validación de formato de email."""
        data = {
            "email": "not-an-email",
            "password": "SecurePass123",
            "full_name": "Test",
            "accept_privacy_policy": True,
        }
        response = await client.post("/api/v1/auth/register", json=data)
        
        assert response.status_code == 422


class TestLoginEndpoint:
    """Tests del endpoint POST /api/v1/auth/login."""

    @pytest.fixture
    async def registered_user(self, client, valid_register_data, valid_login_data):
        """Registra usuario y retorna datos de login."""
        await client.post("/api/v1/auth/register", json=valid_register_data)
        return valid_login_data

    @pytest.mark.asyncio
    async def test_login_success(self, client, registered_user):
        """Verifica login exitoso."""
        response = await client.post("/api/v1/auth/login", json=registered_user)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, registered_user):
        """Verifica rechazo de contraseña incorrecta."""
        wrong_data = registered_user.copy()
        wrong_data["password"] = "WrongPass123"
        
        response = await client.post("/api/v1/auth/login", json=wrong_data)
        
        assert response.status_code == 401
        data = response.json()
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "AUTHENTICATION_FAILED"
        assert data["message"] == "Credenciales inválidas"

    @pytest.mark.asyncio
    async def test_login_nonexistent_user_generic(self, client):
        """Verifica mensaje genérico para usuario inexistente."""
        data = {
            "email": "nonexistent@example.com",
            "password": "SecurePass123",
        }
        response = await client.post("/api/v1/auth/login", json=data)
        
        assert response.status_code == 401
        data = response.json()
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "AUTHENTICATION_FAILED"
        assert data["message"] == "Credenciales inválidas"

    @pytest.mark.asyncio
    async def test_login_locked_account(self, client, valid_register_data, valid_login_data):
        """Verifica bloqueo tras 5 intentos fallidos."""
        await client.post("/api/v1/auth/register", json=valid_register_data)
        
        wrong_data = valid_login_data.copy()
        wrong_data["password"] = "WrongPass123"
        
        # 5 intentos fallidos
        for _ in range(5):
            response = await client.post("/api/v1/auth/login", json=wrong_data)
            assert response.status_code == 401
        
        # 6to intento debe bloquear
        response = await client.post("/api/v1/auth/login", json=wrong_data)
        
        assert response.status_code == 423
        data = response.json()
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "ACCOUNT_LOCKED"
        assert "bloqueada" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_login_valid_after_locked_wait(self, client, valid_register_data, valid_login_data):
        """Verifica que se puede loguear tras esperar expiración de bloqueo."""
        from freezegun import freeze_time
        
        with freeze_time("2024-01-01 12:00:00"):
            await client.post("/api/v1/auth/register", json=valid_register_data)
            
            wrong_data = valid_login_data.copy()
            wrong_data["password"] = "WrongPass123"
            
            for _ in range(5):
                await client.post("/api/v1/auth/login", json=wrong_data)
            
            # Verificar bloqueo
            response = await client.post("/api/v1/auth/login", json=wrong_data)
            assert response.status_code == 423
        
        # Avanzar 16 minutos
        with freeze_time("2024-01-01 12:16:00"):
            response = await client.post("/api/v1/auth/login", json=valid_login_data)
            assert response.status_code == 200


class TestLogoutEndpoint:
    """Tests del endpoint POST /api/v1/auth/logout."""

    @pytest.mark.asyncio
    async def test_logout_success(self, client, valid_register_data, valid_login_data):
        """Verifica logout exitoso."""
        await client.post("/api/v1/auth/register", json=valid_register_data)
        login_response = await client.post("/api/v1/auth/login", json=valid_login_data)
        token = login_response.json()["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.post("/api/v1/auth/logout", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Sesión cerrada exitosamente"

    @pytest.mark.asyncio
    async def test_logout_without_token(self, client):
        """Verifica rechazo sin token."""
        response = await client.post("/api/v1/auth/logout")
        
        assert response.status_code == 401


class TestValidateEndpoint:
    """Tests del endpoint GET /api/v1/auth/validate."""

    @pytest.mark.asyncio
    async def test_validate_valid_token(self, client, valid_register_data, valid_login_data):
        """Verifica validación de token válido."""
        await client.post("/api/v1/auth/register", json=valid_register_data)
        login_response = await client.post("/api/v1/auth/login", json=valid_login_data)
        token = login_response.json()["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get("/api/v1/auth/validate", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["valid"] is True
        assert data["user_id"] is not None
        assert data["expires_at"] is not None

    @pytest.mark.asyncio
    async def test_validate_invalid_token(self, client):
        """Verifica rechazo de token inválido."""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = await client.get("/api/v1/auth/validate", headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        if "detail" in data:
            data = data["detail"]
        assert data["error_code"] == "INVALID_TOKEN"

    @pytest.mark.asyncio
    async def test_validate_expired_token(self, client, valid_register_data, valid_login_data):
        """Verifica rechazo de token expirado."""
        from freezegun import freeze_time
        
        with freeze_time("2024-01-01 12:00:00"):
            await client.post("/api/v1/auth/register", json=valid_register_data)
            login_response = await client.post("/api/v1/auth/login", json=valid_login_data)
            token = login_response.json()["access_token"]
        
        with freeze_time("2024-01-01 13:00:00"):
            headers = {"Authorization": f"Bearer {token}"}
            response = await client.get("/api/v1/auth/validate", headers=headers)
            
            assert response.status_code == 401
            data = response.json()
            if "detail" in data:
                data = data["detail"]
            assert data["error_code"] == "SESSION_EXPIRED"

    @pytest.mark.asyncio
    async def test_validate_without_token(self, client):
        """Verifica rechazo sin token."""
        response = await client.get("/api/v1/auth/validate")
        
        assert response.status_code == 401


class TestHealthEndpoint:
    """Tests del endpoint de health check."""

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Verifica health check."""
        response = await client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "service" in data
        assert "version" in data


class TestRootEndpoint:
    """Tests del endpoint raíz."""

    @pytest.mark.asyncio
    async def test_root_endpoint(self, client):
        """Verifica endpoint raíz."""
        response = await client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "CyberAuth"
        assert "docs" in data
        assert "health" in data