"""
Tests para el servicio de tokens JWT.
"""
import pytest
from datetime import timedelta
from freezegun import freeze_time
from app.services.token_service import token_service


class TestTokenService:
    """Tests de creación y validación de tokens JWT."""

    def test_create_access_token(self):
        """Verifica creación de token con datos correctos."""
        user_id = 123
        email = "test@example.com"
        
        token, expires_at = token_service.create_access_token(user_id, email)
        
        assert isinstance(token, str)
        assert len(token) > 0
        assert expires_at is not None
        
        # Decodificar y verificar payload
        payload = token_service.decode_token(token)
        assert payload is not None
        assert payload["sub"] == str(user_id)
        assert payload["email"] == email
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload

    def test_create_access_token_custom_expiry(self):
        """Verifica token con expiración personalizada."""
        custom_delta = timedelta(minutes=60)
        token, expires_at = token_service.create_access_token(1, "test@test.com", custom_delta)
        
        payload = token_service.decode_token(token)
        assert payload is not None
        
        # Verificar que expiración es aproximadamente 60 min
        from datetime import datetime, timezone
        expected_expire = datetime.now(timezone.utc) + custom_delta
        actual_expire = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        
        diff = abs((expected_expire - actual_expire).total_seconds())
        assert diff < 5  # Tolerancia 5 segundos

    def test_decode_valid_token(self):
        """Verifica decodificación de token válido."""
        token, _ = token_service.create_access_token(456, "decode@test.com")
        payload = token_service.decode_token(token)
        
        assert payload is not None
        assert payload["sub"] == "456"
        assert payload["email"] == "decode@test.com"

    def test_decode_invalid_token(self):
        """Verifica que token inválido retorne None."""
        assert token_service.decode_token("invalid.token.here") is None
        assert token_service.decode_token("") is None
        assert token_service.decode_token("not.a.jwt") is None

    def test_validate_token_success(self):
        """Verifica validación exitosa de token."""
        token, expires_at = token_service.create_access_token(789, "valid@test.com")
        
        is_valid, user_id, exp = token_service.validate_token(token)
        
        assert is_valid is True
        assert user_id == 789
        assert exp is not None
        # Comparar con tolerancia de 1 segundo (JWT exp no tiene microsegundos)
        diff = abs((exp - expires_at).total_seconds())
        assert diff < 1

    def test_validate_token_wrong_type(self):
        """Verifica rechazo de token con tipo incorrecto."""
        # Crear token manualmente con tipo incorrecto
        from jose import jwt
        from app.config import get_settings
        settings = get_settings()
        
        payload = {"sub": "1", "email": "test@test.com", "type": "refresh", "exp": 9999999999}
        wrong_token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
        
        is_valid, user_id, _ = token_service.validate_token(wrong_token)
        assert is_valid is False
        assert user_id is None

    def test_validate_expired_token(self):
        """Verifica rechazo de token expirado."""
        with freeze_time("2024-01-01 12:00:00"):
            token, _ = token_service.create_access_token(1, "expired@test.com")
        
        with freeze_time("2024-01-01 13:00:00"):  # 1 hora después (expirado)
            is_valid, user_id, _ = token_service.validate_token(token)
            assert is_valid is False
            assert user_id is None

    @freeze_time("2024-01-01 12:00:00")
    def test_get_token_remaining_seconds(self):
        """Verifica cálculo de segundos restantes."""
        token, _ = token_service.create_access_token(1, "remaining@test.com")
        
        remaining = token_service.get_token_remaining_seconds(token)
        
        # Debe ser aproximadamente 30 minutos (1800 segundos)
        assert remaining is not None
        assert 1790 < remaining < 1810

    @freeze_time("2024-01-01 12:00:00")
    def test_is_token_expired_false(self):
        """Verifica token no expirado."""
        token, _ = token_service.create_access_token(1, "notexpired@test.com")
        assert token_service.is_token_expired(token) is False

    def test_is_token_expired_true(self):
        """Verifica token expirado."""
        with freeze_time("2024-01-01 12:00:00"):
            token, _ = token_service.create_access_token(1, "expired@test.com")
        
        with freeze_time("2024-01-01 13:00:00"):
            assert token_service.is_token_expired(token) is True

    def test_is_token_expired_invalid(self):
        """Verifica token inválido se considera expirado."""
        assert token_service.is_token_expired("invalid") is True


class TestTokenSecurity:
    """Tests de seguridad de tokens."""

    def test_token_tampering_detected(self):
        """Verifica detección de manipulación de token."""
        token, _ = token_service.create_access_token(1, "tamper@test.com")
        
        # Modificar el token
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + "." + "invalidsignature"
        
        assert token_service.validate_token(tampered)[0] is False

    def test_token_with_different_secret_fails(self):
        """Verifica que token firmado con otra clave falle."""
        from jose import jwt
        from datetime import datetime, timedelta, timezone
        
        payload = {
            "sub": "1",
            "email": "other@test.com",
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        }
        other_token = jwt.encode(payload, "different-secret", algorithm="HS256")
        
        assert token_service.validate_token(other_token)[0] is False