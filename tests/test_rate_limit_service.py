"""
Tests para el servicio de rate limiting.
"""
import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from freezegun import freeze_time
from app.services.rate_limit_service import rate_limit_service, RateLimitService


class TestRateLimitService:
    """Tests de limitación de tasa."""

    @pytest.fixture(autouse=True)
    async def cleanup(self):
        """Limpia el store antes y después de cada test."""
        # Limpiar memoria
        async with rate_limit_service._lock:
            rate_limit_service._memory_store.clear()
        yield
        async with rate_limit_service._lock:
            rate_limit_service._memory_store.clear()

    @pytest.mark.asyncio
    async def test_first_failed_attempt(self):
        """Verifica primer intento fallido."""
        attempts_left, locked_until = await rate_limit_service.record_failed_attempt("user1")
        
        assert attempts_left == 4  # 5 max - 1
        assert locked_until is None

    @pytest.mark.asyncio
    async def test_multiple_failed_attempts(self):
        """Verifica múltiples intentos fallidos."""
        for i in range(4):
            attempts_left, _ = await rate_limit_service.record_failed_attempt("user2")
            assert attempts_left == 4 - i
        
        # 5to intento debe bloquear
        attempts_left, locked_until = await rate_limit_service.record_failed_attempt("user2")
        assert attempts_left == 0
        assert locked_until is not None

    @pytest.mark.asyncio
    async def test_account_locked_after_max_attempts(self):
        """Verifica bloqueo tras exceder intentos máximos."""
        identifier = "user3"
        
        # 5 intentos fallidos
        for _ in range(5):
            await rate_limit_service.record_failed_attempt(identifier)
        
        # Verificar que está bloqueado
        is_locked, locked_until = await rate_limit_service.is_locked(identifier)
        assert is_locked is True
        assert locked_until is not None
        
        # Intentos restantes debe ser 0
        remaining = await rate_limit_service.get_remaining_attempts(identifier)
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_successful_login_resets_counter(self):
        """Verifica que login exitoso resetea contador."""
        identifier = "user4"
        
        # 3 intentos fallidos
        for _ in range(3):
            await rate_limit_service.record_failed_attempt(identifier)
        
        # Login exitoso
        await rate_limit_service.record_success(identifier)
        
        # Contador debe resetearse
        remaining = await rate_limit_service.get_remaining_attempts(identifier)
        assert remaining == 5
        
        is_locked, _ = await rate_limit_service.is_locked(identifier)
        assert is_locked is False

    @pytest.mark.asyncio
    async def test_lock_expires_after_window(self):
        """Verifica que bloqueo expire tras ventana de tiempo."""
        with freeze_time("2024-01-01 12:00:00"):
            identifier = "user5"
            
            # Bloquear cuenta
            for _ in range(5):
                await rate_limit_service.record_failed_attempt(identifier)
            
            is_locked, _ = await rate_limit_service.is_locked(identifier)
            assert is_locked is True
        
        # Avanzar 16 minutos (ventana 15 min + 1)
        with freeze_time("2024-01-01 12:16:00"):
            is_locked, _ = await rate_limit_service.is_locked(identifier)
            assert is_locked is False
            
            # Contador debe resetearse
            remaining = await rate_limit_service.get_remaining_attempts(identifier)
            assert remaining == 5

    @pytest.mark.asyncio
    async def test_separate_counters_per_user(self):
        """Verifica contadores independientes por usuario."""
        await rate_limit_service.record_failed_attempt("userA")
        await rate_limit_service.record_failed_attempt("userA")
        
        await rate_limit_service.record_failed_attempt("userB")
        
        remaining_a = await rate_limit_service.get_remaining_attempts("userA")
        remaining_b = await rate_limit_service.get_remaining_attempts("userB")
        
        assert remaining_a == 3
        assert remaining_b == 4

    @pytest.mark.asyncio
    async def test_separate_counters_ip_vs_user(self):
        """Verifica contadores independientes por IP y por usuario."""
        ip = "192.168.1.1"
        user = "user@test.com"
        
        # 3 intentos por IP
        for _ in range(3):
            await rate_limit_service.record_failed_attempt(ip, by_ip=True)
        
        # 2 intentos por usuario
        for _ in range(2):
            await rate_limit_service.record_failed_attempt(user, by_ip=False)
        
        ip_remaining = await rate_limit_service.get_remaining_attempts(ip, by_ip=True)
        user_remaining = await rate_limit_service.get_remaining_attempts(user, by_ip=False)
        
        assert ip_remaining == 2
        assert user_remaining == 3

    @pytest.mark.asyncio
    async def test_rate_limit_window_config(self):
        """Verifica configuración de ventana de tiempo."""
        service = RateLimitService()
        # Sobrescribir configuración para test
        service.max_attempts = 3
        service.window_minutes = 10
        
        identifier = "config_test"
        
        # 3 intentos deben bloquear
        for _ in range(3):
            await service.record_failed_attempt(identifier)
        
        is_locked, _ = await service.is_locked(identifier)
        assert is_locked is True
        
        # Limpiar
        async with service._lock:
            service._memory_store.clear()


class TestRateLimitIntegration:
    """Tests de integración del rate limiting."""

    @pytest.fixture(autouse=True)
    async def cleanup(self):
        async with rate_limit_service._lock:
            rate_limit_service._memory_store.clear()
        yield
        async with rate_limit_service._lock:
            rate_limit_service._memory_store.clear()

    @pytest.mark.asyncio
    async def test_concurrent_attempts(self):
        """Verifica manejo de intentos concurrentes."""
        identifier = "concurrent_user"
        
        # Simular 5 intentos concurrentes
        tasks = [
            rate_limit_service.record_failed_attempt(identifier)
            for _ in range(5)
        ]
        results = await asyncio.gather(*tasks)
        
        # Al menos uno debe resultar en bloqueo
        locked_results = [r for r in results if r[1] is not None]
        assert len(locked_results) > 0