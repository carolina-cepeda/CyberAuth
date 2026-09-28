import sys
import os

# Asegurar que el directorio raíz esté en el path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configurar variables de entorno ANTES de importar la app
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-minimum-32-characters-long")
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
os.environ.setdefault("RATE_LIMIT_WINDOW_MINUTES", "15")
os.environ.setdefault("MAX_FAILED_ATTEMPTS", "5")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("APP_NAME", "CyberAuth")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("LOG_LEVEL", "DEBUG")

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models.user import User, UserStatus
from app.models.audit_log import AuditLog, AuditAction
from app.services.password_service import password_service
from app.services.token_service import token_service
from app.services.rate_limit_service import rate_limit_service
from app.services.auth_service import AuthService
from app.schemas.auth import RegisterRequest, LoginRequest


# Base de datos en memoria para tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestAsyncSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def override_get_db():
    async with TestAsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    """Crea tablas antes de cada test y limpia después."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(autouse=True)
async def clear_rate_limit():
    """Limpia el store de rate limiting entre tests."""
    async with rate_limit_service._lock:
        rate_limit_service._memory_store.clear()
    yield
    async with rate_limit_service._lock:
        rate_limit_service._memory_store.clear()


@pytest_asyncio.fixture
async def client():
    """Cliente HTTP para tests de API."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def db_session():
    """Sesión de BD para tests directos de servicios."""
    async with TestAsyncSessionLocal() as session:
        yield session


@pytest.fixture
def valid_register_data():
    """Datos válidos para registro."""
    return {
        "email": "test@example.com",
        "password": "SecurePass123",
        "full_name": "Usuario Test",
        "accept_privacy_policy": True,
    }


@pytest.fixture
def valid_login_data():
    """Datos válidos para login."""
    return {
        "email": "test@example.com",
        "password": "SecurePass123",
    }