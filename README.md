# CyberAuth - Servicio de Autenticación

Servicio de autenticación seguro para aplicación de ciberseguridad que ayuda a personas y pequeños negocios en Colombia a identificar y reducir la exposición de sus datos personales en internet.

## Características

- **Registro seguro**: Validación de email único, contraseña robusta (mín 10 chars, 1 mayúscula, 1 número), aceptación obligatoria de política de datos (Ley 1581/2012)
- **Login protegido**: Rate limiting (5 intentos = 15 min bloqueo), hash Argon2, mensajes genéricos anti-enumeración
- **Sesiones JWT**: Tokens con expiración 30 min, validación stateless
- **Auditoría completa**: Logs de registro, login, logout, bloqueos, expiraciones
- **Rendimiento**: Login < 1.5s (p95)

## Requisitos

- Python 3.11+
- PostgreSQL 14+ (o SQLite para desarrollo)
- Redis 7+ (opcional, para rate limiting en producción)

## Instalación

```bash
# Clonar y entrar al directorio
cd /home/karo/Documentos/ADA/Cyber

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores
```

## Configuración

Variables de entorno principales (ver `.env.example`):

| Variable | Descripción | Default |
|----------|-------------|---------|
| `DATABASE_URL` | URL de conexión PostgreSQL | Requerido |
| `SECRET_KEY` | Clave secreta para JWT (mín 32 chars) | Requerido |
| `ALGORITHM` | Algoritmo JWT | HS256 |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Expiración token | 30 |
| `MAX_FAILED_ATTEMPTS` | Intentos antes de bloqueo | 5 |
| `RATE_LIMIT_WINDOW_MINUTES` | Ventana de bloqueo | 15 |
| `REDIS_URL` | URL Redis para rate limiting | redis://localhost:6379/0 |

## Ejecución

### Desarrollo

```bash
# Con SQLite (no requiere PostgreSQL/Redis)
DATABASE_URL="sqlite+aiosqlite:///./auth.db" \
SECRET_KEY="dev-secret-key-change-in-production-min-32-chars" \
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Producción

```bash
# Con PostgreSQL y Redis
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

O con Docker:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## API Endpoints

### Registro
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "SecurePass123",
  "full_name": "Juan Pérez",
  "accept_privacy_policy": true
}
```

**Respuesta exitosa (201):**
```json
{
  "message": "Registro exitoso. Bienvenido a CyberAuth",
  "user_id": 1,
  "token": {
    "access_token": "eyJ...",
    "token_type": "bearer",
    "expires_in": 1800
  }
}
```

### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "SecurePass123"
}
```

**Respuesta exitosa (200):**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Logout
```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

### Validar Sesión
```http
GET /api/v1/auth/validate
Authorization: Bearer <token>
```

**Respuesta exitosa (200):**
```json
{
  "valid": true,
  "user_id": 1,
  "expires_at": "2024-01-01T12:30:00Z"
}
```

### Health Check
```http
GET /health
```

## Códigos de Error

| Código | HTTP | Descripción |
|--------|------|-------------|
| `VALIDATION_ERROR` | 400 | Datos de entrada inválidos |
| `VALIDATION_ERROR_PASSWORD` | 400 | Contraseña no cumple requisitos |
| `POLICY_NOT_ACCEPTED` | 400 | No aceptó política de datos |
| `AUTHENTICATION_FAILED` | 401 | Credenciales inválidas (genérico) |
| `INVALID_TOKEN` | 401 | Token malformado o firma inválida |
| `SESSION_EXPIRED` | 401 | Token expirado (30 min inactividad) |
| `ACCOUNT_LOCKED` | 423 | Cuenta bloqueada por intentos fallidos |
| `RATE_LIMIT_EXCEEDED` | 429 | Demasiadas peticiones |
| `REGISTRATION_FAILED` | 409 | Error en registro (genérico) |
| `INTERNAL_ERROR` | 500 | Error interno del servidor |

## Tests

```bash
# Ejecutar todos los tests
pytest

# Con cobertura
pytest --cov=app --cov-report=term-missing

# Tests específicos
pytest tests/test_auth_service.py -v
pytest tests/test_api_auth.py -v
```

## Estructura del Proyecto

```
app/
├── main.py                 # Entry point FastAPI
├── config.py               # Configuración (Pydantic Settings)
├── database.py             # Conexión BD (SQLAlchemy Async)
├── models/                 # Modelos ORM
│   ├── user.py
│   └── audit_log.py
├── schemas/                # Esquemas Pydantic (request/response)
│   ├── auth.py
│   └── user.py
├── services/               # Lógica de negocio
│   ├── auth_service.py     # Servicio principal
│   ├── password_service.py # Hash/validación contraseñas
│   ├── token_service.py    # JWT tokens
│   ├── rate_limit_service.py # Rate limiting
│   └── audit_service.py    # Logging auditoría
├── api/v1/                 # Rutas API
│   └── auth.py
├── core/                   # Utilidades core
│   ├── exceptions.py       # Excepciones personalizadas
│   └── security.py         # Helpers de seguridad
└── utils/                  # Utilidades varias
```

## Seguridad

- **Hash de contraseñas**: Argon2 (memory-hard, resistente a GPU)
- **Tokens JWT**: HS256, expiración 30 min, claims estándar
- **Rate limiting**: Por IP y por usuario, almacenamiento Redis/memoria
- **Mensajes genéricos**: No revelan si email existe
- **HTTPS obligatorio**: En producción usar TLS 1.2+
- **Auditoría**: Trazabilidad completa para cumplimiento

## Cumplimiento Legal (Colombia)

- **Ley 1581/2012**: Protección de datos personales
- **Decreto 1377/2013**: Reglamentación parcial Ley 1581
- Aceptación explícita de política de tratamiento
- Logs de auditoría inmutables
- Derecho al olvido: endpoint para eliminación (pendiente)

## Licencia

Proyecto interno - CyberAuth Team