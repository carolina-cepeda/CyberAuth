# CyberAuth - Servicio de Autenticación

Servicio de autenticación seguro para aplicación de ciberseguridad que ayuda a personas y pequeños negocios en Colombia a identificar y reducir la exposición de sus datos personales en internet.

## Características

- **Registro seguro**: Validación de email único, contraseña robusta (mín 10 chars, 1 mayúscula, 1 número), aceptación obligatoria de política de datos (Ley 1581/2012)
- **Login protegido**: Rate limiting (5 intentos = 15 min bloqueo), hash Argon2, mensajes genéricos anti-enumeración
- **Sesiones JWT con Sliding Expiration**: Tokens con ventana de inactividad 30 min (renovable), tope absoluto 8h, revocación real por JTI (denylist), claims completos (iss, aud, sub, jti, iat, exp)
- **Auditoría completa**: Logs de registro, login, logout, bloqueos, expiraciones, revocaciones
- **Rendimiento**: Login < 1.5s (p95), registro+login < 2s

## Documentación de Decisiones

- **Bitácora de prompts y decisiones técnicas**: [`docs/PROMPT_LOG.md`](docs/PROMPT_LOG.md) - Trazabilidad de cada refinamiento, decisiones de seguridad, trade-offs y breaking changes.

## Requisitos

- Python 3.11+
- PostgreSQL 14+ (o SQLite para desarrollo)
- Redis 7+ (opcional, para rate limiting en producción)

## Instalación

```bash
# Clonar y entrar al directorio
cd cyberauth  # o el directorio donde clonaste el repo

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
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Ventana de inactividad (sliding) | 30 |
| `MAX_SESSION_LIFETIME_HOURS` | Tope absoluto de vida de sesión | 8 |
| `JWT_ISSUER` | Claim `iss` del token | CyberAuth |
| `JWT_AUDIENCE` | Claim `aud` del token | cyberauth-api |
| `MAX_FAILED_ATTEMPTS` | Intentos antes de bloqueo de cuenta | 5 |
| `ACCOUNT_LOCK_WINDOW_MINUTES` | Ventana de bloqueo de cuenta | 15 |
| `IP_RATE_LIMIT_MAX` | Max requests por IP por ventana | 100 |
| `IP_RATE_LIMIT_WINDOW_MINUTES` | Ventana rate limit IP | 15 |
| `REDIS_URL` | URL Redis (obligatorio en prod) | redis://localhost:6379/0 |
| `ALLOWED_ORIGINS` | CORS whitelist (coma-separado) | * |
| `TRUSTED_PROXY_IPS` | IPs de proxies de confianza para HTTPS enforcement | (vacío) |
| `POLICY_VERSION` | Versión de la política de privacidad | 1.0 |
| `APP_NAME` | Nombre de la aplicación | CyberAuth |
| `DEBUG` | Modo debug | false |
| `LOG_LEVEL` | Nivel de logging | INFO |

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

## Sesiones (Sliding Expiration)

El servicio implementa **expiración por inactividad real** (no expiración absoluta):

- **Ventana deslizante**: 30 minutos de inactividad. Cada request autenticada válida renueva la ventana (`last_activity = NOW()`, `expires_at = NOW() + 30min`).
- **Tope absoluto**: 8 horas (configurable vía `MAX_SESSION_LIFETIME_HOURS`) desde la creación de la sesión. Fuerza re-autenticación periódica.
- **Revocación real (denylist)**: `POST /api/v1/auth/logout` revoca la sesión por `jti`. El token queda invalidado inmediatamente aunque no haya expirado.
- **Claims JWT**: `iss` (CyberAuth), `aud` (cyberauth-api), `sub` (user_id), `jti` (UUID único por sesión), `iat`, `exp`.
- **Validación estricta**: Algoritmo fijado a HS256, rechaza `alg: none` y confusión de algoritmos.
- **Endpoints de sesión**:
  - `GET /api/v1/auth/sessions` — Lista sesiones activas del usuario actual
  - `DELETE /api/v1/auth/sessions/{jti}` — Revoca una sesión específica

## Tests

```bash
# Ejecutar todos los tests
pytest

# Con cobertura
pytest --cov=app --cov-report=term-missing

# Tests específicos
pytest tests/test_auth_service.py -v
pytest tests/test_api_auth.py -v
pytest tests/test_session_service.py -v
pytest tests/test_token_service.py -v
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

- **Hash de contraseñas**: Argon2id (memory-hard, resistente a GPU), calibrado para p95 < 1.5s, ejecutado en threadpool
- **Tokens JWT**: HS256, sliding expiration 30 min + tope absoluto 8h, claims completos (iss, aud, sub, jti, iat, exp), validación estricta de algoritmo
- **Rate limiting**: Por IP (Redis obligatorio en prod) y por cuenta (BD, atómico), headers `Retry-After`, configs separadas
- **Anti-enumeración**: Mismo código (401), mensaje y tiempo para usuario inexistente, contraseña incorrecta y cuenta bloqueada; dummy hash verification
- **HTTPS enforcement**: Middleware valida `X-Forwarded-Proto` / `Forwarded` (solo proxies en `TRUSTED_PROXY_IPS`), HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` en `/auth/*`
- **CORS**: Lista blanca explícita (`ALLOWED_ORIGINS`), no `*` en producción
- **Request ID**: Header `X-Request-ID` (UUID) en todas las respuestas para trazabilidad
- **Auditoría**: Tabla append-only (permisos BD: solo INSERT/SELECT), emails hasheados en logs, sin contraseñas ni tokens

## Cumplimiento Legal (Colombia)

- **Ley 1581/2012**: Protección de datos personales
- **Decreto 1377/2013**: Reglamentación parcial Ley 1581
- **Evidencia de autorización**: `policy_version`, `accepted_at` (UTC), `accepted_ip_hash`, `accepted_ua_hash` guardados en registro
- **Minimización**: `full_name` opcional (no requerido)
- **Derechos del titular implementados**:
  - `DELETE /api/v1/auth/account` — Eliminación de cuenta (requiere reautenticación + confirmación)
  - `GET /api/v1/auth/account/export` — Exportación de datos propios (JSON)
- **Auditoría inmutable**: Tabla `audit_logs` append-only (BD revoca UPDATE/DELETE para usuario de app), emails hasheados (SHA-256 + salt), sin PII sensible
- **Decisiones de seguridad y trade-offs**: Documentados en [`docs/PROMPT_LOG.md`](docs/PROMPT_LOG.md)
- **Limitaciones conocidas**: Documentadas en [`docs/PROMPT_LOG.md`](docs/PROMPT_LOG.md#riesgosnotas)

## Licencia

Proyecto interno - CyberAuth Team