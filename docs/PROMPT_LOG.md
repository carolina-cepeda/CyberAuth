# Bitácora de Prompts y Decisiones - CyberAuth

Este documento registra los prompts principales, decisiones técnicas y razonamientos detrás de cada refinamiento implementado en el servicio de autenticación CyberAuth.

---

## Formato de Registro

Cada entrada sigue el formato:
- **Fecha**: YYYY-MM-DD
- **Refinamiento**: Número y título
- **Prompt/Objetivo**: Qué se pidió o qué problema se resolvió
- **Decisión Técnica**: Qué se implementó y por qué
- **Archivos Afectados**: Lista de archivos modificados
- **Tests**: Qué tests se añadieron/actualizaron
- **Breaking Changes**: Si aplica
- **Riesgos/Notas**: Consideraciones pendientes

---

## 2026-09-29 - Refinamiento 1: Sesión por Inactividad (Sliding Expiration) + JTI + Denylist

### Prompt/Objetivo
> "Implementa inactividad real: registra `last_activity` por sesión (jti) en Redis/BD y renueva la ventana de 30 min en cada petición válida (sliding expiration), con un tope absoluto configurable (p. ej. 8 h). Logout revoca la sesión (denylist por jti hasta su expiración). Claims: iss, aud, sub, iat, exp, jti. Fija el algoritmo al validar; rechaza 'none' y confusión de algoritmos. SECRET_KEY sin default y con validación de longitud al arrancar (falla rápido)."

### Decisión Técnica

1. **Claims JWT extendidos**: Añadidos `jti` (UUID4), `iss` (CyberAuth), `aud` (cyberauth-api), `iat`, `exp`. El `jti` identifica unívocamente cada sesión para poder revocarla.

2. **Almacenamiento de sesiones**: Nueva tabla `user_sessions` en PostgreSQL (para persistencia y auditoría) + caché en Redis para lectura rápida de `last_activity`. Campos: `id`, `user_id`, `jti`, `created_at`, `last_activity`, `expires_at`, `revoked`, `ip_address`, `user_agent`.

3. **Sliding Window (30 min)**: En cada request autenticada válida, se actualiza `last_activity = NOW()` y se extiende `expires_at = NOW() + 30 min` (tanto en BD como Redis). El token JWT original **no se re-emite**; el cliente sigue usando el mismo token. La validación consulta BD/Redis para verificar que la sesión no ha sido revocada y que `last_activity` no supera 30 min.

4. **Tope Absoluto (8h configurable)**: `MAX_SESSION_LIFETIME_HOURS` (default 8). Aunque se renueve la ventana de inactividad, la sesión expira forzosamente a las 8h desde `created_at`. Esto fuerza re-autenticación periódica.

5. **Denylist por JTI**: Logout marca `revoked = true` en BD y añade el `jti` a un set en Redis con TTL = tiempo restante hasta `expires_at`. Validación de token rechaza si `jti` está en denylist.

6. **Validación estricta de algoritmo**: `jwt.decode(..., algorithms=[ALGORITHM], options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]})`. Rechaza tokens sin algoritmo ("none") y confusión de algoritmos.

7. **SECRET_KEY sin default + validación**: `Settings.secret_key` es obligatorio (sin default). En `lifespan` startup se valida `len(secret_key) >= 32`; si no, `sys.exit(1)` con log claro.

8. **Threadpool para crypto**: Hash/verify de Argon2 y JWT encode/decode se ejecutan en `anyio.to_thread.run_sync` para no bloquear el event loop de FastAPI.

### Archivos Afectados

| Archivo | Cambio |
|---|---|
| `app/config.py` | Nuevas settings: `jwt_issuer`, `jwt_audience`, `max_session_lifetime_hours`, `secret_key` validation |
| `app/models/user_session.py` | Nuevo modelo `UserSession` (tabla `user_sessions`) |
| `app/models/__init__.py` | Exportar `UserSession` |
| `app/services/token_service.py` | Reescritura completa: create/validate con jti, iss, aud; threadpool; sliding check contra BD/Redis |
| `app/services/session_service.py` | Nuevo servicio: CRUD sesiones, sliding update, revocación, denylist Redis |
| `app/services/__init__.py` | Exportar `SessionService`, `session_service` |
| `app/services/auth_service.py` | `login`/`register` crean sesión; `logout` revoca; `validate_session` usa session_service |
| `app/api/v1/auth.py` | `logout` revoca sesión; nuevo endpoint `GET /sessions` (listar propias), `DELETE /sessions/{jti}` (revocar una) |
| `app/core/security.py` | Middleware `SecurityHeadersMiddleware` + HTTPS enforcement + request_id |
| `app/main.py` | Registrar middleware, validar SECRET_KEY en startup |
| `alembic/versions/...` | Migración inicial + tabla `user_sessions` + índices |
| `tests/test_session_service.py` | Tests nuevos: sliding window, tope absoluto, revocación, denylist, concurrencia |
| `tests/test_token_service.py` | Tests actualizados: claims nuevos, validación algoritmo, rechazo "none" |
| `tests/test_auth_service.py` | Tests actualizados: login crea sesión, logout revoca, validate_session consulta BD |
| `.env.example` | Nuevas variables documentadas |
| `README.md` | Sección "Sesiones (Sliding Expiration)" + mención a `docs/PROMPT_LOG.md` |

### Tests Añadidos/Actualizados

- `test_sliding_expiration_renews_window`: Login → wait 20 min → request → sesión válida, `last_activity` actualizado
- `test_sliding_expiration_expires_after_30min_inactivity`: Login → wait 31 min → request → 401 SESSION_EXPIRED
- `test_absolute_max_lifetime_8h`: Login → wait 8h+1min (con requests cada 20 min) → 401 SESSION_EXPIRED
- `test_logout_revokes_session_jti`: Login → logout → mismo token → 401 INVALID_TOKEN (revoked)
- `test_denylist_redis_ttl`: Logout → jti en Redis con TTL correcto
- `test_concurrent_sessions_same_user`: Usuario con 2 sesiones simultáneas, logout de una no afecta la otra
- `test_jwt_algorithm_confusion_rejected`: Token firmado con RS256 enviado a endpoint HS256 → rechazado
- `test_jwt_none_algorithm_rejected`: Token con `alg: none` → rechazado
- `test_secret_key_validation_startup`: SECRET_KEY < 32 chars → falla rápido en startup

### Breaking Changes

| Cambio | Impacto | Migración |
|---|---|---|
| Token JWT ahora incluye `jti`, `iss`, `aud` | Clientes que validen payload manualmente | Documentar nuevos claims; son opcionales para el cliente |
| `logout` revoca sesión real (no solo auditoría) | Comportamiento más seguro, compatible | Ninguna - mejora seguridad |
| Nuevo header `X-Request-ID` en todas las respuestas | Clientes pueden usarlo para tracing | Opcional, no rompe |

### Riesgos/Notas

- **Redis obligatorio en producción** para denylist y sliding window performante. En desarrollo funciona con BD sola (más lento).
- **Reloj sincronizado**: Sliding window depende de `datetime.utcnow()` consistente entre workers. Usar NTP.
- **Limpieza de sesiones expiradas**: Job periódico (cron/APScheduler) para borrar sesiones `revoked=true` y `expires_at < NOW()`.
- **Tamaño de token**: `jti` (36 chars) + claims extra ≈ +150 bytes por token. Aceptable.

---

## Próximas Entradas (Pendientes)

- [ ] Refinamiento 2: Bloqueo cuenta vs Rate limit IP (separados)
- [ ] Refinamiento 3: Anti-enumeración completa
- [ ] Refinamiento 4: Contraseñas y hashing (Argon2id calibrado, threadpool, NFKC)
- [ ] Refinamiento 5: Cumplimiento Ley 1581 (policy_version, derechos titular, auditoría inmutable)
- [ ] Refinamiento 6: HTTPS y cabeceras de seguridad
- [ ] Refinamiento 7: Contrato de errores (code, message, field, request_id)
- [ ] Refinamiento 8: Calidad y pruebas (Alembic, ruff, mypy, bandit, CI, coverage)
- [ ] Refinamiento 9: Operación y documentación (Dockerfile, compose, README final)

---

> **Nota**: Esta bitácora vive en `docs/PROMPT_LOG.md` y se actualiza con cada refinamiento. Sirve como trazabilidad de decisiones de seguridad para auditorías futuras.