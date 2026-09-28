"""
Punto de entrada principal de la aplicación CyberAuth.
Servicio de autenticación para aplicación de ciberseguridad en Colombia.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import logging

from app.config import get_settings
from app.database import init_db, engine
from app.api import api_router
from app.core.exceptions import AuthError
from app.core.security import create_generic_error_response


settings = get_settings()

# Configurar logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestión del ciclo de vida de la aplicación."""
    # Startup
    logger.info(f"Iniciando {settings.app_name}...")
    await init_db()
    logger.info("Base de datos inicializada")
    
    yield
    
    # Shutdown
    logger.info(f"Cerrando {settings.app_name}...")
    await engine.dispose()
    logger.info("Conexiones cerradas")


app = FastAPI(
    title=settings.app_name,
    description="Servicio de Autenticación - Aplicación de Ciberseguridad para Colombia",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)

# CORS para desarrollo (restringir en producción)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["https://tudominio.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware para logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = __import__("time").time()
    
    response = await call_next(request)
    
    process_time = __import__("time").time() - start_time
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.3f}s"
    )
    
    # Header de tiempo de respuesta
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Manejador global de excepciones de auth
@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(
        status_code=exc.status_code,
        content=create_generic_error_response(exc),
    )


# Manejador para errores de validación de Pydantic
@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    if not errors:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error_code": "VALIDATION_ERROR", "message": "Datos de entrada inválidos"},
        )
    
    # Mapear errores comunes a códigos de error
    first_error = errors[0]
    loc = first_error.get("loc", [])
    msg = first_error.get("msg", "")
    error_type = first_error.get("type", "")
    
    # Determinar campo
    field = loc[-1] if loc else "unknown"
    
    # Mapear tipos de error
    if error_type == "string_too_short" and field == "password":
        error_code = "VALIDATION_ERROR_PASSWORD"
        message = "La contraseña debe tener al menos 10 caracteres"
    elif error_type == "value_error" and "mayúscula" in msg:
        error_code = "VALIDATION_ERROR_PASSWORD"
        message = "La contraseña debe contener al menos una mayúscula"
    elif error_type == "value_error" and "número" in msg:
        error_code = "VALIDATION_ERROR_PASSWORD"
        message = "La contraseña debe contener al menos un número"
    elif error_type == "value_error" and "política" in msg:
        error_code = "POLICY_NOT_ACCEPTED"
        message = "Debe aceptar la política de tratamiento de datos (Ley 1581 de 2012)"
    elif error_type == "value_error" and "email" in msg.lower():
        error_code = "VALIDATION_ERROR_EMAIL"
        message = "Formato de email inválido"
    else:
        error_code = f"VALIDATION_ERROR_{field.upper()}"
        message = f"Campo '{field}': {msg}"
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error_code": error_code, "message": message},
    )


# Health check
@app.get("/health", tags=["Salud"], summary="Verificar estado del servicio")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": "1.0.0"
    }


# Incluir rutas de API
app.include_router(api_router)


# Root endpoint
@app.get("/", tags=["Raíz"], summary="Información del servicio")
async def root():
    return {
        "service": settings.app_name,
        "description": "Servicio de Autenticación para App de Ciberseguridad Colombia",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )