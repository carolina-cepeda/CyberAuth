"""
Excepciones personalizadas para el servicio de autenticación.
Proporcionan códigos de error claros para la interfaz de usuario.
"""


class AuthError(Exception):
    """Excepción base para errores de autenticación."""
    
    def __init__(
        self,
        error_code: str,
        message: str,
        status_code: int = 400,
        details: str = None
    ):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)


class ValidationError(AuthError):
    """Error de validación de datos de entrada."""
    
    def __init__(self, message: str, field: str = None, details: str = None):
        error_code = "VALIDATION_ERROR"
        if field:
            error_code = f"VALIDATION_ERROR_{field.upper()}"
        super().__init__(error_code, message, 400, details)


class AuthenticationError(AuthError):
    """Error de autenticación (credenciales inválidas)."""
    
    def __init__(self, message: str = "Credenciales inválidas", details: str = None):
        super().__init__("AUTHENTICATION_FAILED", message, 401, details)


class AccountLockedError(AuthError):
    """Error por cuenta bloqueada."""
    
    def __init__(self, locked_until: str = None, details: str = None):
        message = "Cuenta temporalmente bloqueada por seguridad"
        if locked_until:
            message += f". Intente nuevamente después de {locked_until}"
        super().__init__("ACCOUNT_LOCKED", message, 423, details)


class AccountNotFoundError(AuthError):
    """Error cuando la cuenta no existe (mensaje genérico para seguridad)."""
    
    def __init__(self, details: str = None):
        # Mensaje genérico para no revelar si el email existe
        super().__init__(
            "AUTHENTICATION_FAILED",
            "Credenciales inválidas",
            401,
            details
        )


class SessionExpiredError(AuthError):
    """Error por sesión expirada."""
    
    def __init__(self, details: str = None):
        super().__init__(
            "SESSION_EXPIRED",
            "Su sesión ha expirado. Por favor, inicie sesión nuevamente",
            401,
            details
        )


class InvalidTokenError(AuthError):
    """Error por token inválido."""
    
    def __init__(self, message: str = "Token inválido o expirado", details: str = None):
        super().__init__("INVALID_TOKEN", message, 401, details)


class PolicyNotAcceptedError(AuthError):
    """Error por no aceptar política de privacidad."""
    
    def __init__(self, details: str = None):
        super().__init__(
            "POLICY_NOT_ACCEPTED",
            "Debe aceptar la política de tratamiento de datos (Ley 1581 de 2012) para registrarse",
            400,
            details
        )


class DuplicateEmailError(AuthError):
    """Error por email duplicado (mensaje genérico para seguridad)."""
    
    def __init__(self, details: str = None):
        super().__init__(
            "REGISTRATION_FAILED",
            "No se pudo completar el registro. Intente con otro correo",
            409,
            details
        )


class RateLimitExceededError(AuthError):
    """Error por exceso de intentos."""
    
    def __init__(self, retry_after: int = None, details: str = None):
        message = "Demasiados intentos. Intente más tarde"
        if retry_after:
            message += f" ({retry_after} segundos)"
        super().__init__("RATE_LIMIT_EXCEEDED", message, 429, details)