"""
Servicio de gestión de contraseñas usando Argon2 (recomendado) con fallback a bcrypt.
Cumple con requisitos de seguridad: hash lento, salt único, resistencia a GPU.
"""
from passlib.context import CryptContext
from passlib.hash import argon2, bcrypt
import re


class PasswordService:
    """
    Servicio para hashear y verificar contraseñas de forma segura.
    Usa Argon2 como algoritmo principal (ganador de Password Hashing Competition).
    """

    def __init__(self):
        # Configuración Argon2: memory_cost=65536 KB (64MB), time_cost=3, parallelism=4
        # Estos valores balancean seguridad y rendimiento (<1.5s login p95)
        self.pwd_context = CryptContext(
            schemes=["argon2", "bcrypt"],
            default="argon2",
            argon2__memory_cost=65536,
            argon2__time_cost=3,
            argon2__parallelism=4,
            argon2__hash_len=32,
            argon2__salt_size=16,
            bcrypt__rounds=12,
            deprecated="auto",
        )

    def hash_password(self, password: str) -> str:
        """
        Genera un hash seguro de la contraseña.
        
        Args:
            password: Contraseña en texto plano
            
        Returns:
            Hash de la contraseña (incluye algoritmo, salt y parámetros)
        """
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifica una contraseña contra su hash.
        Tiempo constante para prevenir ataques de temporización.
        
        Args:
            plain_password: Contraseña en texto plano
            hashed_password: Hash almacenado en BD
            
        Returns:
            True si la contraseña coincide
        """
        return self.pwd_context.verify(plain_password, hashed_password)

    def check_password_strength(self, password: str) -> tuple[bool, list[str]]:
        """
        Valida la fortaleza de la contraseña según políticas de negocio.
        
        Reglas:
        - Mínimo 10 caracteres
        - Al menos una mayúscula
        - Al menos un número
        
        Args:
            password: Contraseña a validar
            
        Returns:
            Tupla (es_válida, lista_de_errores)
        """
        errors = []
        
        if len(password) < 10:
            errors.append("La contraseña debe tener al menos 10 caracteres")
        
        if not any(c.isupper() for c in password):
            errors.append("La contraseña debe contener al menos una mayúscula")
        
        if not any(c.isdigit() for c in password):
            errors.append("La contraseña debe contener al menos un número")
        
        # Validaciones adicionales de seguridad
        if len(password) > 128:
            errors.append("La contraseña no puede exceder 128 caracteres")
        
        # Verificar patrones comunes débiles
        common_patterns = [
            r"(.)\1{3,}",  # 4+ caracteres repetidos
            r"123456|abcdef|qwerty|password|admin",  # Patrones comunes
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                errors.append("La contraseña contiene patrones predecibles")
                break
        
        return len(errors) == 0, errors

    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Verifica si el hash necesita actualizarse (algoritmo obsoleto o parámetros débiles).
        
        Args:
            hashed_password: Hash almacenado
            
        Returns:
            True si se debe rehashear en el próximo login
        """
        return self.pwd_context.needs_update(hashed_password)

    def identify_hash(self, hashed_password: str) -> str:
        """
        Identifica el algoritmo usado en el hash.
        
        Returns:
            Nombre del algoritmo (argon2, bcrypt, etc.)
        """
        return self.pwd_context.identify(hashed_password)


# Instancia singleton
password_service = PasswordService()