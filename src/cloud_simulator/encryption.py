"""
Módulo: encryption.py
Simula operaciones de cifrado y descifrado de datos.
Utiliza la biblioteca 'cryptography' para imitar cifrado en reposo o en tránsito.
"""

from cryptography.fernet import Fernet


class EncryptionManager:
    """
    Gestiona la generación de claves, cifrado y descifrado de datos.
    """

    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt_data(self, data: str) -> bytes:
        """Cifra una cadena de texto."""
        return self.cipher.encrypt(data.encode())

    def decrypt_data(self, token: bytes) -> str:
        """Descifra una cadena cifrada."""
        return self.cipher.decrypt(token).decode()

    def get_key(self) -> bytes:
        """Devuelve la clave de cifrado actual."""
        return self.key
