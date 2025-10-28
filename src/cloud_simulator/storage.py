"""
Módulo: storage.py
Simula un servicio de almacenamiento en la nube (como Amazon S3).

Permite crear buckets, subir archivos y controlar su nivel de acceso (privado/público).
"""

from typing import List, Dict


class FileObject:
    """
    Representa un archivo dentro de un bucket simulado.
    """

    def __init__(self, name: str, content: str, encrypted: bool = False):
        self.name = name
        self.content = content
        self.encrypted = encrypted


class Bucket:
    """
    Representa un bucket de almacenamiento.
    """

    def __init__(self, name: str, public: bool = False):
        self.name = name
        self.public = public
        self.files: List[FileObject] = []

    def upload_file(self, file: FileObject):
        """Sube un archivo al bucket."""
        self.files.append(file)

    def list_files(self) -> List[str]:
        """Devuelve una lista de nombres de archivos en el bucket."""
        return [f.name for f in self.files]

    def get_file(self, filename: str) -> Dict:
        """Obtiene información de un archivo por su nombre."""
        for f in self.files:
            if f.name == filename:
                return {"name": f.name, "encrypted": f.encrypted}
        return {"error": "Archivo no encontrado"}
