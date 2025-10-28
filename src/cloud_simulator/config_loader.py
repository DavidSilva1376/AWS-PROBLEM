# src/cloud_simulator/config_loader.py
"""
Módulo para cargar configuraciones de simulación desde JSON.
Crea objetos de usuarios, roles, políticas, buckets y archivos a partir de un JSON.
"""

import json
from pathlib import Path
from typing import List, Dict, Any

from cloud_simulator.iam import Policy, Role, User
from cloud_simulator.storage import Bucket, FileObject


def load_simulation_from_json(json_path: str) -> Dict[str, Any]:
    """
    Carga un JSON con configuración de simulación y retorna:
    {
        "users": [...],
        "buckets": [...]
    }
    """
    path = Path(json_path)
    if not path.is_file():
        raise FileNotFoundError(f"Archivo de configuración no encontrado: {json_path}")

    with path.open("r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    # Primero, crear roles y políticas
    role_map: Dict[str, Role] = {}
    for u in cfg.get("users", []):
        role_name = u.get("role")
        if role_name not in role_map:
            role_map[role_name] = Role(role_name)
        role = role_map[role_name]
        # Adjuntar políticas
        for p in u.get("policies", []):
            policy_obj = Policy(
                name=p.get("name", "unnamed_policy"),
                effect=p.get("effect", "Allow"),
                actions=p.get("actions", []),
                resources=p.get("resources", [])
            )
            role.attach_policy(policy_obj)

    # Crear usuarios
    users: List[User] = []
    for u in cfg.get("users", []):
        role = role_map[u.get("role")]
        user_obj = User(username=u.get("username", "unknown"), role=role)
        users.append(user_obj)

    # Crear buckets y archivos
    buckets: List[Bucket] = []
    for b in cfg.get("buckets", []):
        bucket_obj = Bucket(name=b.get("name", "unnamed_bucket"), public=b.get("public", False))
        for f in b.get("files", []):
            file_obj = FileObject(
                filename=f.get("filename", "unnamed_file"),
                content=f.get("content", ""),
                encrypted=f.get("encrypted", False)
            )
            bucket_obj.upload_file(file_obj)
        buckets.append(bucket_obj)

    return {
        "users": users,
        "buckets": buckets
    }
