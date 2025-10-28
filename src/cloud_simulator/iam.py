"""
Módulo: iam.py
Simula el sistema de gestión de identidad y acceso (IAM).

Permite crear usuarios, roles y políticas de acceso en formato JSON.
Estos objetos serán utilizados más adelante para auditar configuraciones inseguras.
"""

import json
from typing import List, Dict


class Policy:
    """
    Representa una política de acceso IAM simulada.
    """

    def __init__(self, name: str, effect: str, actions: List[str], resources: List[str]):
        self.name = name
        self.effect = effect  # "Allow" o "Deny"
        self.actions = actions
        self.resources = resources

    def to_dict(self) -> Dict:
        """Convierte la política a un diccionario."""
        return {
            "name": self.name,
            "effect": self.effect,
            "actions": self.actions,
            "resources": self.resources,
        }


class Role:
    """
    Representa un rol de IAM (conjunto de permisos).
    """

    def __init__(self, name: str):
        self.name = name
        self.policies: List[Policy] = []

    def attach_policy(self, policy: Policy):
        """Asigna una política al rol."""
        self.policies.append(policy)

    def get_effective_permissions(self) -> List[str]:
        """Devuelve una lista de acciones permitidas."""
        allowed = []
        for policy in self.policies:
            if policy.effect.lower() == "allow":
                allowed.extend(policy.actions)
        return list(set(allowed))  # elimina duplicados


class User:
    """
    Representa un usuario del sistema IAM.
    """

    def __init__(self, username: str, role: Role):
        self.username = username
        self.role = role

    def has_permission(self, action: str) -> bool:
        """Comprueba si el usuario tiene permiso para realizar cierta acción."""
        return action in self.role.get_effective_permissions()
