"""
Módulo: audit.py
Simula un sistema de auditoría de seguridad sobre el entorno cloud.
Detecta configuraciones inseguras, permisos excesivos o buckets públicos.
"""

from typing import List, Dict
from tabulate import tabulate


class SecurityAudit:
    """
    Revisa los elementos simulados y genera reportes de vulnerabilidades.
    """

    def __init__(self):
        self.findings: List[Dict] = []

    def check_public_buckets(self, buckets: List):
        """Detecta buckets con acceso público."""
        for bucket in buckets:
            if getattr(bucket, "public", False):
                self.findings.append(
                    {
                        "type": "Public Bucket",
                        "resource": bucket.name,
                        "risk": "Alta",
                        "description": "El bucket es público y puede exponer datos sensibles.",
                    }
                )

    def check_admin_roles(self, users: List):
        """Detecta usuarios con permisos administrativos amplios."""
        for user in users:
            perms = user.role.get_effective_permissions()
            if "*" in perms:
                self.findings.append(
                    {
                        "type": "Permisos excesivos",
                        "resource": user.username,
                        "risk": "Alta",
                        "description": "El usuario tiene permisos de administrador global.",
                    }
                )

    def generate_report(self):
        """Muestra las vulnerabilidades encontradas en formato tabla."""
        if not self.findings:
            print("✅ No se detectaron vulnerabilidades.")
            return

        print("\n=== REPORTE DE AUDITORÍA DE SEGURIDAD ===\n")
        headers = ["Tipo", "Recurso", "Riesgo", "Descripción"]
        table = [
            [f["type"], f["resource"], f["risk"], f["description"]]
            for f in self.findings
        ]
        print(tabulate(table, headers=headers, tablefmt="fancy_grid"))
