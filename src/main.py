# src/main.py
"""
Simulación de auditoría de seguridad en entorno cloud (Startup AWS Simulation)
Autor: Luis (proyecto educativo)

Ejemplo de uso:
  python src/main.py
  python src/main.py --config data/config_example.json
"""

import argparse
from tabulate import tabulate
from pathlib import Path

# Importaciones del proyecto
from cloud_simulator.iam import Policy, Role, User
from cloud_simulator.storage import Bucket, FileObject
from cloud_simulator.encryption import EncryptionManager
from cloud_simulator.audit import SecurityAudit
from cloud_simulator.pentest import CloudPentest
from cloud_simulator.config_loader import load_simulation_from_json


# ------------------------------------------------------------
# Función principal para ejecutar la simulación completa
# ------------------------------------------------------------
def run_full_simulation(config_file: str = None):
    """
    Ejecuta simulación completa.
    Si se pasa config_file, carga usuarios y buckets desde JSON.
    Retorna dict con objetos y resultados.
    """
    if config_file:
        print(f"\nCargando configuración desde: {config_file}\n")
        cfg = load_simulation_from_json(config_file)
        users = cfg["users"]
        buckets = cfg["buckets"]
    else:
        print("\nCargando configuración predeterminada...\n")
        # Configuración base por defecto
        admin_policy = Policy("allow_all_admin", "Allow", ["*"], ["*"])
        readonly_policy = Policy(
            "read_only_storage", "Allow",
            ["storage:GetObject", "storage:ListBucket"],
            ["arn:simulated:storage:bucket/*"]
        )

        admin_role = Role("AdminRole")
        admin_role.attach_policy(admin_policy)

        dev_role = Role("DevRole")
        dev_role.attach_policy(readonly_policy)

        user_admin = User("alice_admin", admin_role)
        user_dev = User("bob_dev", dev_role)
        users = [user_admin, user_dev]

        bucket_private = Bucket("startup-datos-privado", public=False)
        bucket_public = Bucket("startup-datos-publico", public=True)

        f1 = FileObject("clientes.csv", "nombre,correo\nLuis,luis@example.com", encrypted=False)
        f2 = FileObject("proyecto.txt", "Documentación técnica del proyecto", encrypted=False)
        bucket_private.upload_file(f1)
        bucket_public.upload_file(f2)
        buckets = [bucket_private, bucket_public]

    # -------------------------
    # Cifrado (simulado)
    # -------------------------
    enc_mgr = EncryptionManager()
    for b in buckets:
        for f in b.files:
            if not f.encrypted:
                token = enc_mgr.encrypt_data(f.content)
                f.content = token.decode() if isinstance(token, (bytes, bytearray)) else str(token)
                f.encrypted = True

    # -------------------------
    # Auditoría
    # -------------------------
    audit = SecurityAudit()
    audit.check_public_buckets(buckets)
    audit.check_admin_roles(users)
    findings = audit.findings

    # -------------------------
    # Pentest
    # -------------------------
    pentest = CloudPentest(users, buckets)
    pentest_results = pentest.run_all_tests()

    return {
        "users": users,
        "buckets": buckets,
        "findings": findings,
        "pentest_results": pentest_results,
    }


# ------------------------------------------------------------
# Función para mostrar resultados
# ------------------------------------------------------------
def print_simulation_results(results: dict):
    users = results["users"]
    buckets = results["buckets"]
    findings = results["findings"]
    pentest_results = results["pentest_results"]

    print("\n=== Simulación de Auditoría de Seguridad Cloud ===\n")

    # IAM
    table_iam = [(u.username, u.role.name, ", ".join(u.role.get_effective_permissions())) for u in users]
    print("Usuarios y roles IAM simulados:\n")
    print(tabulate(table_iam, headers=["Usuario", "Rol", "Permisos"], tablefmt="fancy_grid"))
    print("\n")

    # STORAGE
    table_storage = [(b.name, "PUBLIC" if b.public else "PRIVATE", f.name)
                     for b in buckets for f in b.files]
    print("Archivos cargados al almacenamiento simulado:\n")
    print(tabulate(table_storage, headers=["Bucket", "Acceso", "Archivo"], tablefmt="fancy_grid"))
    print("\n")

    # AUDITORÍA
    print("=== REPORTE DE AUDITORÍA DE SEGURIDAD (simulado) ===\n")
    if not findings:
        print("✅ No se detectaron vulnerabilidades.\n")
    else:
        for f in findings:
            riesgo = f.get("Riesgo") or f.get("risk") or f.get("nivel") or "N/A"
            tipo = f.get("Tipo") or f.get("type") or "Desconocido"
            recurso = f.get("Recurso") or f.get("recurso") or "Sin especificar"
            desc = f.get("Descripción") or f.get("descripcion") or f.get("detail") or ""
            print(f"- [{riesgo}] {tipo} -> {recurso}: {desc}")
        print()

    # PENTEST
    print("=== PRUEBAS DE PENETRACIÓN (simuladas) ===\n")
    pentable = [(r.get("Usuario", "-"),
                 r.get("Bucket", r.get("Acción", "-")),
                 r.get("Resultado", "-"),
                 r.get("Detalle", "-")) for r in pentest_results]
    print(tabulate(pentable, headers=["Usuario", "Recurso", "Resultado", "Detalle"], tablefmt="fancy_grid"))
    print()


# ------------------------------------------------------------
# CLI (Interfaz por línea de comandos)
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Simulación educativa de auditoría y pentest en entorno cloud (AWS simulado)."
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Ruta del archivo JSON con configuración personalizada (opcional)."
    )

    args = parser.parse_args()
    config_file = args.config

    if config_file:
        path = Path(config_file)
        if not path.is_file():
            print(f"❌ No se encontró el archivo de configuración: {config_file}")
            return

    results = run_full_simulation(config_file)
    print_simulation_results(results)


if __name__ == "__main__":
    main()
