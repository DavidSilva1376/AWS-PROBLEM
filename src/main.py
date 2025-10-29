# src/main.py
"""
Simulación de auditoría de seguridad en entorno cloud (Startup AWS Simulation)
Autor: Luis (proyecto educativo)

Ejemplo de uso:
  python src/main.py
  python src/main.py --config data/config_example.json
  python src/main.py --menu
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
    Retorna (users, buckets).
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

    return users, buckets


# ------------------------------------------------------------
# Funciones individuales
# ------------------------------------------------------------
def run_audit(users, buckets):
    audit = SecurityAudit()
    audit.check_public_buckets(buckets)
    audit.check_admin_roles(users)
    return audit.findings


def run_pentest(users, buckets):
    pentest = CloudPentest(users, buckets)
    return pentest.run_all_tests()


# ------------------------------------------------------------
# Funciones para mostrar resultados
# ------------------------------------------------------------
def print_iam(users):
    table_iam = [(u.username, u.role.name, ", ".join(u.role.get_effective_permissions())) for u in users]
    print("\nUsuarios y roles IAM simulados:\n")
    print(tabulate(table_iam, headers=["Usuario", "Rol", "Permisos"], tablefmt="fancy_grid"))
    print()


def print_storage(buckets):
    table_storage = [(b.name, "PUBLIC" if b.public else "PRIVATE", f.name)
                     for b in buckets for f in b.files]
    print("Archivos cargados al almacenamiento simulado:\n")
    print(tabulate(table_storage, headers=["Bucket", "Acceso", "Archivo"], tablefmt="fancy_grid"))
    print()


def print_audit(findings):
    print("\n=== REPORTE DE AUDITORÍA DE SEGURIDAD (simulado) ===\n")
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


def print_pentest(pentest_results):
    print("=== PRUEBAS DE PENETRACIÓN (simuladas) ===\n")
    pentable = [(r.get("Usuario", "-"),
                 r.get("Bucket", r.get("Acción", "-")),
                 r.get("Resultado", "-"),
                 r.get("Detalle", "-")) for r in pentest_results]
    print(tabulate(pentable, headers=["Usuario", "Recurso", "Resultado", "Detalle"], tablefmt="fancy_grid"))
    print()


# ------------------------------------------------------------
# NUEVA FUNCIÓN: Reforzar seguridad (opción 6)
# ------------------------------------------------------------
def fix_security_issues(users, buckets):
    """
    Simula remediaciones:
      - Hace privados los buckets públicos (b.public = False)
      - Quita '*' de actions en las policies; si quedan vacías, añade 'restricted'
    Devuelve un dict con resumen de cambios.
    """
    fixed = {"buckets_fixed": [], "policies_fixed": []}

    # Arreglar buckets públicos
    for b in buckets:
        if getattr(b, "public", False):
            b.public = False
            fixed["buckets_fixed"].append(b.name)

    # Arreglar policies con '*'
    # Recorremos roles a través de usuarios (evita duplicados si varios usuarios comparten el mismo role)
    seen_roles = set()
    for u in users:
        role = getattr(u, "role", None)
        if not role:
            continue
        if role.name in seen_roles:
            continue
        seen_roles.add(role.name)
        for p in getattr(role, "policies", []):
            actions = getattr(p, "actions", [])
            if "*" in actions:
                # remover '*'
                new_actions = [a for a in actions if a != "*"]
                if not new_actions:
                    # si queda vacío, dejamos un marcador "restricted"
                    new_actions = ["restricted"]
                p.actions = new_actions
                fixed["policies_fixed"].append({"role": role.name, "policy": p.name, "new_actions": new_actions})

    # Mostrar resumen de remediaciones aplicadas
    print("\n🛠️  Remediaciones aplicadas (simuladas):\n")
    if fixed["buckets_fixed"]:
        print("Buckets cambiados a privado:")
        for bname in fixed["buckets_fixed"]:
            print(f" - {bname}")
    else:
        print(" - No se encontraron buckets públicos para corregir.")

    if fixed["policies_fixed"]:
        print("\nPolicies modificadas (se removió '*'):")
        for item in fixed["policies_fixed"]:
            print(f" - Role: {item['role']}, Policy: {item['policy']}, Nuevas acciones: {item['new_actions']}")
    else:
        print(" - No se encontraron policies con '*' para modificar.")

    # Mostrar estado posterior
    print("\n🔎 Estado posterior a las remediaciones:\n")
    print_storage(buckets)
    print_iam(users)

    return fixed


# ------------------------------------------------------------
# Menú interactivo
# ------------------------------------------------------------
def interactive_menu(users, buckets):
    while True:
        print("\n=== Menú de Simulación Cloud ===")
        print("[1] Ejecutar simulación completa")
        print("[2] Ejecutar solo auditoría")
        print("[3] Ejecutar solo pentest")
        print("[4] Mostrar usuarios y roles IAM")
        print("[5] Mostrar buckets y archivos")
        print("[6] Reforzar seguridad simulada")  # <-- nueva opción
        print("[0] Salir")

        option = input("\nSelecciona una opción: ").strip()

        if option == "1":
            print("\n🔍 Ejecutando simulación completa...\n")
            findings = run_audit(users, buckets)
            pentest_results = run_pentest(users, buckets)
            print_iam(users)
            print_storage(buckets)
            print_audit(findings)
            print_pentest(pentest_results)

        elif option == "2":
            print("\n🧾 Ejecutando solo auditoría...\n")
            findings = run_audit(users, buckets)
            print_audit(findings)

        elif option == "3":
            print("\n💥 Ejecutando solo pentest...\n")
            pentest_results = run_pentest(users, buckets)
            print_pentest(pentest_results)

        elif option == "4":
            print_iam(users)

        elif option == "5":
            print_storage(buckets)

        elif option == "6":
            print("\n🔧 Reforzando seguridad (simulado)...\n")
            fix_security_issues(users, buckets)

        elif option == "0":
            print("\n👋 Saliendo del simulador. ¡Hasta luego!\n")
            break
        else:
            print("❌ Opción no válida, intenta de nuevo.")


# ------------------------------------------------------------
# CLI (Interfaz por línea de comandos mejorada)
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Simulación educativa de auditoría y pentest en entorno cloud (AWS simulado)."
    )
    parser.add_argument("--config", type=str, help="Ruta del archivo JSON con configuración personalizada (opcional).")
    parser.add_argument("--menu", action="store_true", help="Inicia el modo interactivo de menú (opcional).")
    parser.add_argument("action", nargs="?", choices=["audit", "pentest", "full"], help="Acción rápida a ejecutar (opcional).")

    args = parser.parse_args()
    config_file = args.config

    # Validación del archivo
    if config_file:
        path = Path(config_file)
        if not path.is_file():
            print(f"❌ No se encontró el archivo de configuración: {config_file}")
            return

    # Cargar simulación
    users, buckets = run_full_simulation(config_file)

    # Modo menú
    if args.menu:
        interactive_menu(users, buckets)
        return

    # Acciones CLI directas
    if args.action == "audit":
        findings = run_audit(users, buckets)
        print_audit(findings)
        return

    elif args.action == "pentest":
        pentest_results = run_pentest(users, buckets)
        print_pentest(pentest_results)
        return

    elif args.action == "full":
        findings = run_audit(users, buckets)
        pentest_results = run_pentest(users, buckets)
        print_iam(users)
        print_storage(buckets)
        print_audit(findings)
        print_pentest(pentest_results)
        return

    # Si no hay flags ni acción => modo clásico
    findings = run_audit(users, buckets)
    pentest_results = run_pentest(users, buckets)
    print_iam(users)
    print_storage(buckets)
    print_audit(findings)
    print_pentest(pentest_results)


if __name__ == "__main__":
    main()

