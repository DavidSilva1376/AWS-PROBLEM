# src/main.py
"""
Simulación de auditoría de seguridad en entorno cloud (Startup AWS Simulation)
Autor: Luis (proyecto educativo)

Este archivo usa los módulos que ya creaste en:
  src/cloud_simulator/iam.py
  src/cloud_simulator/storage.py
  src/cloud_simulator/encryption.py
  src/cloud_simulator/audit.py
  src/cloud_simulator/pentest.py
  src/cloud_simulator/reporting.py  <- nuevo

Asegúrate de ejecutar desde la raíz del proyecto:
  python src/main.py
"""

from tabulate import tabulate
from cloud_simulator.iam import Policy, Role, User
from cloud_simulator.storage import Bucket, FileObject
from cloud_simulator.encryption import EncryptionManager
from cloud_simulator.audit import SecurityAudit
from cloud_simulator.pentest import CloudPentest
from cloud_simulator import reporting
from cloud_simulator.config_loader import load_simulation_from_json


def run_full_simulation(config_file: str = None):
    """
    Ejecuta simulación completa.
    Si se pasa config_file, carga usuarios y buckets desde JSON.
    Retorna dict con objetos y resultados.
    """
    if config_file:
        cfg = load_simulation_from_json(config_file)
        users = cfg["users"]
        buckets = cfg["buckets"]
    else:
        # Default hardcoded setup anterior
        admin_policy = Policy("allow_all_admin", "Allow", ["*"], ["*"])
        readonly_policy = Policy("read_only_storage", "Allow", ["storage:GetObject", "storage:ListBucket"], ["arn:simulated:storage:bucket/*"])

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

    # Cifrado del primer archivo de cada bucket privado
    enc_mgr = EncryptionManager()
    for b in buckets:
        for fn in b.list_files():
            f = b.files[fn]
            if not f.encrypted:
                token = enc_mgr.encrypt_data(f.content)
                f.content = token.decode() if isinstance(token, (bytes, bytearray)) else str(token)
                f.encrypted = True

    # Auditoría
    audit = SecurityAudit()
    audit.check_public_buckets(buckets)
    audit.check_admin_roles(users)
    findings = audit.findings

    # Pentest
    pentest = CloudPentest(users, buckets)
    pentest_results = pentest.run_all_tests()

    return {
        "users": users,
        "buckets": buckets,
        "findings": findings,
        "pentest_results": pentest_results,
    }



def pretty_print_simulation(sim):
    """
    Imprime en consola la configuración actual y los resultados.
    'sim' es el dict retornado por run_full_simulation o una re-ejecución.
    """
    users = sim["users"]
    buckets = sim["buckets"]
    findings = sim["findings"]
    pentest_results = sim["pentest_results"]

    # IAM
    table_iam = []
    for u in users:
        perms = u.role.get_effective_permissions()
        table_iam.append((u.username, u.role.name, ", ".join(perms)))
    print("\nUsuarios y roles IAM simulados:\n")
    print(tabulate(table_iam, headers=["Usuario", "Rol", "Permisos"], tablefmt="fancy_grid"))
    print("\n")

    # Storage
    table_storage = []
    for b in buckets:
        for fn in b.list_files():
            table_storage.append((b.name, "PUBLIC" if b.public else "PRIVATE", fn))
    print("Archivos cargados al almacenamiento simulado:\n")
    print(tabulate(table_storage, headers=["Bucket", "Acceso", "Archivo"], tablefmt="fancy_grid"))
    print("\n")

    # Auditoría
    print("=== REPORTE DE AUDITORÍA DE SEGURIDAD (simulado) ===\n")
    if findings:
        for f in findings:
            print(f"- [{f.get('risk')}] {f.get('type')} -> {f.get('resource')}: {f.get('description')}")
    else:
        print("✅ No se detectaron vulnerabilidades.")
    print("\n")

    # Pentest (tabla)
    if pentest_results:
        print("=== PRUEBAS DE PENETRACIÓN (simuladas) ===\n")
        table = [
            (
                r.get("Usuario", "-"),
                r.get("Bucket", r.get("Acción", "-")),
                r["Resultado"],
                r["Detalle"],
            )
            for r in pentest_results
        ]
        print(tabulate(table, headers=["Usuario", "Recurso", "Resultado", "Detalle"], tablefmt="fancy_grid"))
        print("\n")


def interactive_menu(sim_state):
    """
    Menú interactivo simple en consola:
      1) Mostrar estadísticas de hallazgos
      2) Guardar reporte (JSON + TXT)
      3) Aplicar remediaciones simuladas y re-ejecutar auditoría/pentest
      4) Salir
    """
    while True:
        print("\n--- Menú ---")
        print("1) Mostrar estadísticas de hallazgos")
        print("2) Guardar reporte (JSON + TXT) en carpeta 'data/'")
        print("3) Aplicar remediaciones simuladas y re-ejecutar auditoría/pentest")
        print("4) Salir")
        choice = input("Selecciona una opción (1-4): ").strip()
        if choice == "1":
            stats = reporting.compute_findings_stats(sim_state["findings"])
            print("\nEstadísticas de hallazgos:")
            for k, v in stats.items():
                print(f"  {k}: {v}")
        elif choice == "2":
            json_path = reporting.save_report_json(sim_state["findings"], sim_state["pentest_results"])
            txt_path = reporting.save_report_txt(sim_state["findings"], sim_state["pentest_results"])
            print(f"\nReportes guardados:\n - {json_path}\n - {txt_path}")
        elif choice == "3":
            print("\nAplicando remediaciones simuladas...")
            applied = reporting.apply_remediations(sim_state["users"], sim_state["buckets"])
            if applied:
                for t, desc in applied:
                    print(f" - {t}: {desc}")
            else:
                print(" - No se aplicaron remediaciones (estado ya seguro o no hay elementos a modificar).")

            # Re-ejecutar auditoría y pentest sobre el estado actual
            print("\nRe-ejecutando auditoría y pentest sobre el estado remediado...")
            # reusar SecurityAudit y CloudPentest con los mismos objetos (users, buckets)
            audit = SecurityAudit()
            audit.check_public_buckets(sim_state["buckets"])
            audit.check_admin_roles(sim_state["users"])
            pentest = CloudPentest(sim_state["users"], sim_state["buckets"])
            new_findings = audit.findings
            new_pentest = pentest.run_all_tests()
            sim_state["findings"] = new_findings
            sim_state["pentest_results"] = new_pentest
            print("Re-ejecución completada. Nuevos resultados impresos abajo:")
            pretty_print_simulation(sim_state)
        elif choice == "4":
            print("Saliendo. ¡Hasta luego!")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")


def main():
    print("\n=== Simulación de Auditoría de Seguridad Cloud ===")
    state = run_full_simulation()
    pretty_print_simulation(state)

    # Menú interactivo para guardar reportes, ver stats y aplicar remediaciones
    interactive_menu(state)


if __name__ == "__main__":
    main()
