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

Asegúrate de ejecutar desde la raíz del proyecto:
  python src/main.py
"""

from tabulate import tabulate

# Importaciones que coinciden con los archivos que ya tienes
from cloud_simulator.iam import Policy, Role, User
from cloud_simulator.storage import Bucket, FileObject
from cloud_simulator.encryption import EncryptionManager
from cloud_simulator.audit import SecurityAudit


def main():
    print("\n=== Simulación de Auditoría de Seguridad Cloud ===\n")

    # -------------------------
    # 1) Configuración IAM
    # -------------------------
    # Creamos políticas básicas
    admin_policy = Policy("allow_all_admin", "Allow", ["*"], ["*"])
    readonly_policy = Policy(
        "read_only_storage",
        "Allow",
        ["storage:GetObject", "storage:ListBucket"],
        ["arn:simulated:storage:bucket/*"],
    )

    # Creamos roles y les adjuntamos políticas
    admin_role = Role("AdminRole")
    admin_role.attach_policy(admin_policy)

    dev_role = Role("DevRole")
    dev_role.attach_policy(readonly_policy)  # ejemplo: solo lectura sobre storage

    # Creamos usuarios con roles
    user_admin = User("alice_admin", admin_role)
    user_dev = User("bob_dev", dev_role)

    users = [user_admin, user_dev]

    # Mostrar configuración IAM en tabla simple
    table_iam = []
    for u in users:
        perms = u.role.get_effective_permissions()
        table_iam.append((u.username, u.role.name, ", ".join(perms)))
    print("Usuarios y roles IAM simulados:\n")
    print(tabulate(table_iam, headers=["Usuario", "Rol", "Permisos"], tablefmt="fancy_grid"))
    print("\n")

    # -------------------------
    # 2) Configuración Storage
    # -------------------------
    # Creamos buckets (uno público para que la auditoría lo detecte)
    bucket_private = Bucket("startup-datos-privado", public=False)
    bucket_public = Bucket("startup-datos-publico", public=True)  # intencionalmente público para demo

    # Subimos archivos; marcamos uno como cifrado más abajo
    f1 = FileObject("clientes.csv", "nombre,correo\nLuis,luis@example.com", encrypted=False)
    f2 = FileObject("proyecto.txt", "Documentación técnica del proyecto", encrypted=False)
    bucket_private.upload_file(f1)
    bucket_public.upload_file(f2)

    buckets = [bucket_private, bucket_public]

    # Mostrar archivos por bucket
    table_storage = []
    for b in buckets:
        for fn in b.list_files():
            table_storage.append((b.name, "PUBLIC" if b.public else "PRIVATE", fn))
    print("Archivos cargados al almacenamiento simulado:\n")
    print(tabulate(table_storage, headers=["Bucket", "Acceso", "Archivo"], tablefmt="fancy_grid"))
    print("\n")

    # -------------------------
    # 3) Cifrado (simulado)
    # -------------------------
    enc_mgr = EncryptionManager()
    # ciframos el contenido del primer archivo en bucket privado y actualizamos su flag
    original = f1.content
    token = enc_mgr.encrypt_data(original)
    # guardamos el contenido cifrado (en este simulador lo guardamos como str del token)
    f1.content = token.decode() if isinstance(token, (bytes, bytearray)) else str(token)
    f1.encrypted = True

    # Demo de descifrado para verificar que funciona
    decrypted = enc_mgr.decrypt_data(token)

    print("Ejemplo de cifrado simulado (archivo 'clientes.csv'):")
    print(f"🔒 Encriptado (vista parcial): {str(token)[:60]}...")
    print(f"🔓 Desencriptado: {decrypted}\n")

    # -------------------------
    # 4) Auditoría
    # -------------------------
    audit = SecurityAudit()
    audit.check_public_buckets(buckets)
    audit.check_admin_roles(users)

    print("\n=== REPORTE DE AUDITORÍA DE SEGURIDAD (simulado) ===\n")
    audit.generate_report()

    # -------------------------
    # 5) Pentest Simulado
    # -------------------------
    from cloud_simulator.pentest import CloudPentest

    pentest = CloudPentest(users, buckets)
    results = pentest.run_all_tests()

    print("\n=== PRUEBAS DE PENETRACIÓN (simuladas) ===\n")
    # Note: usamos la importación de tabulate al inicio del archivo (no se re-importa aquí)
    table = [
        (
            r.get("Usuario", "-"),
            r.get("Bucket", r.get("Acción", "-")),
            r["Resultado"],
            r["Detalle"],
        )
        for r in results
    ]
    print(tabulate(table, headers=["Usuario", "Recurso", "Resultado", "Detalle"], tablefmt="fancy_grid"))


if __name__ == "__main__":
    main()

