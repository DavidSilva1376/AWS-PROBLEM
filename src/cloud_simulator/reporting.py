# src/cloud_simulator/reporting.py
"""
Módulo: reporting.py
Funciones para:
 - Guardar reportes de auditoría y pentest en JSON y TXT.
 - Calcular estadísticas básicas sobre hallazgos.
 - Aplicar remediaciones simuladas (hacer buckets privados, eliminar '*' de políticas).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Tipos de entrada esperados:
# findings: lista de dicts con keys 'type','resource','risk','description' (desde SecurityAudit.findings)
# pentest_results: lista de dicts con keys variadas (desde CloudPentest.results)


def _timestamp_str() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def save_report_json(
    findings: List[Dict[str, Any]],
    pentest_results: List[Dict[str, Any]],
    out_dir: str = "data",
    filename_prefix: str = "audit_report",
) -> str:
    """
    Guarda un JSON con los hallazgos y resultados del pentest.
    Devuelve la ruta del archivo guardado.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "pentest_results": pentest_results,
    }
    filename = f"{filename_prefix}_{_timestamp_str()}.json"
    path = Path(out_dir) / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return str(path.resolve())


def save_report_txt(
    findings: List[Dict[str, Any]],
    pentest_results: List[Dict[str, Any]],
    out_dir: str = "data",
    filename_prefix: str = "audit_report",
) -> str:
    """
    Guarda un archivo TXT legible con el resumen de hallazgos y resultados de pentest.
    Devuelve la ruta del archivo guardado.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{filename_prefix}_{_timestamp_str()}.txt"
    path = Path(out_dir) / filename
    lines = []
    lines.append("REPORTE DE AUDITORÍA (SIMULADO)")
    lines.append(f"Generado: {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("HALLAZGOS:")
    if not findings:
        lines.append("  - Ningún hallazgo detectado.")
    else:
        for i, f in enumerate(findings, start=1):
            lines.append(f"  {i}. Tipo: {f.get('type')}")
            lines.append(f"     Recurso: {f.get('resource')}")
            lines.append(f"     Riesgo: {f.get('risk')}")
            lines.append(f"     Descripción: {f.get('description')}")
            lines.append("")

    lines.append("")
    lines.append("RESULTADOS PENTEST:")
    if not pentest_results:
        lines.append("  - No se ejecutaron pruebas de pentest.")
    else:
        for i, r in enumerate(pentest_results, start=1):
            lines.append(f"  {i}. {r}")
    content = "\n".join(lines)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(content)
    return str(path.resolve())


def compute_findings_stats(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Calcula estadísticas simples: conteo total y por nivel de riesgo (Alta/Media/Baja/otros).
    Devuelve dict con keys 'total', 'Alta', 'Media', 'Baja', 'otros'.
    """
    stats = {"total": 0, "Alta": 0, "Media": 0, "Baja": 0, "otros": 0}
    for f in findings:
        stats["total"] += 1
        r = str(f.get("risk", "")).strip()
        if r.lower() == "alta":
            stats["Alta"] += 1
        elif r.lower() == "media":
            stats["Media"] += 1
        elif r.lower() == "baja":
            stats["Baja"] += 1
        else:
            stats["otros"] += 1
    return stats


def apply_remediations(users: List[Any], buckets: List[Any]) -> List[Tuple[str, str]]:
    """
    Aplica remediaciones simples y simuladas:
     - Pone 'public' = False en todos los buckets públicos (los hace privados).
     - Elimina la acción '*' de políticas (lo reemplaza por 'restricted' como marcador) para roles/policies.
    Devuelve una lista de tuplas (tipo_remediacion, descripcion).
    """
    applied = []

    # Remediar buckets públicos
    for b in buckets:
        if getattr(b, "public", False):
            b.public = False
            applied.append(("bucket_privacy", f"Bucket {b.name} cambiado a privado."))

    # Remediar policies con '*'
    # Asumimos que usuarios tienen .role y role.policies (lista de Policy)
    for u in users:
        role = getattr(u, "role", None)
        if not role:
            continue
        policies = getattr(role, "policies", [])
        for p in policies:
            actions = getattr(p, "actions", [])
            if "*" in actions:
                # Eliminamos '*' y añadimos un placeholder para indicar restricción aplicada
                new_actions = [a for a in actions if a != "*"]
                # si queda vacío, añadimos un marcador 'restricted' para que la política no quede vacía
                if not new_actions:
                    new_actions = ["restricted"]
                p.actions = new_actions
                applied.append(("policy_reduced", f"Policy {p.name} en role {role.name} modificada: '*' removido."))

    return applied
