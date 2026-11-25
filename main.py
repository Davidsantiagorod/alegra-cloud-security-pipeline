#!/usr/bin/env python3
"""vuln-pipeline — triage, priorizacion y remediacion de vulnerabilidades (Linux).

Ejemplos:
  python main.py                         # 6 ejemplos del reto, IA en modo mock (offline)
  python main.py --include-extra         # + casos propios (N/A legitimo, SAST, kernel)
  python main.py --llm compromised       # simula un LLM que obedece la injection -> guardrails
  python main.py --llm gemini            # Gemini API real (requiere GEMINI_API_KEY)
  python main.py --gate                  # modo CI: exit 2 si hay P1/P2 accionables
  python main.py --verify-audit          # verifica integridad del log de auditoria
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pipeline.actions import console_table, write_action_artifacts, write_reports
from pipeline.audit import verify
from pipeline.engine import run
from pipeline.policy import evaluate_gate

ROOT = Path(__file__).resolve().parent


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Pipeline de vulnerabilidades - Alegra")
    p.add_argument("--input", nargs="+", type=Path, default=[ROOT / "data" / "findings.json"])
    p.add_argument("--include-extra", action="store_true", help="agrega data/extra_findings.json")
    p.add_argument("--inventory", type=Path, default=ROOT / "data" / "asset_inventory.json")
    p.add_argument("--intel", type=Path, default=ROOT / "data" / "threat_intel.json")
    p.add_argument("--out", type=Path, default=ROOT / "output")
    p.add_argument("--llm", choices=["off", "mock", "gemini", "compromised"], default="mock")
    p.add_argument("--gate", action="store_true", help="modo CI: falla si hay P1/P2 accionables")
    p.add_argument("--baseline", type=Path, default=None,
                   help="report.json previo: con --gate solo bloquea P1/P2 nuevos o agravados")
    p.add_argument("--verify-audit", action="store_true")
    args = p.parse_args(argv)

    if args.verify_audit:
        ok, msg = verify(args.out / "audit.jsonl")
        print(("OK  " if ok else "FAIL ") + msg)
        return 0 if ok else 1

    inputs = list(args.input)
    if args.include_extra:
        inputs.append(ROOT / "data" / "extra_findings.json")

    result = run(inputs, args.inventory, args.intel, args.out, llm=args.llm)
    write_action_artifacts(result["decisions"], args.out)
    write_reports(result, args.out)

    print(f"\nvuln-pipeline · run {result['run_id']} · IA: {args.llm}\n")
    print(console_table(result["decisions"]))
    if result["errors"]:
        print("\nErrores de ingesta:", *result["errors"], sep="\n - ")
    alerts = [d for d in result["decisions"] if "tampering_suspected" in d.flags]
    for d in alerts:
        print(f"\n[!] {d.group_id}: posible prompt injection en el advisory -> ignorada, "
              f"prioridad mantenida en {d.priority}, alerta a AppSec.")
    rejected = [d for d in result["decisions"]
                if {"llm_downgrade_rejected", "llm_missed_injection", "llm_hallucinated_version"} & set(d.flags)]
    for d in rejected:
        bad = sorted({"llm_downgrade_rejected", "llm_missed_injection", "llm_hallucinated_version"} & set(d.flags))
        print(f"[!] {d.group_id}: guardrails rechazaron salida del LLM: {', '.join(bad)}")

    print(f"\nReporte: {args.out / 'report.md'} · Acciones: {args.out / 'actions'} · "
          f"Auditoria: {result['audit_path']}")

    if args.gate:
        blocking, suppressed = evaluate_gate(result["decisions"], args.baseline)
        if blocking:
            mode_lbl = "diferencial vs baseline" if args.baseline else "estricto"
            print(f"\nGATE ({mode_lbl}): FALLA — {len(blocking)} hallazgo(s) P1/P2 bloqueantes: "
                  + ", ".join(d.group_id for d in blocking))
            return 2
        extra_msg = f" ({suppressed} P1/P2 preexistentes en baseline siguen su SLA)" if suppressed else ""
        print(f"\nGATE: OK{extra_msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
