#!/usr/bin/env python3
"""
LinuxAudit - Outil d'audit de sécurité automatisé pour systèmes Linux
Auteur  : Jean Alioune Thiaw
Licence : MIT
Usage   : sudo python3 audit.py [--output DIR] [--format json|html|both]
"""

import argparse
import json
import os
import sys
import datetime
from pathlib import Path

# Modules de vérification thématiques
from modules.check_users    import check_users
from modules.check_network  import check_network
from modules.check_ssh      import check_ssh
from modules.check_logs     import check_logs
from modules.check_files    import check_files
from modules.check_services import check_services
from modules.check_passwords import check_passwords

# Générateur de rapport HTML
from reports.html_report import generate_html_report

# ─────────────────────────────────────────────
# Constantes de criticité
# ─────────────────────────────────────────────
SEVERITY_WEIGHT = {"HIGH": 10, "MEDIUM": 5, "LOW": 1}

BANNER = r"""
  _     _                  _                   _ _ _
 | |   (_)_ __  _   ___  _/ \  _   _  __| (_) |_
 | |   | | '_ \| | | \ \/ / _ \| | | |/ _` | | __|
 | |___| | | | | |_| |>  </ ___ \ |_| | (_| | | |_
 |_____|_|_| |_|\__,_/_/\_/_/   \_\__,_|\__,_|_|\__|
  Audit de Sécurité Linux  –  EFREI Mastère Cybersécurité
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit de sécurité automatisé pour systèmes Linux"
    )
    parser.add_argument(
        "--output", default="output",
        help="Répertoire de sortie des rapports (défaut : ./output)"
    )
    parser.add_argument(
        "--format", choices=["json", "html", "both"], default="both",
        help="Format du rapport de sortie"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Affiche les détails de chaque vérification"
    )
    return parser.parse_args()


def compute_score(findings: list[dict]) -> int:
    """
    Calcule un score de conformité sur 100.
    Chaque finding déduit des points selon sa criticité.
    Score minimum : 0.
    """
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    return max(0, 100 - penalty)


def run_audit(verbose: bool = False) -> dict:
    """
    Orchestre l'ensemble des modules de vérification.
    Retourne le rapport brut (dict) avant sérialisation.
    """
    timestamp = datetime.datetime.now().isoformat()
    hostname  = os.uname().nodename

    print(BANNER)
    print(f"  [*] Hôte    : {hostname}")
    print(f"  [*] Date    : {timestamp}")
    print(f"  [*] Utilisateur : {os.getenv('USER', 'unknown')}\n")

    # ── Définition des modules à exécuter ──────────────────────────────
    checks = [
        ("Utilisateurs & Sudo",      check_users),
        ("Réseau & Ports",           check_network),
        ("Configuration SSH",        check_ssh),
        ("Logs système",             check_logs),
        ("Fichiers sensibles",       check_files),
        ("Services actifs",          check_services),
        ("Politique mots de passe",  check_passwords),
    ]

    all_findings: list[dict] = []
    categories:  list[dict] = []

    for name, func in checks:
        print(f"  [+] Vérification : {name} ...", end=" ", flush=True)
        try:
            result = func(verbose=verbose)
            status = "OK" if not result["findings"] else f"{len(result['findings'])} finding(s)"
            print(status)
        except Exception as exc:
            print(f"ERREUR ({exc})")
            result = {
                "category": name,
                "findings": [{
                    "id":          "ERR-000",
                    "title":       f"Erreur d'exécution du module : {name}",
                    "description": str(exc),
                    "severity":    "HIGH",
                    "remediation": "Vérifier les droits d'exécution (sudo requis).",
                    "references":  []
                }],
                "info": {}
            }

        result["category"] = name
        all_findings.extend(result["findings"])
        categories.append(result)

    score = compute_score(all_findings)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f.get("severity", "LOW")] += 1

    report = {
        "meta": {
            "tool":      "LinuxAudit v1.0",
            "author":    "Jean Alioune Thiaw – EFREI Mastère Cybersécurité",
            "hostname":  hostname,
            "timestamp": timestamp,
            "os":        open("/etc/os-release").readline().strip() if Path("/etc/os-release").exists() else "Unknown"
        },
        "summary": {
            "score":          score,
            "total_findings": len(all_findings),
            "by_severity":    counts
        },
        "categories": categories
    }

    print(f"\n  ══════════════════════════════════════════")
    print(f"  Score de conformité : {score}/100")
    print(f"  Findings : {counts['HIGH']} HIGH  |  {counts['MEDIUM']} MEDIUM  |  {counts['LOW']} LOW")
    print(f"  ══════════════════════════════════════════\n")

    return report


def save_reports(report: dict, output_dir: str, fmt: str) -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt in ("json", "both"):
        json_path = Path(output_dir) / f"audit_{ts}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  [✓] Rapport JSON : {json_path}")

    if fmt in ("html", "both"):
        html_path = Path(output_dir) / f"audit_{ts}.html"
        html_content = generate_html_report(report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"  [✓] Rapport HTML : {html_path}")


def main() -> None:
    if os.geteuid() != 0:
        print("[!] Attention : certaines vérifications nécessitent les droits root.")
        print("    Relancer avec : sudo python3 audit.py\n")

    args   = parse_args()
    report = run_audit(verbose=args.verbose)
    save_reports(report, args.output, args.format)
    print("  Audit terminé.\n")


if __name__ == "__main__":
    main()
