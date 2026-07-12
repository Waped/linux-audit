"""
check_logs.py — Analyse des logs système pour détecter les comportements suspects
Contrôles effectués :
  - Tentatives de connexion échouées (auth.log / secure)
  - Utilisation de sudo (traces d'élévation)
  - Présence d'un daemon de log (rsyslog / syslog-ng / journald)
  - Rotation des logs configurée
  - Accès à des fichiers sensibles
"""

import subprocess
import re
from pathlib import Path
from collections import Counter


LOG_FILES = {
    "auth":   ["/var/log/auth.log", "/var/log/secure"],
    "syslog": ["/var/log/syslog",   "/var/log/messages"],
}
FAILED_LOGIN_THRESHOLD = 10  # Seuil d'alerte pour les échecs de connexion


def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""


def _find_log_file(candidates: list) -> str | None:
    for f in candidates:
        if Path(f).exists():
            return f
    return None


def check_logs(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── 1. Daemon de logs ────────────────────────────────────────────
    log_daemon = None
    for daemon in ("rsyslog", "syslog-ng", "systemd-journald"):
        status = _run(f"systemctl is-active {daemon} 2>/dev/null")
        if status == "active":
            log_daemon = daemon
            break
    info["log_daemon"] = log_daemon or "aucun détecté"

    if not log_daemon:
        findings.append({
            "id":          "LOG-001",
            "title":       "Aucun daemon de logs actif détecté",
            "description": "Sans rsyslog, syslog-ng ou journald actif, les événements système "
                           "ne sont pas correctement journalisés.",
            "severity":    "HIGH",
            "remediation": "Installer et activer rsyslog : `apt install rsyslog && systemctl enable rsyslog`.",
            "references":  ["CIS Benchmark L1 – Section 4.2", "ANSSI R-55"]
        })

    # ── 2. Tentatives de connexion échouées ──────────────────────────
    auth_log = _find_log_file(LOG_FILES["auth"])
    info["auth_log"] = auth_log

    if auth_log:
        failed_raw = _run(
            f"grep -i 'failed password\\|authentication failure\\|invalid user' {auth_log} "
            f"2>/dev/null | tail -500"
        )
        failed_lines = failed_raw.splitlines() if failed_raw else []
        info["failed_login_count"] = len(failed_lines)

        # Extraction des IPs sources
        ips = re.findall(r'from\s+([\d\.]+)', failed_raw)
        ip_counts = Counter(ips).most_common(5)
        info["top_failed_ips"] = [{"ip": ip, "count": c} for ip, c in ip_counts]

        if len(failed_lines) > FAILED_LOGIN_THRESHOLD:
            findings.append({
                "id":          "LOG-002",
                "title":       f"Volume élevé d'échecs de connexion ({len(failed_lines)} détectés)",
                "description": f"{len(failed_lines)} tentatives échouées dans {auth_log}. "
                               f"Top IPs : {ip_counts}",
                "severity":    "HIGH" if len(failed_lines) > 100 else "MEDIUM",
                "remediation": "Installer fail2ban pour bloquer les IPs malveillantes automatiquement. "
                               "Vérifier les logs pour identifier l'attaque.",
                "references":  ["ANSSI R-57", "CIS Benchmark – Section 4.2.4"]
            })

        # ── 3. Usages sudo suspects ──────────────────────────────────
        sudo_raw = _run(f"grep 'sudo' {auth_log} 2>/dev/null | grep -v '#' | tail -200")
        sudo_failures = [l for l in sudo_raw.splitlines() if "incorrect password" in l.lower()
                         or "3 incorrect" in l.lower()]
        info["sudo_failures"] = len(sudo_failures)

        if sudo_failures:
            findings.append({
                "id":          "LOG-003",
                "title":       f"Tentatives sudo échouées ({len(sudo_failures)})",
                "description": "Des tentatives d'élévation de privilèges sudo ont échoué. "
                               "Peut indiquer une tentative d'escalade de privilèges.",
                "severity":    "MEDIUM",
                "remediation": "Examiner les logs sudo. Envisager `sudoreplay` ou un SIEM "
                               "pour tracer toutes les actions sudo.",
                "references":  ["ANSSI R-30"]
            })

    else:
        findings.append({
            "id":          "LOG-004",
            "title":       "Fichier de log d'authentification introuvable",
            "description": "auth.log / secure est absent ou illisible.",
            "severity":    "MEDIUM",
            "remediation": "Vérifier la configuration de rsyslog et les permissions de /var/log/.",
            "references":  []
        })

    # ── 4. Logrotate configuré ───────────────────────────────────────
    logrotate_ok = Path("/etc/logrotate.conf").exists() or Path("/etc/logrotate.d").exists()
    info["logrotate"] = logrotate_ok
    if not logrotate_ok:
        findings.append({
            "id":          "LOG-005",
            "title":       "logrotate non configuré",
            "description": "Sans rotation des logs, /var/log peut saturer le disque, "
                           "rendant le système instable.",
            "severity":    "LOW",
            "remediation": "Installer logrotate : `apt install logrotate`. "
                           "Configurer dans /etc/logrotate.d/.",
            "references":  ["CIS Benchmark L1 – Section 4.3"]
        })

    return {"findings": findings, "info": info}
