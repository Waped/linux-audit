"""
check_services.py — Vérification des services actifs et potentiellement dangereux
Contrôles effectués :
  - Services inutiles ou dangereux activés
  - Services en écoute sur toutes les interfaces
  - Présence de services de sécurité recommandés
"""

import subprocess
from pathlib import Path


DANGEROUS_SERVICES = {
    "telnet":       ("HIGH",   "Protocole non chiffré, remplacé par SSH."),
    "ftp":          ("HIGH",   "FTP transmet identifiants en clair. Utiliser SFTP."),
    "rsh":          ("HIGH",   "Remote Shell non chiffré et authentification faible."),
    "rlogin":       ("HIGH",   "Remote Login non chiffré."),
    "rexec":        ("HIGH",   "Remote Exec non chiffré."),
    "tftp":         ("HIGH",   "TFTP sans authentification."),
    "nis":          ("MEDIUM", "NIS (Yellow Pages) : protocole obsolète et peu sécurisé."),
    "chargen":      ("MEDIUM", "Générateur de caractères, inutile en production."),
    "daytime":      ("LOW",    "Service daytime inutile."),
    "discard":      ("LOW",    "Service discard inutile."),
    "echo":         ("LOW",    "Service echo inutile."),
    "time":         ("LOW",    "Service time inutile."),
    "snmpd":        ("MEDIUM", "SNMP v1/v2 transmet les community strings en clair."),
    "xinetd":       ("LOW",    "Super-daemon obsolète. Préférer systemd socket activation."),
    "avahi-daemon": ("LOW",    "mDNS/DNS-SD : divulgue des informations sur le réseau local."),
    "cups":         ("LOW",    "Service d'impression inutile sur un serveur."),
    "nfs":          ("MEDIUM", "NFS expose le système de fichiers réseau."),
    "rpcbind":      ("MEDIUM", "Portmapper RPC, nécessaire pour NFS/NIS mais exposé."),
}

RECOMMENDED_SECURITY_SERVICES = {
    "fail2ban":   "Blocage automatique des IPs malveillantes.",
    "auditd":     "Journalisation des appels système (audit Linux).",
    "apparmor":   "Confinement des processus (MAC).",
    "clamav":     "Antivirus open-source.",
    "aide":       "Détection d'intrusion basée sur les fichiers (HIDS).",
}


def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def _service_active(name: str) -> bool:
    status = _run(f"systemctl is-active {name} 2>/dev/null")
    return status == "active"


def _service_enabled(name: str) -> bool:
    status = _run(f"systemctl is-enabled {name} 2>/dev/null")
    return status in ("enabled", "static")


def check_services(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── 1. Services dangereux actifs ────────────────────────────────
    active_dangerous = {}
    for svc, (severity, reason) in DANGEROUS_SERVICES.items():
        if _service_active(svc) or _service_enabled(svc):
            active_dangerous[svc] = {"severity": severity, "reason": reason}

    info["dangerous_services"] = list(active_dangerous.keys())
    if verbose:
        print(f"    Services dangereux détectés : {list(active_dangerous.keys())}")

    for svc, meta in active_dangerous.items():
        findings.append({
            "id":          f"SVC-{'D' + svc[:3].upper()}",
            "title":       f"Service dangereux actif : {svc}",
            "description": meta["reason"],
            "severity":    meta["severity"],
            "remediation": f"Désactiver : `systemctl disable --now {svc}`.",
            "references":  ["CIS Benchmark L1 – Section 2.2"]
        })

    # ── 2. Services de sécurité manquants ────────────────────────────
    missing_security = {}
    for svc, reason in RECOMMENDED_SECURITY_SERVICES.items():
        if not _service_active(svc):
            missing_security[svc] = reason

    info["missing_security_services"] = list(missing_security.keys())

    # Priorité : fail2ban et auditd sont importants
    for svc in ("fail2ban", "auditd"):
        if svc in missing_security:
            severity = "MEDIUM"
            findings.append({
                "id":          f"SVC-SEC-{svc[:4].upper()}",
                "title":       f"Service de sécurité absent : {svc}",
                "description": missing_security[svc],
                "severity":    severity,
                "remediation": f"Installer et activer : `apt install {svc} && systemctl enable --now {svc}`.",
                "references":  ["ANSSI R-57", "CIS Benchmark – Section 4.1"]
            })

    # AppArmor / SELinux
    apparmor_status = _run("aa-status 2>/dev/null | head -1")
    selinux_status  = _run("getenforce 2>/dev/null")
    info["mac_status"] = apparmor_status or selinux_status or "non détecté"

    if not apparmor_status and selinux_status.lower() not in ("enforcing",):
        findings.append({
            "id":          "SVC-MAC-001",
            "title":       "Aucun système de contrôle d'accès mandatoire (MAC) actif",
            "description": "AppArmor et SELinux semblent inactifs. Un MAC limite l'impact d'une compromission.",
            "severity":    "MEDIUM",
            "remediation": "Activer AppArmor : `systemctl enable apparmor && aa-enforce /etc/apparmor.d/*`.",
            "references":  ["CIS Benchmark L1 – Section 1.6", "ANSSI R-31"]
        })

    # ── 3. Liste complète des services actifs ────────────────────────
    all_active = _run("systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}'")
    info["active_services_count"] = len(all_active.splitlines()) if all_active else 0

    return {"findings": findings, "info": info}
