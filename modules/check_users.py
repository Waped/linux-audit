"""
check_users.py — Vérification des utilisateurs, sudo, comptes à risque
Contrôles effectués :
  - Utilisateurs avec UID 0 autres que root
  - Comptes sans mot de passe
  - Règles sudo trop permissives (ALL, NOPASSWD)
  - Comptes avec shell interactif inutiles
"""

import subprocess
import pwd
import grp
from pathlib import Path


def _run(cmd: str) -> str:
    """Exécute une commande shell et retourne stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def check_users(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── 1. Utilisateurs avec UID 0 (hors root) ──────────────────────
    uid0_users = [
        p.pw_name for p in pwd.getpwall()
        if p.pw_uid == 0 and p.pw_name != "root"
    ]
    info["uid0_users"] = uid0_users
    if uid0_users:
        findings.append({
            "id":          "USR-001",
            "title":       "Utilisateurs avec UID 0 autres que root",
            "description": f"Comptes détectés : {', '.join(uid0_users)}. "
                           "Un UID 0 confère les privilèges root complets.",
            "severity":    "HIGH",
            "remediation": "Supprimer ou modifier ces comptes : `usermod -u <nouvel_uid> <user>`. "
                           "Seul root doit avoir l'UID 0.",
            "references":  ["CIS Benchmark L1 – Section 6.2.3"]
        })

    # ── 2. Comptes sans mot de passe ────────────────────────────────
    no_pwd = []
    try:
        shadow_lines = Path("/etc/shadow").read_text().splitlines()
        for line in shadow_lines:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] in ("", "!!", "!"):
                # On exclut les comptes système sans shell
                user_entry = pwd.getpwnam(parts[0])
                if user_entry.pw_shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                    no_pwd.append(parts[0])
    except (PermissionError, FileNotFoundError):
        # Non-root : on utilise une heuristique via passwd
        raw = _run("awk -F: '($2==\"\" || $2==\"!!\" || $2==\"!\") {print $1}' /etc/passwd")
        no_pwd = raw.splitlines() if raw else []

    info["no_password_accounts"] = no_pwd
    if no_pwd:
        findings.append({
            "id":          "USR-002",
            "title":       "Comptes avec mot de passe vide ou désactivé",
            "description": f"Comptes concernés : {', '.join(no_pwd)}.",
            "severity":    "HIGH",
            "remediation": "Définir un mot de passe fort ou désactiver le compte : "
                           "`passwd -l <user>` pour verrouiller.",
            "references":  ["CIS Benchmark L1 – Section 6.2.1", "ANSSI R-68"]
        })

    # ── 3. Règles sudo à risque ──────────────────────────────────────
    risky_sudo = []
    sudoers_files = [Path("/etc/sudoers")]
    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists():
        sudoers_files += list(sudoers_d.iterdir())

    for sf in sudoers_files:
        try:
            for i, line in enumerate(sf.read_text().splitlines(), 1):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "NOPASSWD" in line or ("ALL" in line and "=" in line):
                    risky_sudo.append(f"{sf.name}:{i} → {line}")
        except PermissionError:
            risky_sudo.append(f"{sf.name} : lecture refusée (accès root requis)")

    info["risky_sudo_rules"] = risky_sudo
    if risky_sudo:
        severity = "HIGH" if any("NOPASSWD" in r for r in risky_sudo) else "MEDIUM"
        findings.append({
            "id":          "USR-003",
            "title":       "Règles sudo trop permissives détectées",
            "description": f"{len(risky_sudo)} règle(s) à risque :\n" + "\n".join(risky_sudo),
            "severity":    severity,
            "remediation": "Restreindre sudo au strict nécessaire. Éviter `NOPASSWD` et `ALL`. "
                           "Utiliser des alias de commandes ciblés.",
            "references":  ["CIS Benchmark L1 – Section 5.3", "ANSSI R-30"]
        })

    # ── 4. Comptes avec shell interactif non-système ─────────────────
    interactive_shells = ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash",
                          "/usr/bin/zsh", "/bin/ksh")
    system_uid_max = 999  # Seuil commun Debian/Ubuntu

    shell_users = [
        p.pw_name for p in pwd.getpwall()
        if p.pw_shell in interactive_shells and p.pw_uid > system_uid_max
    ]
    info["interactive_shell_users"] = shell_users
    if verbose:
        print(f"    Utilisateurs avec shell interactif : {shell_users}")

    # On ne génère un finding que si des comptes autres que les humains connus existent
    # (heuristique : UID > 1000 souvent = humain ; entre 1000 et system_uid_max = service)
    service_with_shell = [
        p.pw_name for p in pwd.getpwall()
        if p.pw_shell in interactive_shells
        and 0 < p.pw_uid <= system_uid_max
        and p.pw_name not in ("root",)
    ]
    if service_with_shell:
        findings.append({
            "id":          "USR-004",
            "title":       "Comptes de service avec shell interactif",
            "description": f"Comptes détectés : {', '.join(service_with_shell)}. "
                           "Un shell interactif sur un compte de service élargit la surface d'attaque.",
            "severity":    "MEDIUM",
            "remediation": "Désactiver le shell : `usermod -s /usr/sbin/nologin <user>`.",
            "references":  ["CIS Benchmark L1 – Section 6.2.7"]
        })

    return {"findings": findings, "info": info}
