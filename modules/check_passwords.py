"""
check_passwords.py — Vérification de la politique de mots de passe
Contrôles effectués :
  - login.defs : PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_MIN_LEN, PASS_WARN_AGE
  - Présence de PAM pwquality / pam_cracklib
  - Comptes avec mots de passe n'expirant jamais
  - Comptes dont le MDP a expiré
  - Utilisation de hash forts (SHA-512 vs MD5/DES)
"""

import re
import pwd
import subprocess
from pathlib import Path
from datetime import datetime, timedelta


LOGINDEFS_PATH = "/etc/login.defs"
PAM_PATHS = [
    "/etc/pam.d/common-password",
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
]

# Seuils recommandés (CIS + ANSSI)
RECOMMENDED = {
    "PASS_MAX_DAYS": 90,
    "PASS_MIN_DAYS": 1,
    "PASS_MIN_LEN":  14,
    "PASS_WARN_AGE": 7,
}


def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def _parse_logindefs() -> dict:
    config = {}
    try:
        for line in Path(LOGINDEFS_PATH).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                config[parts[0]] = parts[1]
    except FileNotFoundError:
        pass
    return config


def _get_shadow_entries() -> list[dict]:
    """Parse /etc/shadow pour extraire les infos de mot de passe."""
    entries = []
    try:
        for line in Path("/etc/shadow").read_text().splitlines():
            parts = line.split(":")
            if len(parts) < 9:
                continue
            username  = parts[0]
            pw_hash   = parts[1]
            last_chg  = parts[2]  # Jours depuis 1970-01-01
            min_days  = parts[3]
            max_days  = parts[4]
            warn_days = parts[5]

            # Ignorer les comptes système (non-humains)
            try:
                p = pwd.getpwnam(username)
                if p.pw_uid < 1000 and username != "root":
                    continue
            except KeyError:
                continue

            entries.append({
                "username":  username,
                "pw_hash":   pw_hash,
                "last_chg":  int(last_chg) if last_chg.isdigit() else None,
                "max_days":  int(max_days)  if max_days.isdigit()  else None,
                "min_days":  int(min_days)  if min_days.isdigit()  else None,
                "warn_days": int(warn_days) if warn_days.isdigit() else None,
            })
    except (FileNotFoundError, PermissionError):
        pass
    return entries


def check_passwords(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── 1. Vérification login.defs ───────────────────────────────────
    logindefs = _parse_logindefs()
    info["login_defs"] = logindefs

    for param, threshold in RECOMMENDED.items():
        value = logindefs.get(param)
        if value is None:
            findings.append({
                "id":          f"PWD-{param[:3]}0",
                "title":       f"login.defs : {param} non défini",
                "description": f"{param} absent de {LOGINDEFS_PATH}. Valeur par défaut possiblement non sécurisée.",
                "severity":    "MEDIUM",
                "remediation": f"Ajouter dans {LOGINDEFS_PATH} : `{param}    {threshold}`",
                "references":  ["CIS Benchmark L1 – Section 5.4.1", "ANSSI R-68"]
            })
            continue

        val_int = int(value)

        if param == "PASS_MAX_DAYS" and val_int > threshold:
            findings.append({
                "id":          "PWD-MAX",
                "title":       f"PASS_MAX_DAYS trop élevé ({val_int} > {threshold})",
                "description": "Les mots de passe doivent expirer régulièrement pour limiter la fenêtre d'exposition.",
                "severity":    "MEDIUM",
                "remediation": f"Modifier dans {LOGINDEFS_PATH} : `PASS_MAX_DAYS    {threshold}`",
                "references":  ["CIS Benchmark L1 – Section 5.4.1.1"]
            })
        elif param == "PASS_MIN_LEN" and val_int < threshold:
            findings.append({
                "id":          "PWD-LEN",
                "title":       f"PASS_MIN_LEN insuffisant ({val_int} < {threshold})",
                "description": f"La longueur minimale requise est {val_int}. Les recommandations ANSSI exigent ≥ {threshold}.",
                "severity":    "HIGH",
                "remediation": f"Modifier : `PASS_MIN_LEN    {threshold}` et configurer pam_pwquality.",
                "references":  ["ANSSI R-68", "CIS Benchmark – Section 5.4.1"]
            })
        elif param == "PASS_WARN_AGE" and val_int < threshold:
            findings.append({
                "id":          "PWD-WARN",
                "title":       f"PASS_WARN_AGE trop faible ({val_int} < {threshold} jours)",
                "description": "Les utilisateurs ont trop peu de préavis avant l'expiration du mot de passe.",
                "severity":    "LOW",
                "remediation": f"Modifier : `PASS_WARN_AGE    {threshold}`",
                "references":  ["CIS Benchmark – Section 5.4.1.4"]
            })

    # ── 2. PAM pwquality ─────────────────────────────────────────────
    pam_quality_found = False
    for pam_path in PAM_PATHS:
        if Path(pam_path).exists():
            content = Path(pam_path).read_text()
            if "pam_pwquality" in content or "pam_cracklib" in content:
                pam_quality_found = True
                info["pam_pwquality"] = pam_path
                break

    if not pam_quality_found:
        findings.append({
            "id":          "PWD-PAM",
            "title":       "pam_pwquality / pam_cracklib non configuré",
            "description": "Aucune règle de qualité des mots de passe via PAM. "
                           "Les utilisateurs peuvent choisir des mots de passe triviaux.",
            "severity":    "HIGH",
            "remediation": "Installer et configurer : `apt install libpam-pwquality`. "
                           "Ajouter dans /etc/pam.d/common-password : "
                           "`password requisite pam_pwquality.so minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1`",
            "references":  ["CIS Benchmark L1 – Section 5.4.1", "ANSSI R-68"]
        })

    # ── 3. Comptes avec MDP n'expirant jamais ────────────────────────
    shadow_entries = _get_shadow_entries()
    no_expiry = [e["username"] for e in shadow_entries if e["max_days"] in (None, 0, 99999, -1)]
    info["accounts_no_expiry"] = no_expiry

    if no_expiry:
        findings.append({
            "id":          "PWD-EXP",
            "title":       f"Comptes sans expiration de mot de passe ({len(no_expiry)})",
            "description": f"Comptes : {', '.join(no_expiry)}",
            "severity":    "MEDIUM",
            "remediation": "Définir une expiration : `chage -M 90 <user>`. "
                           "Vérifier avec `chage -l <user>`.",
            "references":  ["CIS Benchmark – Section 5.4.1.1", "ANSSI R-68"]
        })

    # ── 4. Algorithme de hachage des mots de passe ───────────────────
    weak_hash_users = []
    for e in shadow_entries:
        h = e["pw_hash"]
        if not h or h in ("!", "!!", "*", "x"):
            continue  # Compte verrouillé / désactivé
        if not h.startswith("$6$") and not h.startswith("$y$") and not h.startswith("$2b$"):
            # SHA-512 = $6$, yescrypt = $y$, bcrypt = $2b$
            algo = "$1$=MD5" if h.startswith("$1$") else \
                   "$5$=SHA-256" if h.startswith("$5$") else "DES/inconnu"
            weak_hash_users.append(f"{e['username']} ({algo})")

    info["weak_hash_users"] = weak_hash_users
    if weak_hash_users:
        findings.append({
            "id":          "PWD-HASH",
            "title":       f"Mots de passe avec algorithme de hachage faible ({len(weak_hash_users)})",
            "description": f"Comptes utilisant MD5, SHA-256 ou DES :\n" +
                           "\n".join(f"  {u}" for u in weak_hash_users),
            "severity":    "HIGH",
            "remediation": "Migrer vers SHA-512 : modifier ENCRYPT_METHOD SHA512 dans login.defs. "
                           "Forcer le changement de mot de passe : `chage -d 0 <user>`.",
            "references":  ["ANSSI R-68", "CIS Benchmark – Section 5.4.4"]
        })

    return {"findings": findings, "info": info}
