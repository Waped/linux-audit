"""
check_ssh.py — Vérification de la configuration SSH (sshd_config)
Contrôles effectués :
  - PermitRootLogin
  - PasswordAuthentication
  - MaxAuthTries
  - ClientAliveInterval / ClientAliveCountMax (timeout)
  - Protocol version
  - PermitEmptyPasswords
  - AllowUsers / AllowGroups (liste blanche)
  - Port par défaut (22)
"""

import subprocess
from pathlib import Path
import re


SSHD_CONFIG_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/sshd_config",
]

# Paramètres attendus : {clé: (valeur_attendue_ou_None, severity_si_mauvais, message)}
EXPECTED = {
    "PermitRootLogin":          ("no",    "HIGH",   "La connexion SSH directe en tant que root doit être interdite."),
    "PasswordAuthentication":   ("no",    "MEDIUM", "L'authentification par mot de passe doit être désactivée au profit des clés."),
    "PermitEmptyPasswords":     ("no",    "HIGH",   "Les mots de passe vides ne doivent jamais être acceptés."),
    "X11Forwarding":            ("no",    "LOW",    "Le forwarding X11 expose le serveur graphique et devrait être désactivé."),
    "UsePAM":                   ("yes",   "MEDIUM", "PAM doit être activé pour centraliser l'authentification."),
    "MaxAuthTries":             (None,    "MEDIUM", "MaxAuthTries devrait être ≤ 4 pour limiter le brute-force."),
    "ClientAliveInterval":      (None,    "LOW",    "ClientAliveInterval devrait être défini (≤ 300s) pour déconnecter les sessions inactives."),
    "ClientAliveCountMax":      (None,    "LOW",    "ClientAliveCountMax devrait être ≤ 3."),
    "Protocol":                 ("2",     "HIGH",   "Seul le protocole SSH 2 est sécurisé."),
    "LogLevel":                 (None,    "LOW",    "LogLevel devrait être VERBOSE ou INFO."),
}


def _parse_sshd_config(path: str) -> dict:
    """Parse sshd_config et retourne un dict {paramètre_lowercase: valeur}."""
    config = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1].strip()
    except (FileNotFoundError, PermissionError):
        pass
    return config


def check_ssh(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── Localisation du fichier de config ───────────────────────────
    config_path = None
    for path in SSHD_CONFIG_PATHS:
        if Path(path).exists():
            config_path = path
            break

    if not config_path:
        findings.append({
            "id":          "SSH-000",
            "title":       "Fichier sshd_config introuvable",
            "description": "Impossible de localiser /etc/ssh/sshd_config. SSH est peut-être absent.",
            "severity":    "LOW",
            "remediation": "Vérifier l'installation de OpenSSH : `apt list --installed | grep openssh-server`.",
            "references":  []
        })
        return {"findings": findings, "info": info}

    config = _parse_sshd_config(config_path)
    info["sshd_config_path"] = config_path
    info["parsed_config"]    = config

    if verbose:
        print(f"    Config SSH lue depuis : {config_path} ({len(config)} paramètres)")

    # ── Vérifications paramètre par paramètre ───────────────────────
    for param, (expected_val, severity, message) in EXPECTED.items():
        key   = param.lower()
        value = config.get(key)

        # Paramètres avec valeur numérique à comparer
        if param == "MaxAuthTries":
            if value is None:
                findings.append(_make_finding(
                    "SSH-001", param, "non défini (défaut : 6, trop élevé)", severity,
                    message, "Ajouter dans sshd_config : `MaxAuthTries 3`",
                    ["CIS SSH – Section 5.2.7"]
                ))
            elif int(value) > 4:
                findings.append(_make_finding(
                    "SSH-001", param, value, severity,
                    f"{message} Valeur actuelle : {value}.",
                    "Réduire à 3 : `MaxAuthTries 3`",
                    ["CIS SSH – Section 5.2.7"]
                ))
            continue

        if param == "ClientAliveInterval":
            if value is None or int(value) == 0:
                findings.append(_make_finding(
                    "SSH-002", param, value or "non défini", severity,
                    message, "Ajouter : `ClientAliveInterval 300`",
                    ["CIS SSH – Section 5.2.12"]
                ))
            continue

        if param == "ClientAliveCountMax":
            if value is None or int(value) > 3:
                findings.append(_make_finding(
                    "SSH-003", param, value or "non défini", severity,
                    message, "Ajouter : `ClientAliveCountMax 3`",
                    ["CIS SSH – Section 5.2.12"]
                ))
            continue

        if param == "LogLevel":
            if value not in ("verbose", "info", "VERBOSE", "INFO"):
                findings.append(_make_finding(
                    "SSH-004", param, value or "non défini", severity,
                    message, "Ajouter : `LogLevel VERBOSE`",
                    ["CIS SSH – Section 5.2.5"]
                ))
            continue

        # Paramètres booléens (yes/no)
        if expected_val and value and value.lower() != expected_val.lower():
            fid = f"SSH-{list(EXPECTED.keys()).index(param)+10:03d}"
            findings.append(_make_finding(
                fid, param, value, severity, message,
                f"Modifier dans sshd_config : `{param} {expected_val}` puis `systemctl reload sshd`.",
                [f"CIS SSH – Section 5.2 ({param})"]
            ))
        elif value is None and expected_val:
            fid = f"SSH-{list(EXPECTED.keys()).index(param)+10:03d}"
            findings.append(_make_finding(
                fid, param, "non défini (valeur par défaut potentiellement non sécurisée)",
                severity, message,
                f"Ajouter dans sshd_config : `{param} {expected_val}`.",
                [f"CIS SSH – Section 5.2 ({param})"]
            ))

    # ── Port SSH par défaut ──────────────────────────────────────────
    port = config.get("port", "22")
    info["ssh_port"] = port
    if port == "22":
        findings.append({
            "id":          "SSH-020",
            "title":       "SSH sur le port par défaut (22)",
            "description": "Le port 22 est la première cible des scanners automatisés.",
            "severity":    "LOW",
            "remediation": "Changer vers un port non-standard > 1024 dans sshd_config : `Port 2222`. "
                           "Note : cela relève de la sécurité par obscurité, non d'une vraie protection.",
            "references":  ["ANSSI R-64"]
        })

    # ── AllowUsers / AllowGroups ─────────────────────────────────────
    if not config.get("allowusers") and not config.get("allowgroups"):
        findings.append({
            "id":          "SSH-021",
            "title":       "Aucune liste blanche SSH (AllowUsers/AllowGroups)",
            "description": "Sans AllowUsers ni AllowGroups, tout compte système peut tenter une connexion SSH.",
            "severity":    "MEDIUM",
            "remediation": "Ajouter dans sshd_config : `AllowGroups sshusers` et créer le groupe.",
            "references":  ["CIS SSH – Section 5.2.17", "ANSSI R-67"]
        })

    return {"findings": findings, "info": info}


def _make_finding(fid, param, current_val, severity, description, remediation, references):
    return {
        "id":          fid,
        "title":       f"SSH : {param} = {current_val}",
        "description": description,
        "severity":    severity,
        "remediation": remediation,
        "references":  references
    }
