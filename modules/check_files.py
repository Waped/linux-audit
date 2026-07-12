"""
check_files.py — Vérification des permissions sur fichiers et répertoires sensibles
Contrôles effectués :
  - Permissions /etc/passwd, /etc/shadow, /etc/sudoers
  - Fichiers avec SUID/SGID inattendu
  - Fichiers world-writable dans les répertoires système
  - .ssh/authorized_keys mal configurés
  - Répertoires critiques (cron, crontab, etc.)
"""

import os
import stat
import subprocess
from pathlib import Path


# Fichiers sensibles avec permissions attendues (octal)
SENSITIVE_FILES = {
    "/etc/passwd":        (0o644, "Lecture pour tous, écriture root uniquement"),
    "/etc/shadow":        (0o640, "Lecture root + groupe shadow uniquement"),
    "/etc/group":         (0o644, "Lecture pour tous, écriture root uniquement"),
    "/etc/gshadow":       (0o640, "Lecture root + groupe shadow uniquement"),
    "/etc/sudoers":       (0o440, "Lecture root + groupe sudo uniquement"),
    "/etc/ssh/sshd_config": (0o600, "Lecture root uniquement"),
    "/etc/crontab":       (0o600, "Lecture/écriture root uniquement"),
    "/boot/grub/grub.cfg": (0o600, "Lecture root uniquement"),
}

# Binaires SUID légitimes connus (whitelist)
KNOWN_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/bin/su",
    "/usr/bin/passwd", "/bin/passwd",
    "/usr/bin/newgrp", "/usr/bin/gpasswd",
    "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/mount", "/bin/mount",
    "/usr/bin/umount", "/bin/umount",
    "/usr/sbin/pppd", "/usr/lib/openssh/ssh-keysign",
    "/usr/bin/pkexec", "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/sbin/unix_chkpwd", "/usr/sbin/unix_chkpwd",
    "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/ssh-agent", "/usr/bin/wall",
    "/usr/bin/write", "/usr/bin/screen",
    "/usr/bin/Xorg", "/usr/lib/xorg/Xorg",
    "/usr/bin/fusermount", "/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/ping", "/bin/ping",
}


def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        return r.stdout.strip()
    except Exception:
        return ""


def _octal(path: str) -> int | None:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except (FileNotFoundError, PermissionError):
        return None


def check_files(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── 1. Permissions des fichiers sensibles ────────────────────────
    bad_perms = []
    for filepath, (expected_perm, explanation) in SENSITIVE_FILES.items():
        actual = _octal(filepath)
        if actual is None:
            continue  # Fichier absent : skip
        if actual != expected_perm:
            bad_perms.append({
                "file":     filepath,
                "actual":   oct(actual),
                "expected": oct(expected_perm),
                "note":     explanation
            })

    info["bad_permissions"] = bad_perms
    if bad_perms:
        details = "\n".join(
            f"  {b['file']} : {b['actual']} (attendu {b['expected']})"
            for b in bad_perms
        )
        findings.append({
            "id":          "FILE-001",
            "title":       "Permissions incorrectes sur fichiers sensibles",
            "description": f"{len(bad_perms)} fichier(s) avec des permissions non conformes :\n{details}",
            "severity":    "HIGH",
            "remediation": "Corriger avec chmod. Exemple : `chmod 640 /etc/shadow` "
                           "et `chown root:shadow /etc/shadow`.",
            "references":  ["CIS Benchmark L1 – Sections 6.1.x", "ANSSI R-53"]
        })

    # ── 2. Fichiers SUID/SGID non répertoriés ───────────────────────
    suid_raw = _run(
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"
    )
    suid_files = set(suid_raw.splitlines()) if suid_raw else set()
    unknown_suid = suid_files - KNOWN_SUID
    info["suid_files_count"]   = len(suid_files)
    info["unknown_suid_files"] = list(unknown_suid)

    if verbose:
        print(f"    Fichiers SUID/SGID : {len(suid_files)} (dont {len(unknown_suid)} inconnus)")

    if unknown_suid:
        findings.append({
            "id":          "FILE-002",
            "title":       f"Fichiers SUID/SGID non répertoriés ({len(unknown_suid)})",
            "description": "Fichiers avec bit SUID/SGID hors whitelist :\n" +
                           "\n".join(f"  {f}" for f in sorted(unknown_suid)[:10]),
            "severity":    "HIGH",
            "remediation": "Retirer le bit SUID si inutile : `chmod u-s <fichier>`. "
                           "CVE-2021-4034 (pkexec) rappelle le danger de ces bits.",
            "references":  ["CIS Benchmark L1 – Section 6.1.13", "ANSSI R-54"]
        })

    # ── 3. Fichiers world-writable (hors /tmp et /proc) ─────────────
    ww_raw = _run(
        "find / -xdev -type f -perm -0002 "
        "! -path '/tmp/*' ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
        "2>/dev/null | head -20"
    )
    ww_files = ww_raw.splitlines() if ww_raw else []
    info["world_writable_files"] = ww_files

    if ww_files:
        findings.append({
            "id":          "FILE-003",
            "title":       f"Fichiers accessibles en écriture par tous ({len(ww_files)} détectés)",
            "description": "Exemples :\n" + "\n".join(f"  {f}" for f in ww_files[:5]),
            "severity":    "MEDIUM",
            "remediation": "Retirer la permission world-write : `chmod o-w <fichier>`.",
            "references":  ["CIS Benchmark L1 – Section 6.1.11"]
        })

    # ── 4. .ssh/authorized_keys trop permissifs ──────────────────────
    home_dirs = [p for p in Path("/home").iterdir() if p.is_dir()] + [Path("/root")]
    bad_keys  = []
    for home in home_dirs:
        auth_keys = home / ".ssh" / "authorized_keys"
        if auth_keys.exists():
            perm = _octal(str(auth_keys))
            if perm and perm > 0o600:
                bad_keys.append(f"{auth_keys} ({oct(perm)})")

    info["bad_authorized_keys"] = bad_keys
    if bad_keys:
        findings.append({
            "id":          "FILE-004",
            "title":       "authorized_keys avec permissions trop larges",
            "description": "Fichiers concernés :\n" + "\n".join(f"  {f}" for f in bad_keys),
            "severity":    "MEDIUM",
            "remediation": "Restreindre les permissions : `chmod 600 ~/.ssh/authorized_keys`.",
            "references":  ["CIS SSH – Section 5.2", "ANSSI R-70"]
        })

    return {"findings": findings, "info": info}
