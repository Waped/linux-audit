"""
check_network.py — Vérification réseau : ports ouverts, firewall, interfaces
Contrôles effectués :
  - Ports en écoute sur 0.0.0.0 (exposition publique)
  - Services connus sur ports non-standards
  - Présence et état d'un firewall (iptables/nftables/ufw)
  - Transfert IP activé
"""

import subprocess
import re
from pathlib import Path


def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


# Ports réputés dangereux si exposés publiquement
DANGEROUS_PORTS = {
    21:   "FTP (non chiffré)",
    23:   "Telnet (non chiffré)",
    25:   "SMTP ouvert (relay potentiel)",
    135:  "RPC Windows (hors domaine AD)",
    139:  "NetBIOS",
    445:  "SMB (risque ransomware)",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh / syslog UDP",
    1433: "MSSQL",
    3306: "MySQL/MariaDB exposé",
    3389: "RDP",
    5432: "PostgreSQL exposé",
    6379: "Redis (souvent non authentifié)",
    27017:"MongoDB (souvent non authentifié)",
}


def _parse_listening_ports() -> list[dict]:
    """Retourne la liste des ports TCP/UDP en écoute avec adresse et processus."""
    ports = []
    raw = _run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
    for line in raw.splitlines():
        # Exemple ss : tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,...))
        m = re.search(
            r'(tcp|udp)\s+\S+\s+\d+\s+\d+\s+([\d\.\:]+):(\d+)\s',
            line, re.IGNORECASE
        )
        if m:
            proto, addr, port = m.group(1), m.group(2), int(m.group(3))
            # Extraction du processus
            proc_m = re.search(r'users:\(\("([^"]+)"', line)
            process = proc_m.group(1) if proc_m else "inconnu"
            ports.append({
                "proto":   proto.upper(),
                "address": addr,
                "port":    port,
                "process": process
            })
    return ports


def check_network(verbose: bool = False) -> dict:
    findings = []
    info     = {}

    # ── 1. Ports en écoute ──────────────────────────────────────────
    listening = _parse_listening_ports()
    info["listening_ports"] = listening

    # Ports exposés sur toutes les interfaces (0.0.0.0 ou ::)
    public_ports = [p for p in listening if p["address"] in ("0.0.0.0", "::")]

    # Ports dangereux exposés
    exposed_dangerous = [
        p for p in public_ports if p["port"] in DANGEROUS_PORTS
    ]
    if exposed_dangerous:
        details = "\n".join(
            f"  Port {p['port']}/{ p['proto']} ({DANGEROUS_PORTS[p['port']]}) – processus : {p['process']}"
            for p in exposed_dangerous
        )
        findings.append({
            "id":          "NET-001",
            "title":       "Ports dangereux exposés sur toutes les interfaces",
            "description": f"{len(exposed_dangerous)} port(s) à risque détecté(s) :\n{details}",
            "severity":    "HIGH",
            "remediation": "Fermer ces ports via le firewall ou arrêter les services inutiles. "
                           "Pour SSH : restreindre avec `AllowUsers` dans sshd_config.",
            "references":  ["CIS Benchmark L1 – Section 2.2", "ANSSI R-12"]
        })

    if verbose:
        print(f"    Ports en écoute : {len(listening)} | Exposés dangereux : {len(exposed_dangerous)}")

    # ── 2. Firewall ──────────────────────────────────────────────────
    firewall_active = False

    # Vérification UFW
    ufw_status = _run("ufw status 2>/dev/null")
    if "active" in ufw_status.lower():
        firewall_active = True
        info["firewall"] = "ufw (actif)"

    # Vérification iptables
    if not firewall_active:
        ipt = _run(r"iptables -L -n 2>/dev/null | grep -v '^Chain\|^target\|^$' | wc -l")
        if ipt.isdigit() and int(ipt) > 0:
            firewall_active = True
            info["firewall"] = f"iptables ({ipt} règles)"

    # Vérification nftables
    if not firewall_active:
        nft = _run("nft list ruleset 2>/dev/null | wc -l")
        if nft.isdigit() and int(nft) > 2:
            firewall_active = True
            info["firewall"] = f"nftables ({nft} lignes)"

    if not firewall_active:
        info["firewall"] = "aucun firewall détecté"
        findings.append({
            "id":          "NET-002",
            "title":       "Aucun firewall actif détecté",
            "description": "Ni ufw, ni iptables, ni nftables ne semble actif. "
                           "Le système est exposé sans filtrage réseau.",
            "severity":    "HIGH",
            "remediation": "Activer et configurer ufw : `ufw enable && ufw default deny incoming`. "
                           "N'autoriser que les ports nécessaires.",
            "references":  ["CIS Benchmark L1 – Section 3.5", "ANSSI R-14"]
        })

    # ── 3. IP Forwarding ─────────────────────────────────────────────
    ip_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    info["ip_forwarding"] = ip_forward
    if ip_forward == "1":
        findings.append({
            "id":          "NET-003",
            "title":       "Transfert IP (IP forwarding) activé",
            "description": "net.ipv4.ip_forward = 1. Ce paramètre est nécessaire pour les routeurs "
                           "et passerelles, mais inutile et risqué sur un serveur classique.",
            "severity":    "MEDIUM",
            "remediation": "Désactiver si inutile : `sysctl -w net.ipv4.ip_forward=0` "
                           "et persister dans /etc/sysctl.conf.",
            "references":  ["CIS Benchmark L1 – Section 3.1.1"]
        })

    # ── 4. Source Routing ────────────────────────────────────────────
    src_route = _run("sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null")
    if "= 1" in src_route:
        findings.append({
            "id":          "NET-004",
            "title":       "Source routing accepté",
            "description": "net.ipv4.conf.all.accept_source_route = 1. "
                           "Permet à un attaquant de forcer un chemin réseau spécifique.",
            "severity":    "MEDIUM",
            "remediation": "Désactiver : `sysctl -w net.ipv4.conf.all.accept_source_route=0`.",
            "references":  ["CIS Benchmark L1 – Section 3.2.1"]
        })

    return {"findings": findings, "info": info}
