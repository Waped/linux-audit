# 🛡️ LinuxAudit — Outil d'Audit de Sécurité Linux Automatisé

> Projet personnel réalisé dans le cadre du Mastère **Cybersécurité & Cloud — EFREI Paris**  
> Alioune Thiaw · 2024–2025

---

## 📌 Présentation

**LinuxAudit** est un outil d'audit de conformité et de sécurité pour systèmes Linux, développé en Python 3.10+.  
Il analyse une machine locale et génère un rapport complet (JSON + HTML) identifiant les vulnérabilités et proposant des remédiations concrètes.

### Référentiels couverts
- **CIS Benchmark** Linux Level 1 & Level 2
- **ANSSI** — Guide de durcissement des systèmes GNU/Linux
- **ISO 27001** — Contrôles A.9 (accès), A.12 (opérations), A.13 (réseau)
- **RGPD** — Mesures techniques de protection des données

---

## 🎯 Fonctionnalités

| Module            | Contrôles effectués                                              |
|-------------------|------------------------------------------------------------------|
| `check_users`     | UID 0 hors root, comptes sans MDP, sudo permissif               |
| `check_network`   | Ports exposés, firewall, IP forwarding                          |
| `check_ssh`       | PermitRootLogin, PasswordAuth, MaxAuthTries, timeout            |
| `check_logs`      | Daemon de logs, échecs auth, sudo suspects, logrotate           |
| `check_files`     | Permissions sensibles, SUID/SGID, world-writable, authorized_keys |
| `check_services`  | Services dangereux actifs, MAC (AppArmor/SELinux)               |
| `check_passwords` | login.defs, pam_pwquality, expiration, hash faibles             |

---

## 🚀 Installation & Usage

### Prérequis
- Python 3.10+
- OS : Debian 11+, Ubuntu 20.04+
- Droits root recommandés (lecture /etc/shadow, iptables, etc.)

### Exécution directe
```bash
git clone https://github.com/votre-repo/linux-audit.git
cd linux-audit

# Audit complet (JSON + HTML)
sudo python3 audit.py

# Options avancées
sudo python3 audit.py --format html --output /tmp/rapport --verbose
```

### Via Docker
```bash
# Build
docker build -t linux-audit .

# Run (monte le répertoire de sortie localement)
docker run --rm --privileged \
  -v $(pwd)/output:/app/output \
  linux-audit

# Rapport disponible dans ./output/
```

---

## 📂 Structure du projet

```
linux-audit/
├── audit.py                   # Orchestrateur principal
├── Dockerfile                 # Conteneurisation
├── README.md
├── modules/
│   ├── check_users.py         # Utilisateurs & sudo
│   ├── check_network.py       # Réseau & ports
│   ├── check_ssh.py           # Configuration SSH
│   ├── check_logs.py          # Analyse des logs
│   ├── check_files.py         # Permissions fichiers
│   ├── check_services.py      # Services actifs
│   └── check_passwords.py     # Politique MDP
├── reports/
│   └── html_report.py         # Générateur rapport HTML
└── output/                    # Rapports générés (gitignore)
```

---

## 📊 Exemple de rapport

Le score de conformité est calculé ainsi :
- Chaque finding **HIGH** retire 10 points
- Chaque finding **MEDIUM** retire 5 points
- Chaque finding **LOW** retire 1 point
- Score minimum : 0

---

## 🔗 Liens utiles
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [ANSSI Durcissement Linux](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/)
- [OpenSCAP](https://www.open-scap.org/) — Alternative industrielle

---

## 📄 Licence

MIT — Libre d'utilisation, de modification et de distribution.
