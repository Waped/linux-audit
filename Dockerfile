# ─────────────────────────────────────────────────────────────────────────────
# LinuxAudit – Dockerfile
# Image légère basée sur Python 3.12-slim (Debian Bookworm)
# Usage :
#   docker build -t linux-audit .
#   docker run --rm --privileged -v $(pwd)/output:/app/output linux-audit
#
# ⚠️  --privileged est requis pour lire /etc/shadow, /proc, iptables, etc.
#     En production : préférer les capabilities ciblées.
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim-bookworm

# Métadonnées
LABEL maintainer="Jean Alioune Thiaw <jean@efrei.net>"
LABEL description="Outil d'audit de sécurité Linux automatisé"
LABEL version="1.0"

# Outils système nécessaires aux modules (ss, iptables, find, grep, awk, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2      \
    iptables      \
    net-tools     \
    procps        \
    findutils     \
    grep          \
    gawk          \
    sudo          \
    openssh-client \
    libpam-runtime \
    && rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Copie des sources
COPY . .

# Dépendances Python (aucune à ce stade : stdlib pure)
# Si des dépendances sont ajoutées : RUN pip install --no-cache-dir -r requirements.txt

# Répertoire de sortie (monté par l'utilisateur)
RUN mkdir -p /app/output

# Point d'entrée
ENTRYPOINT ["python3", "audit.py"]
CMD ["--format", "both", "--output", "/app/output"]
