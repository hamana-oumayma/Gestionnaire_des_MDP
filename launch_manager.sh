#!/bin/bash
# Script de lancement du gestionnaire de mots de passe

cd "$(dirname "$0")"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé."
    sudo apt update && sudo apt install python3 python3-pip -y
fi

# Vérifier l'environnement virtuel
if [ ! -d "projet-env" ]; then
    echo "🔄 Création de l'environnement virtuel..."
    python3 -m venv projet-env
fi

# Activer l'environnement
source projet-env/bin/activate

# Vérifier les dépendances
if ! python -c "import requests" 2>/dev/null; then
    echo "📦 Installation des dépendances..."
    pip install requests cryptography
fi

# Lancer le gestionnaire
echo "🚀 Lancement de Password Manager Pro..."
python password_manager_ui.py
