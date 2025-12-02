"""
Gestionnaire complet de mots de passe
"""

import json
import os
import sys
import base64
from datetime import datetime
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, data_file="passwords.json"):
        self.data_file = data_file
        self.key = None
        self.cipher = None
        self.initialize()
    
    def initialize(self):
        """Initialise le chiffrement."""
        print("🔐 INITIALISATION DU GESTIONNAIRE")
        print("-" * 40)
        
        # Demander le mot de passe maître
        master_pwd = getpass("Mot de passe maître : ")
        
        # Dériver une clé
        salt = b'gestionnaire_mdp_salt'  # En production, stockez un sel unique
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
        
        self.cipher = Fernet(key)
        
        # Créer fichier si inexistant
        if not os.path.exists(self.data_file):
            self.save_data([])
            print("✅ Nouvelle base de données créée.")
    
    def save_data(self, data):
        """Sauvegarde les données chiffrées."""
        encrypted = self.cipher.encrypt(json.dumps(data).encode())
        with open(self.data_file, 'wb') as f:
            f.write(encrypted)
    
    def load_data(self):
        """Charge les données déchiffrées."""
        with open(self.data_file, 'rb') as f:
            encrypted = f.read()
        
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())
    
    def add_password(self):
        """Ajoute un nouveau mot de passe."""
        print("\n" + "=" * 50)
        print("➕ AJOUT D'UN NOUVEAU MOT DE PASSE")
        print("=" * 50)
        
        # Informations
        service = input("\nService (ex: Gmail) : ").strip()
        username = input("Nom d'utilisateur : ").strip()
        
        # Générer ou saisir
        print("\nOptions pour le mot de passe :")
        print("1. Générer un mot de passe sécurisé")
        print("2. Saisir mon propre mot de passe")
        choice = input("Choix (1/2) : ")
        
        if choice == '1':
            # Importer le générateur
            try:
                from passwd_generator_api import generate_password, check_password_breaches
                
                length = int(input("Longueur (16) : ") or "16")
                password = generate_password(
                    length,
                    True,  # minuscules
                    True,  # majuscules
                    True,  # chiffres
                    True   # symboles
                )
                
                # Vérifier
                compromised, count = check_password_breaches(password)
                if compromised:
                    print(f"⚠️  ATTENTION: {count} fuites")
                    if input("Utiliser quand même ? (o/n) : ").lower() != 'o':
                        return
                
            except ImportError:
                print("❌ Générateur non disponible")
                password = getpass("Mot de passe : ")
        else:
            password = getpass("Mot de passe : ")
        
        notes = input("Notes (optionnel) : ").strip()
        
        # Sauvegarder
        data = self.load_data()
        entry = {
            'id': len(data) + 1,
            'service': service,
            'username': username,
            'password': password,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'updated': datetime.now().isoformat()
        }
        
        data.append(entry)
        self.save_data(data)
        
        print(f"\n✅ {service} ajouté avec succès !")
    
    def list_passwords(self):
        """Liste tous les mots de passe."""
        data = self.load_data()
        
        print("\n" + "=" * 50)
        print("📋 LISTE DES MOTS DE PASSE")
        print("=" * 50)
        
        if not data:
            print("\nAucun mot de passe enregistré.")
            return
        
        for entry in data:
            print(f"\nID: {entry['id']}")
            print(f"Service: {entry['service']}")
            print(f"Utilisateur: {entry['username']}")
            print(f"Créé le: {entry['created'][:10]}")
            if entry['notes']:
                print(f"Notes: {entry['notes']}")
            print("-" * 30)
    
    def search_password(self):
        """Recherche un mot de passe."""
        query = input("\nRechercher (service ou utilisateur) : ").lower()
        
        data = self.load_data()
        results = []
        
        for entry in data:
            if (query in entry['service'].lower() or 
                query in entry['username'].lower()):
                results.append(entry)
        
        if not results:
            print("❌ Aucun résultat.")
            return
        
        print(f"\n🔍 {len(results)} résultat(s) :")
        for entry in results:
            print(f"\nService: {entry['service']}")
            print(f"Utilisateur: {entry['username']}")
            print(f"Mot de passe: {entry['password']}")
            print("-" * 30)
    
    def delete_password(self):
        """Supprime un mot de passe."""
        self.list_passwords()
        
        try:
            pid = int(input("\nID à supprimer : "))
        except ValueError:
            print("❌ ID invalide.")
            return
        
        data = self.load_data()
        new_data = [e for e in data if e['id'] != pid]
        
        if len(new_data) == len(data):
            print("❌ ID non trouvé.")
            return
        
        # Réindexer les IDs
        for i, entry in enumerate(new_data, 1):
            entry['id'] = i
        
        self.save_data(new_data)
        print("✅ Supprimé avec succès.")
    
    def export_passwords(self):
        """Exporte les mots de passe."""
        print("\n⚠️  ATTENTION: L'export sera en texte clair !")
        confirm = input("Continuer ? (o/n) : ").lower()
        
        if confirm != 'o':
            return
        
        data = self.load_data()
        export_file = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(export_file, 'w', encoding='utf-8') as f:
            f.write("EXPORT DES MOTS DE PASSE\n")
            f.write(f"Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            for entry in data:
                f.write(f"Service: {entry['service']}\n")
                f.write(f"Utilisateur: {entry['username']}\n")
                f.write(f"Mot de passe: {entry['password']}\n")
                f.write(f"Notes: {entry['notes']}\n")
                f.write(f"Créé: {entry['created']}\n")
                f.write("-" * 40 + "\n")
        
        print(f"✅ Exporté dans {export_file}")
        print("🔒 SUPPRIMEZ CE FICHIER APRÈS UTILISATION !")

def main():
    """Menu principal."""
    print("\n" + "=" * 60)
    print("🔐 GESTIONNAIRE DE MOTS DE PASSE - KALI LINUX")
    print("=" * 60)
    
    # Vérifier les dépendances
    try:
        import cryptography
    except ImportError:
        print("❌ Module 'cryptography' manquant.")
        print("Installez avec: sudo pip3 install cryptography")
        sys.exit(1)
    
    # Initialiser le gestionnaire
    try:
        manager = PasswordManager()
    except Exception as e:
        print(f"❌ Erreur: {e}")
        sys.exit(1)
    
    while True:
        print("\n" + "=" * 50)
        print("MENU PRINCIPAL")
        print("=" * 50)
        print("1. ➕ Ajouter un mot de passe")
        print("2. 📋 Lister tous les mots de passe")
        print("3. 🔍 Rechercher un mot de passe")
        print("4. 🗑️  Supprimer un mot de passe")
        print("5. 📤 Exporter les mots de passe")
        print("6. 🛠️  Outils de génération")
        print("7. 🚪 Quitter")
        print("=" * 50)
        
        choice = input("\nVotre choix (1-7) : ")
        
        if choice == '1':
            manager.add_password()
        elif choice == '2':
            manager.list_passwords()
        elif choice == '3':
            manager.search_password()
        elif choice == '4':
            manager.delete_password()
        elif choice == '5':
            manager.export_passwords()
        elif choice == '6':
            print("\nOuvrir un autre terminal pour :")
            print("  python3 passwd_generator.py")
            print("  python3 passwd_generator_api.py")
        elif choice == '7':
            print("\n👋 À bientôt !")
            break
        else:
            print("❌ Choix invalide.")

if __name__ == "__main__":
    main()
