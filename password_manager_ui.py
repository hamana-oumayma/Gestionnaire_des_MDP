#!/usr/bin/env python3
"""
Password Manager Pro - Interface Utilisateur Complète
"""

import sys
import os
import json
import getpass
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Import des générateurs
sys.path.append('.')
try:
    from passwd_generator_api import generer_mot_de_passe, verifier_mot_de_passe_api, analyser_complexite
except ImportError:
    print("⚠️  Générateur API non disponible")
    generer_mot_de_passe = None

class PasswordManagerUI:
    def __init__(self):
        self.data_file = "passwords.encrypted"
        self.key = None
        self.cipher = None
        self.current_user = None
        
        # Couleurs pour l'interface (si supporté)
        self.colors = {
            'reset': '\033[0m',
            'bold': '\033[1m',
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
        }
        
        self.init_ui()
    
    def color_text(self, text, color):
        """Ajoute des couleurs au texte si supporté."""
        if sys.platform != 'win32' and os.isatty(sys.stdout.fileno()):
            return f"{self.colors.get(color, '')}{text}{self.colors['reset']}"
        return text
    
    def clear_screen(self):
        """Efface l'écran."""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_header(self, title):
        """Affiche un en-tête stylisé."""
        self.clear_screen()
        print("\n" + "="*70)
        print(self.color_text(f"🔐  {title}", 'cyan'))
        print("="*70 + "\n")
    
    def print_success(self, message):
        """Affiche un message de succès."""
        print(self.color_text(f"✅  {message}", 'green'))
    
    def print_error(self, message):
        """Affiche un message d'erreur."""
        print(self.color_text(f"❌  {message}", 'red'))
    
    def print_warning(self, message):
        """Affiche un message d'avertissement."""
        print(self.color_text(f"⚠️   {message}", 'yellow'))
    
    def print_info(self, message):
        """Affiche un message d'information."""
        print(self.color_text(f"ℹ️   {message}", 'blue'))
    
    def input_box(self, prompt, password=False):
        """Boîte de saisie stylisée."""
        print(self.color_text(f"\n{prompt}", 'bold'))
        print("-" * 40)
        if password:
            return getpass.getpass("> ")
        else:
            return input("> ")
    
    def init_ui(self):
        """Initialise l'interface."""
        self.clear_screen()
        self.show_welcome_screen()
        self.init_encryption()
    
    def show_welcome_screen(self):
        """Affiche l'écran de bienvenue."""
        print("\n" + "="*70)
        print(self.color_text("""
    ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ 
    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
    ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
    ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
    ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ 
        """, 'cyan'))
        print(self.color_text("           GESTIONNAIRE DE MOTS DE PASSE PROFESSIONNEL", 'bold'))
        print("="*70)
        print(self.color_text("\n🔒  Stockage chiffré AES-256 • Vérification API • Interface intuitive", 'yellow'))
        print("\n" + "-"*70)
        input(self.color_text("\nAppuyez sur Entrée pour continuer...", 'purple'))
    
    def init_encryption(self):
        """Initialise le système de chiffrement."""
        self.print_header("AUTHENTIFICATION")
        
        # Premier démarrage ou existant
        if os.path.exists(self.data_file):
            print("Bienvenue de retour !")
            master_pwd = self.input_box("Veuillez entrer votre mot de passe maître :", password=True)
            
            try:
                # Charger la clé existante
                with open("master.key", "rb") as f:
                    salt = f.read(16)
                    stored_key = f.read()
                
                # Dériver la clé
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
                
                if key != stored_key:
                    self.print_error("Mot de passe incorrect !")
                    sys.exit(1)
                
                self.cipher = Fernet(key)
                self.print_success("Authentification réussie !")
                
            except Exception as e:
                self.print_error(f"Erreur de chargement : {e}")
                sys.exit(1)
        else:
            print("Première utilisation - Configuration initiale")
            print("\n" + "-"*40)
            print("🔐  Créez un mot de passe maître fort :")
            print("   • Minimum 12 caractères")
            print("   • Lettres, chiffres, symboles")
            print("   • Ne le perdez PAS !")
            print("-"*40)
            
            while True:
                master_pwd = self.input_box("Nouveau mot de passe maître :", password=True)
                confirm_pwd = self.input_box("Confirmez le mot de passe :", password=True)
                
                if master_pwd != confirm_pwd:
                    self.print_error("Les mots de passe ne correspondent pas.")
                    continue
                
                if len(master_pwd) < 8:
                    self.print_warning("Mot de passe trop court (min. 8 caractères)")
                    continue
                
                # Dériver la clé
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
                
                # Sauvegarder la clé
                with open("master.key", "wb") as f:
                    f.write(salt)
                    f.write(key)
                
                self.cipher = Fernet(key)
                self.save_data([])
                self.print_success("Configuration terminée !")
                break
    
    def save_data(self, data):
        """Sauvegarde les données chiffrées."""
        encrypted = self.cipher.encrypt(json.dumps(data).encode())
        with open(self.data_file, 'wb') as f:
            f.write(encrypted)
    
    def load_data(self):
        """Charge les données déchiffrées."""
        try:
            with open(self.data_file, 'rb') as f:
                encrypted = f.read()
            
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception as e:
            self.print_error(f"Erreur de chargement : {e}")
            return []
    
    def show_main_menu(self):
        """Affiche le menu principal."""
        while True:
            self.print_header("MENU PRINCIPAL")
            
            print("1. 📝  Ajouter un nouveau mot de passe")
            print("2. 📋  Voir tous les mots de passe")
            print("3. 🔍  Rechercher un mot de passe")
            print("4. 🛠️   Générateur de mot de passe")
            print("5. 📊  Statistiques")
            print("6. ⚙️   Paramètres")
            print("7. 🚪  Quitter")
            
            print("\n" + "-"*70)
            choix = self.input_box("Votre choix (1-7) :")
            
            if choix == '1':
                self.add_password()
            elif choix == '2':
                self.list_passwords()
            elif choix == '3':
                self.search_password()
            elif choix == '4':
                self.show_generator()
            elif choix == '5':
                self.show_statistics()
            elif choix == '6':
                self.show_settings()
            elif choix == '7':
                self.exit_program()
            else:
                self.print_error("Choix invalide. Réessayez.")
    
    def add_password(self):
        """Ajoute un nouveau mot de passe."""
        self.print_header("AJOUTER UN MOT DE PASSE")
        
        service = self.input_box("Nom du service (ex: Gmail, Facebook) :")
        username = self.input_box("Nom d'utilisateur / Email :")
        url = self.input_box("URL du site (optionnel) :") or ""
        category = self.select_category()
        notes = self.input_box("Notes (optionnel) :") or ""
        
        # Choix du mot de passe
        print("\n" + "-"*40)
        print("1. 🔧  Générer un mot de passe sécurisé")
        print("2. ⌨️   Saisir manuellement")
        print("3. 🔍  Vérifier un mot de passe existant")
        
        choix_mdp = self.input_box("Option (1-3) :")
        
        if choix_mdp == '1':
            password = self.generate_password_ui()
        elif choix_mdp == '2':
            password = self.input_box("Mot de passe :", password=True)
        elif choix_mdp == '3':
            password = self.input_box("Mot de passe à vérifier :", password=True)
            self.verify_password_ui(password, show_only=True)
            use_it = self.input_box("Utiliser ce mot de passe ? (o/n) :").lower()
            if use_it != 'o':
                return
        else:
            self.print_error("Option invalide.")
            return
        
        if not password:
            self.print_error("Mot de passe requis.")
            return
        
        # Vérification API
        self.print_info("Vérification de la sécurité...")
        is_compromised, breach_count, _ = verifier_mot_de_passe_api(password)
        
        if is_compromised:
            self.print_warning(f"⚠️  Mot de passe trouvé dans {breach_count:,} fuites !")
            proceed = self.input_box("Voulez-vous quand même l'utiliser ? (o/n) :").lower()
            if proceed != 'o':
                return
        
        # Sauvegarde
        data = self.load_data()
        entry = {
            'id': len(data) + 1,
            'service': service,
            'username': username,
            'password': password,
            'url': url,
            'category': category,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'updated': datetime.now().isoformat(),
            'breaches': breach_count if is_compromised else 0
        }
        
        data.append(entry)
        self.save_data(data)
        
        self.print_success(f"✅  {service} ajouté avec succès !")
        input("\nAppuyez sur Entrée pour continuer...")
    
    def select_category(self):
        """Sélectionne une catégorie."""
        categories = [
            "📧 Email", "💼 Travail", "🛒 Shopping", 
            "🏦 Bancaire", "🎮 Jeux", "💻 Social",
            "📱 Mobile", "🌐 Web", "⚡ Autre"
        ]
        
        print("\n" + "-"*40)
        print("Catégories disponibles :")
        for i, cat in enumerate(categories, 1):
            print(f"{i}. {cat}")
        
        while True:
            try:
                choix = int(self.input_box(f"Catégorie (1-{len(categories)}) :"))
                if 1 <= choix <= len(categories):
                    return categories[choix - 1]
                else:
                    self.print_error("Choix invalide.")
            except ValueError:
                self.print_error("Entrez un nombre.")
    
    def generate_password_ui(self):
        """Interface pour générer un mot de passe."""
        self.print_header("GÉNÉRATEUR DE MOT DE PASSE")
        
        print("Configuration du mot de passe :")
        print("-"*40)
        
        try:
            length = int(self.input_box("Longueur (12-32) :") or "16")
            length = max(8, min(64, length))
            
            use_lower = self.input_box("Lettres minuscules ? (o/n) [o] :").lower() in ['', 'o', 'oui']
            use_upper = self.input_box("Lettres majuscules ? (o/n) [o] :").lower() in ['', 'o', 'oui']
            use_digits = self.input_box("Chiffres ? (o/n) [o] :").lower() in ['', 'o', 'oui']
            use_symbols = self.input_box("Symboles ? (o/n) [o] :").lower() in ['', 'o', 'oui']
            
            if not any([use_lower, use_upper, use_digits, use_symbols]):
                self.print_error("Sélectionnez au moins un type.")
                return None
            
            password = generer_mot_de_passe(length, use_lower, use_upper, use_digits, use_symbols)
            
            print("\n" + "="*40)
            print(self.color_text("🔑  VOTRE MOT DE PASSE :", 'green'))
            print("="*40)
            print(f"\n{password}\n")
            print("="*40)
            
            # Vérification
            self.verify_password_ui(password)
            
            return password
            
        except Exception as e:
            self.print_error(f"Erreur : {e}")
            return None
    
    def verify_password_ui(self, password, show_only=False):
        """Interface de vérification de mot de passe."""
        print("\n" + "-"*40)
        print("🔍  VÉRIFICATION EN COURS...")
        
        is_compromised, breach_count, response_time = verifier_mot_de_passe_api(password)
        
        print("\n" + "="*40)
        print(self.color_text("📊  RÉSULTATS DE VÉRIFICATION", 'cyan'))
        print("="*40)
        
        print(f"\nLongueur : {len(password)} caractères")
        print(f"Temps de réponse : {response_time:.2f}s")
        
        if is_compromised:
            print(self.color_text(f"\n🚨  COMPROMIS : {breach_count:,} fuites", 'red'))
            if breach_count > 100000:
                print("⚠️  EXTÊMEMENT DANGEREUX - À ÉVITER ABSOLUMENT")
        elif is_compromised is False:
            print(self.color_text("\n✅  NON TROUVÉ dans les fuites", 'green'))
        else:
            print(self.color_text("\n⚠️  VÉRIFICATION IMPOSSIBLE (hors ligne)", 'yellow'))
        
        # Analyse de complexité
        analyser_complexite(password)
        
        if not show_only:
            input("\nAppuyez sur Entrée pour continuer...")
    
    def list_passwords(self):
        """Liste tous les mots de passe."""
        self.print_header("LISTE DES MOTS DE PASSE")
        
        data = self.load_data()
        
        if not data:
            self.print_info("Aucun mot de passe enregistré.")
            input("\nAppuyez sur Entrée pour continuer...")
            return
        
        # Filtrer par catégorie
        categories = sorted(set(item['category'] for item in data))
        print("Filtrer par catégorie :")
        print("0. Toutes les catégories")
        for i, cat in enumerate(categories, 1):
            print(f"{i}. {cat}")
        
        try:
            choix = int(self.input_box(f"\nCatégorie (0-{len(categories)}) :") or "0")
            if choix > 0:
                selected_cat = categories[choix - 1]
                data = [item for item in data if item['category'] == selected_cat]
        except:
            pass
        
        # Afficher
        for item in data:
            print("\n" + "="*60)
            print(self.color_text(f"📁  {item['service']}", 'bold'))
            print("-"*60)
            print(f"👤  Utilisateur : {item['username']}")
            print(f"🔑  Mot de passe : {'•' * len(item['password'])}")
            print(f"📂  Catégorie : {item['category']}")
            print(f"📅  Créé le : {item['created'][:10]}")
            
            if item['breaches'] > 0:
                print(self.color_text(f"⚠️  COMPROMIS : {item['breaches']} fuites", 'red'))
            
            if item['notes']:
                print(f"📝  Notes : {item['notes']}")
        
        print("\n" + "="*60)
        print(f"Total : {len(data)} mot(s) de passe")
        
        # Options
        print("\n" + "-"*60)
        print("1. 👁️   Voir un mot de passe")
        print("2. 📋  Copier un mot de passe")
        print("3. 🗑️   Supprimer un mot de passe")
        print("4. ↩️   Retour")
        
        choix = self.input_box("Option (1-4) :")
        
        if choix == '1':
            self.view_password_details(data)
        elif choix == '2':
            self.copy_password(data)
        elif choix == '3':
            self.delete_password_ui(data)
    
    def view_password_details(self, data):
        """Affiche les détails d'un mot de passe."""
        try:
            pid = int(self.input_box("ID du mot de passe à afficher :"))
            for item in data:
                if item['id'] == pid:
                    print("\n" + "="*60)
                    print(self.color_text(f"🔓  DÉTAILS - {item['service']}", 'green'))
                    print("="*60)
                    print(f"👤  Utilisateur : {item['username']}")
                    print(f"🔑  Mot de passe : {item['password']}")
                    print(f"🌐  URL : {item['url']}")
                    print(f"📂  Catégorie : {item['category']}")
                    print(f"📅  Créé le : {item['created']}")
                    print(f"✏️   Modifié le : {item['updated']}")
                    
                    if item['breaches'] > 0:
                        print(self.color_text(f"🚨  ALERTE : {item['breaches']:,} fuites", 'red'))
                    
                    if item['notes']:
                        print(f"\n📝  Notes :\n{item['notes']}")
                    
                    input("\nAppuyez sur Entrée pour continuer...")
                    return
            self.print_error("ID non trouvé.")
        except ValueError:
            self.print_error("ID invalide.")
    
    def search_password(self):
        """Recherche un mot de passe."""
        self.print_header("RECHERCHE")
        
        query = self.input_box("Rechercher (service, utilisateur, catégorie) :").lower()
        
        if not query:
            return
        
        data = self.load_data()
        results = []
        
        for item in data:
            if (query in item['service'].lower() or 
                query in item['username'].lower() or 
                query in item['category'].lower() or
                query in (item.get('notes', '').lower())):
                results.append(item)
        
        if not results:
            self.print_info("Aucun résultat trouvé.")
            input("\nAppuyez sur Entrée pour continuer...")
            return
        
        print(f"\n🔍  {len(results)} résultat(s) trouvé(s) :")
        print("-"*60)
        
        for item in results:
            print(f"\n[{item['id']}] {item['service']}")
            print(f"   👤 {item['username']}")
            print(f"   📂 {item['category']}")
            
            if item['breaches'] > 0:
                print(self.color_text(f"   ⚠️  {item['breaches']} fuites", 'red'))
        
        print("\n" + "="*60)
        print("1. 👁️   Voir un résultat")
        print("2. ↩️   Nouvelle recherche")
        print("3. ↩️   Retour")
        
        choix = self.input_box("Option (1-3) :")
        
        if choix == '1':
            self.view_password_details(results)
        elif choix == '2':
            self.search_password()
    
    def show_generator(self):
        """Affiche le générateur de mots de passe."""
        self.print_header("GÉNÉRATEUR AVANCÉ")
        
        password = self.generate_password_ui()
        
        if password:
            save_it = self.input_box("\nVoulez-vous sauvegarder ce mot de passe ? (o/n) :").lower()
            if save_it == 'o':
                self.add_password_with_generated(password)
    
    def add_password_with_generated(self, password):
        """Ajoute un mot de passe généré."""
        service = self.input_box("Pour quel service ? :")
        username = self.input_box("Nom d'utilisateur :")
        category = self.select_category()
        
        data = self.load_data()
        entry = {
            'id': len(data) + 1,
            'service': service,
            'username': username,
            'password': password,
            'category': category,
            'created': datetime.now().isoformat(),
            'updated': datetime.now().isoformat(),
            'breaches': 0
        }
        
        data.append(entry)
        self.save_data(data)
        
        self.print_success(f"✅  {service} sauvegardé avec le mot de passe généré !")
        input("\nAppuyez sur Entrée pour continuer...")
    
    def show_statistics(self):
        """Affiche les statistiques."""
        self.print_header("STATISTIQUES")
        
        data = self.load_data()
        
        if not data:
            self.print_info("Aucune donnée à analyser.")
            input("\nAppuyez sur Entrée pour continuer...")
            return
        
        total = len(data)
        
        # Par catégorie
        categories = {}
        for item in data:
            cat = item['category']
            categories[cat] = categories.get(cat, 0) + 1
        
        # Dates
        dates = [datetime.fromisoformat(item['created'][:10]) for item in data]
        oldest = min(dates).strftime('%d/%m/%Y')
        newest = max(dates).strftime('%d/%m/%Y')
        
        # Mots de passe compromis
        compromised = sum(1 for item in data if item['breaches'] > 0)
        
        print("📊  VUE D'ENSEMBLE")
        print("-"*40)
        print(f"• Total des comptes : {total}")
        print(f"• Comptes compromis : {compromised}")
        print(f"• Période : {oldest} → {newest}")
        print(f"• Données chiffrées : {os.path.getsize(self.data_file):,} octets")
        
        print("\n📂  RÉPARTITION PAR CATÉGORIE")
        print("-"*40)
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            percent = (count / total) * 100
            bar = "█" * int(percent // 5)
            print(f"{cat:20} {bar:20} {count:3} ({percent:.1f}%)")
        
        print("\n🔒  ANALYSE DE SÉCURITÉ")
        print("-"*40)
        if compromised > 0:
            self.print_warning(f"{compromised} mot(s) de passe compromis !")
            print("Considérez les changer immédiatement.")
        else:
            self.print_success("Aucun mot de passe compromis détecté.")
        
        # Longueur moyenne
        avg_length = sum(len(item['password']) for item in data) / total
        print(f"Longueur moyenne : {avg_length:.1f} caractères")
        
        input("\nAppuyez sur Entrée pour continuer...")
    
    def show_settings(self):
        """Affiche les paramètres."""
        self.print_header("PARAMÈTRES")
        
        print("1. 🔐  Changer le mot de passe maître")
        print("2. 💾  Sauvegarder la base de données")
        print("3. 📥  Restaurer une sauvegarde")
        print("4. 🗑️   Vider la base de données")
        print("5. ℹ️   À propos")
        print("6. ↩️   Retour")
        
        choix = self.input_box("Option (1-6) :")
        
        if choix == '1':
            self.change_master_password()
        elif choix == '2':
            self.backup_database()
        elif choix == '3':
            self.restore_database()
        elif choix == '4':
            self.clear_database()
        elif choix == '5':
            self.show_about()
    
    def change_master_password(self):
        """Change le mot de passe maître."""
        self.print_header("CHANGER LE MOT DE PASSE MAÎTRE")
        
        current = self.input_box("Mot de passe actuel :", password=True)
        
        # Vérifier le mot de passe actuel
        try:
            with open("master.key", "rb") as f:
                salt = f.read(16)
                stored_key = f.read()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            test_key = base64.urlsafe_b64encode(kdf.derive(current.encode()))
            
            if test_key != stored_key:
                self.print_error("Mot de passe actuel incorrect !")
                input("\nAppuyez sur Entrée pour continuer...")
                return
        except Exception as e:
            self.print_error(f"Erreur : {e}")
            return
        
        # Nouveau mot de passe
        new_pwd = self.input_box("Nouveau mot de passe :", password=True)
        confirm_pwd = self.input_box("Confirmez le nouveau mot de passe :", password=True)
        
        if new_pwd != confirm_pwd:
            self.print_error("Les mots de passe ne correspondent pas.")
            return
        
        if len(new_pwd) < 8:
            self.print_error("Le mot de passe doit faire au moins 8 caractères.")
            return
        
        # Générer nouvelle clé
        new_salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=new_salt,
            iterations=100000,
        )
        new_key = base64.urlsafe_b64encode(kdf.derive(new_pwd.encode()))
        
        # Chiffrer à nouveau les données avec la nouvelle clé
        old_cipher = self.cipher
        self.cipher = Fernet(new_key)
        
        data = self.load_data()
        self.save_data(data)  # Resauvegarde avec nouvelle clé
        
        # Sauvegarder nouvelle clé
        with open("master.key", "wb") as f:
            f.write(new_salt)
            f.write(new_key)
        
        self.print_success("✅  Mot de passe maître changé avec succès !")
        input("\nAppuyez sur Entrée pour continuer...")
    
    def backup_database(self):
        """Crée une sauvegarde."""
        self.print_header("SAUVEGARDE")
        
        if not os.path.exists(self.data_file):
            self.print_error("Aucune donnée à sauvegarder.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"backup_passwords_{timestamp}.encrypted"
        
        try:
            with open(self.data_file, 'rb') as src, open(backup_file, 'wb') as dst:
                dst.write(src.read())
            
            self.print_success(f"✅  Sauvegarde créée : {backup_file}")
            print(f"Taille : {os.path.getsize(backup_file):,} octets")
            
        except Exception as e:
            self.print_error(f"Erreur de sauvegarde : {e}")
        
        input("\nAppuyez sur Entrée pour continuer...")
    
    def exit_program(self):
        """Quitte le programme proprement."""
        self.print_header("AU REVOIR")
        print("\nMerci d'avoir utilisé Password Manager Pro !")
        print("Vos données sont sécurisées. 🔒")
        print("\n" + "="*70)
        sys.exit(0)
    
    def show_about(self):
        """Affiche les informations sur le programme."""
        self.print_header("À PROPOS")
        
        print("Password Manager Pro - Version 2.0")
        print("Développé pour Kali Linux")
        print("\n" + "-"*40)
        print("Fonctionnalités :")
        print("• 🔐  Chiffrement AES-256")
        print("• 🌐  Vérification API Have I Been Pwned")
        print("• 🛠️   Générateur de mots de passe")
        print("• 📊  Statistiques détaillées")
        print("• 💾  Sauvegarde/restauration")
        print("\n" + "-"*40)
        print("Sécurité :")
        print("• Mot de passe maître requis")
        print("• Données chiffrées localement")
        print("• Aucune donnée envoyée à des tiers")
        print("\n" + "="*40)
        
        input("\nAppuyez sur Entrée pour continuer...")

def main():
    """Point d'entrée principal."""
    try:
        # Vérifier les dépendances
        import requests
        from cryptography.fernet import Fernet
        
        manager = PasswordManagerUI()
        manager.show_main_menu()
        
    except ImportError as e:
        print(f"❌ Module manquant : {e}")
        print("\nInstallez les dépendances :")
        print("pip install requests cryptography")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n👋  Programme interrompu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur inattendue : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
