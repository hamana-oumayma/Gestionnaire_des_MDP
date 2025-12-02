#!/usr/bin/env python3
"""
Générateur avec vérification API - Version améliorée
"""

import random
import string
import hashlib
import requests
import time
import sys
from datetime import datetime

def ask_yes_no(question):
    """Pose une question oui/non."""
    while True:
        answer = input(question + " (o/n) : ").strip().lower()
        if answer in ["o", "oui", "y", "yes"]:
            return True
        elif answer in ["n", "non", "no"]:
            return False
        else:
            print("❓ Réponse invalide. Réponds par 'o' (oui) ou 'n' (non).")

def afficher_logo():
    """Affiche un logo ASCII pour le générateur."""
    print("\n" + "="*60)
    print("""
    ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ 
    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
    ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
    ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
    ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ 
    """)
    print("           GÉNÉRATEUR DE MOTS DE PASSE SÉCURISÉS")
    print("="*60 + "\n")

def afficher_info_securite():
    """Affiche des informations de sécurité importantes."""
    print("🔐  INFORMATIONS DE SÉCURITÉ")
    print("-"*40)
    print("• Ce générateur vérifie vos mots de passe contre")
    print("  plus de 1 milliard de fuites de données")
    print("• Votre mot de passe n'est JAMAIS envoyé en clair")
    print("• Seuls les 5 premiers caractères du hash sont envoyés")
    print("• Données fournies par Have I Been Pwned (Troy Hunt)")
    print("-"*40 + "\n")

def afficher_progression(etape, total, message):
    """Affiche une barre de progression."""
    pourcentage = int((etape / total) * 100)
    barre = "█" * (pourcentage // 2) + "░" * (50 - (pourcentage // 2))
    print(f"\r[{barre}] {pourcentage}% - {message}", end="", flush=True)
    if etape == total:
        print()

def verifier_mot_de_passe_api(password):
    """
    Vérifie si le mot de passe a été compromis.
    Retourne: (est_compromis, nombre_fuites, temps_reponse)
    """
    print("\n" + "🔍  VÉRIFICATION EN LIGNE")
    print("-"*40)
    
    # Explication du processus
    print("Étape 1/3 : Calcul du hash sécurisé...")
    time.sleep(0.5)
    
    # Calcul du hash SHA-1
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    print(f"Étape 2/3 : Hash calculé : {prefix}*****")
    print("Étape 3/3 : Interrogation de la base de données...")
    
    debut = time.time()
    
    try:
        # Simulation de progression
        for i in range(1, 101):
            afficher_progression(i, 100, "Recherche dans la base de données")
            time.sleep(0.01)
        
        # Requête à l'API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {
            'User-Agent': 'PasswordManager-Kali-FR/1.0',
            'Add-Padding': 'true'
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        temps_reponse = time.time() - debut
        
        if response.status_code == 200:
            # Chercher le suffixe dans les résultats
            for ligne in response.text.splitlines():
                if ligne.startswith(suffix):
                    nombre_fuites = int(ligne.split(':')[1])
                    return True, nombre_fuites, temps_reponse
            
            return False, 0, temps_reponse
        else:
            return None, 0, temps_reponse
            
    except requests.exceptions.RequestException as e:
        return None, 0, time.time() - debut

def afficher_resultat_verification(password, est_compromis, nombre_fuites, temps_reponse):
    """Affiche le résultat de la vérification de manière claire."""
    
    print("\n" + "📊  RÉSULTAT DE LA VÉRIFICATION")
    print("="*40)
    
    # Affichage basique
    print(f"Mot de passe testé : {'*' * len(password)}")
    print(f"Temps de réponse : {temps_reponse:.2f} secondes")
    
    if est_compromis is None:
        print("\n⚠️  STATUT : VÉRIFICATION IMPOSSIBLE")
        print("   • Problème de connexion Internet")
        print("   • L'API peut être temporairement indisponible")
        print("   • Vérifiez votre connexion et réessayez")
        return
    
    if est_compromis:
        print(f"\n🚨  ALERTE DE SÉCURITÉ : MOT DE PASSE COMPROMIS")
        print("="*40)
        
        # Niveau de danger
        if nombre_fuites > 1000000:
            niveau = "🔴 DANGER EXTRÊME"
        elif nombre_fuites > 100000:
            niveau = "🔴 TRÈS DANGEREUX"
        elif nombre_fuites > 10000:
            niveau = "🟠 DANGEREUX"
        elif nombre_fuites > 1000:
            niveau = "🟠 RISQUÉ"
        else:
            niveau = "🟡 ATTENTION"
        
        print(f"Niveau de risque : {niveau}")
        print(f"Nombre de fuites : {nombre_fuites:,}")
        
        # Explications
        print("\n📈  CE QUE CELA SIGNIFIE :")
        if nombre_fuites > 1000000:
            print("   • Votre mot de passe est parmi les PLUS UTILISÉS au monde")
            print("   • Les hackers le testent EN PREMIER")
            print("   • Cracké en MOINS D'UNE SECONDE")
        elif nombre_fuites > 100000:
            print("   • Extrêmement courant dans les fuites de données")
            print("   • Cracké en quelques secondes")
            print("   • Jamais utiliser pour des comptes importants")
        
        print("\n💡  RECOMMANDATIONS :")
        print("   1. NE JAMAIS UTILISER ce mot de passe")
        print("   2. Changer immédiatement si déjà utilisé")
        print("   3. Utiliser notre générateur pour en créer un nouveau")
        print("   4. Activer l'authentification à deux facteurs")
        
    else:
        print("\n✅  STATUT : MOT DE PASSE SÉCURISÉ")
        print("-"*40)
        print("   • Non trouvé dans les fuites de données connues")
        print("   • Bonne base pour un mot de passe sécurisé")
        print("   • Vérifiez aussi sa longueur et complexité")
        
        # Conseils supplémentaires
        print("\n💡  CONSEILS POUR RENFORCER :")
        if len(password) < 12:
            print(f"   • Augmenter la longueur (actuel : {len(password)} caractères)")
        if not any(c.isdigit() for c in password):
            print("   • Ajouter des chiffres")
        if not any(c in "!@#$%^&*()_-+=[]{}|;:,.<>?" for c in password):
            print("   • Ajouter des symboles spéciaux")

def analyser_complexite(password):
    """Analyse la complexité du mot de passe."""
    print("\n🔬  ANALYSE DE COMPLEXITÉ")
    print("-"*40)
    
    score = 0
    max_score = 6
    
    # Longueur
    if len(password) >= 8:
        score += 1
        print(f"✅ Longueur : {len(password)} caractères (minimum 8)")
    else:
        print(f"❌ Longueur : {len(password)} caractères (trop court!)")
    
    # Minuscules
    if any(c.islower() for c in password):
        score += 1
        print("✅ Contient des lettres minuscules")
    else:
        print("❌ Pas de lettres minuscules")
    
    # Majuscules
    if any(c.isupper() for c in password):
        score += 1
        print("✅ Contient des lettres majuscules")
    else:
        print("❌ Pas de lettres majuscules")
    
    # Chiffres
    if any(c.isdigit() for c in password):
        score += 1
        print("✅ Contient des chiffres")
    else:
        print("❌ Pas de chiffres")
    
    # Symboles
    if any(c in "!@#$%^&*()_-+=[]{}|;:,.<>?" for c in password):
        score += 1
        print("✅ Contient des symboles spéciaux")
    else:
        print("❌ Pas de symboles spéciaux")
    
    # Motifs simples
    motifs_dangereux = ["123", "abc", "qwerty", "azerty", "password", "admin"]
    has_motif = any(motif in password.lower() for motif in motifs_dangereux)
    if not has_motif:
        score += 1
        print("✅ Pas de motifs évidents")
    else:
        print("❌ Contient des motifs trop simples")
    
    # Note finale
    pourcentage = int((score / max_score) * 100)
    print(f"\n📊 NOTE : {pourcentage}%")
    
    if pourcentage >= 85:
        print("🏆 EXCELLENT : Mot de passe très sécurisé")
    elif pourcentage >= 70:
        print("👍 BON : Mot de passe correct")
    elif pourcentage >= 50:
        print("⚠️  MOYEN : Améliorations nécessaires")
    else:
        print("🚨 FAIBLE : À changer immédiatement")

def generer_mot_de_passe(longueur, use_lower, use_upper, use_digits, use_symbols):
    """Génère un mot de passe sécurisé."""
    chars = ""
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()_-+=[]{}|;:,.<>?"
    
    if not chars:
        raise ValueError("Aucun type de caractère sélectionné.")
    
    # Génération avec garantie de diversité
    password = []
    if use_lower:
        password.append(random.choice(string.ascii_lowercase))
    if use_upper:
        password.append(random.choice(string.ascii_uppercase))
    if use_digits:
        password.append(random.choice(string.digits))
    if use_symbols:
        password.append(random.choice("!@#$%^&*()_-+=[]{}|;:,.<>?"))
    
    # Compléter
    while len(password) < longueur:
        password.append(random.choice(chars))
    
    random.shuffle(password)
    return ''.join(password)

def main():
    """Fonction principale."""
    afficher_logo()
    afficher_info_securite()
    
    # Vérifier la connexion Internet
    print("🌐  Vérification de la connexion Internet...")
    try:
        requests.get("https://api.pwnedpasswords.com", timeout=3)
        print("✅  Connecté à l'API de vérification\n")
    except:
        print("⚠️   Pas de connexion Internet détectée\n")
        print("   Le générateur fonctionnera sans vérification API")
        print("   Activez Internet pour une sécurité maximale\n")
    
    print("="*60)
    print("CONFIGURATION DU MOT DE PASSE")
    print("="*60)
    
    # Configuration
    while True:
        try:
            longueur = int(input("\nLongueur du mot de passe (recommandé : 12+) : "))
            if longueur > 0:
                if longueur < 8:
                    print("⚠️  Attention : Moins de 8 caractères = TRÈS FAIBLE")
                    confirmer = input("   Voulez-vous continuer ? (o/n) : ").lower()
                    if confirmer != 'o':
                        continue
                break
            else:
                print("❌ La longueur doit être positive.")
        except ValueError:
            print("❌ Veuillez entrer un nombre valide.")
    
    print("\nSélectionnez les types de caractères :")
    use_lower = ask_yes_no("  • Lettres minuscules (a-z) ?")
    use_upper = ask_yes_no("  • Lettres majuscules (A-Z) ?")
    use_digits = ask_yes_no("  • Chiffres (0-9) ?")
    use_symbols = ask_yes_no("  • Symboles spéciaux (!@#$...) ?")
    
    if not any([use_lower, use_upper, use_digits, use_symbols]):
        print("\n❌ ERREUR : Vous devez sélectionner au moins un type de caractère.")
        return
    
    # Génération
    print("\n" + "="*60)
    print("GÉNÉRATION EN COURS...")
    print("="*60)
    
    try:
        password = generer_mot_de_passe(longueur, use_lower, use_upper, use_digits, use_symbols)
        
        # Vérification API
        est_compromis, nombre_fuites, temps_reponse = verifier_mot_de_passe_api(password)
        
        # Affichage des résultats
        print("\n" + "="*60)
        print("📋  RÉSUMÉ DU MOT DE PASSE GÉNÉRÉ")
        print("="*60)
        
        # Afficher le mot de passe
        print(f"\n🔑  VOTRE MOT DE PASSE :")
        print(f"   {password}")
        print(f"   Longueur : {len(password)} caractères")
        
        # Vérification API
        afficher_resultat_verification(password, est_compromis, nombre_fuites, temps_reponse)
        
        # Analyse de complexité
        analyser_complexite(password)
        
        # Conseils de stockage
        print("\n" + "="*60)
        print("💾  CONSEILS DE STOCKAGE")
        print("="*60)
        print("• Utilisez ce mot de passe pour UN SEUL service")
        print("• Ne le partagez JAMAIS par email ou message")
        print("• Utilisez un gestionnaire de mots de passe")
        print("• Activez l'authentification à deux facteurs")
        print("• Changez-le tous les 6-12 mois")
        
    except Exception as e:
        print(f"\n❌ ERREUR : {e}")
        return
    
    # Option de vérification personnalisée
    print("\n" + "="*60)
    print("🔍  VÉRIFICATION PERSONNALISÉE")
    print("="*60)
    
    while True:
        choix = input("\nVoulez-vous vérifier un autre mot de passe ? (o/n) : ").lower()
        if choix in ['n', 'non', 'no']:
            break
        elif choix in ['o', 'oui', 'y', 'yes']:
            mot_a_verifier = input("\nMot de passe à vérifier : ")
            
            if not mot_a_verifier:
                print("❌ Veuillez entrer un mot de passe")
                continue
            
            print(f"\n{'='*60}")
            print(f"VÉRIFICATION DE : {'*' * len(mot_a_verifier)}")
            print(f"{'='*60}")
            
            est_comp, nb_fuites, temps = verifier_mot_de_passe_api(mot_a_verifier)
            afficher_resultat_verification(mot_a_verifier, est_comp, nb_fuites, temps)
            analyser_complexite(mot_a_verifier)
        else:
            print("❌ Réponse invalide.")
    
    print("\n" + "="*60)
    print("🎉  GÉNÉRATION TERMINÉE")
    print("="*60)
    print("\nMerci d'avoir utilisé notre générateur sécurisé !")
    print("Restez en sécurité en ligne 🔒\n")

if __name__ == "__main__":
    try:
        import requests
    except ImportError:
        print("❌ ERREUR : Le module 'requests' n'est pas installé.")
        print("   Installez-le avec : pip install requests")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋  Opération annulée par l'utilisateur.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERREUR INATTENDUE : {e}")
        print("   Contactez le support si le problème persiste.")
        sys.exit(1)
