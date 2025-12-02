"""
Générateur de mots de passe basique
"""

import random
import string

def ask_yes_no(question):
    """Pose une question oui/non."""
    while True:
        answer = input(question + " (o/n) : ").strip().lower()
        if answer in ["o", "oui", "y", "yes"]:
            return True
        elif answer in ["n", "non", "no"]:
            return False
        else:
            print("Réponse invalide. Réponds par 'o' ou 'n'.")

def main():
    print("=" * 50)
    print("GÉNÉRATEUR DE MOTS DE PASSE - VERSION BASIQUE")
    print("=" * 50)
    
    # Longueur
    while True:
        try:
            length = int(input("Longueur du mot de passe : "))
            if length > 0:
                break
            else:
                print("La longueur doit être positive.")
        except ValueError:
            print("Entrez un nombre valide.")
    
    # Options
    print("\nSélection des caractères :")
    use_lower = ask_yes_no("Lettres minuscules ?")
    use_upper = ask_yes_no("Lettres majuscules ?")
    use_digits = ask_yes_no("Chiffres ?")
    use_symbols = ask_yes_no("Symboles ?")
    
    # Caractères disponibles
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
        print("Erreur : Aucun type sélectionné.")
        return
    
    # Génération
    password = ''.join(random.choices(chars, k=length))
    
    print("\n" + "=" * 50)
    print("RÉSULTAT :")
    print(f"Mot de passe : {password}")
    print(f"Longueur : {len(password)} caractères")
    print("=" * 50)

if __name__ == "__main__":
    main()
