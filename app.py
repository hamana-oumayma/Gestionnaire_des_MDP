"""
Password Manager Web - Interface Web Complète
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_session import Session
import sqlite3
import hashlib
import json
import os
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
import random
import string

# Configuration de l'application
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 heure

Session(app)

# Chemins
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data', 'passwords.db')
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Créer le dossier data s'il n'existe pas
os.makedirs(DATA_DIR, exist_ok=True)

class PasswordManager:
    def __init__(self, user_id=None):
        self.user_id = user_id
        self.init_db()
    
    def init_db(self):
        """Initialise la base de données."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Table des utilisateurs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                master_key BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table des mots de passe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                url TEXT,
                category TEXT DEFAULT 'Autre',
                notes TEXT,
                breach_count INTEGER DEFAULT 0,
                strength_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Table des sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_user(self, username, master_password):
        """Crée un nouvel utilisateur."""
        # Générer un sel unique
        salt = os.urandom(16)
        
        # Dériver la clé maîtresse
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        master_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        # Sauvegarder dans la base de données
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, master_key, salt) VALUES (?, ?, ?)',
                (username, master_key, salt)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            # Créer un répertoire utilisateur pour les clés
            user_dir = os.path.join(DATA_DIR, f"user_{user_id}")
            os.makedirs(user_dir, exist_ok=True)
            
            return user_id
        except sqlite3.IntegrityError:
            return None  # Utilisateur existe déjà
        finally:
            conn.close()
    
    def authenticate_user(self, username, master_password):
        """Authentifie un utilisateur."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, master_key, salt FROM users WHERE username = ?',
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return None
        
        user_id, stored_key, salt = user
        
        # Dériver la clé depuis le mot de passe fourni
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        test_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        if test_key == stored_key:
            return user_id
        return None
    
    def get_cipher(self, user_id, master_password):
        """Retourne un objet Fernet pour le chiffrement."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT salt FROM users WHERE id = ?',
            (user_id,)
        )
        salt = cursor.fetchone()[0]
        conn.close()
        
        # Dériver la clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        return Fernet(key)
    
    def add_password(self, user_id, master_password, service, username, password, 
                     url='', category='Autre', notes=''):
        """Ajoute un mot de passe chiffré."""
        cipher = self.get_cipher(user_id, master_password)
        encrypted_password = cipher.encrypt(password.encode())
        
        # Vérifier les fuites (optionnel)
        breach_count = self.check_breaches(password)
        
        # Calculer la force
        strength_score = self.calculate_strength(password)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO passwords 
            (user_id, service, username, encrypted_password, url, category, notes, breach_count, strength_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, service, username, encrypted_password, url, category, notes, breach_count, strength_score))
        
        conn.commit()
        conn.close()
        
        return cursor.lastrowid
    
    def get_passwords(self, user_id, master_password):
        """Récupère tous les mots de passe déchiffrés."""
        cipher = self.get_cipher(user_id, master_password)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, service, username, encrypted_password, url, category, notes, 
                   breach_count, strength_score, created_at, updated_at
            FROM passwords 
            WHERE user_id = ?
            ORDER BY service
        ''', (user_id,))
        
        passwords = []
        for row in cursor.fetchall():
            try:
                decrypted_password = cipher.decrypt(row[3]).decode()
                passwords.append({
                    'id': row[0],
                    'service': row[1],
                    'username': row[2],
                    'password': decrypted_password,
                    'url': row[4],
                    'category': row[5],
                    'notes': row[6],
                    'breach_count': row[7],
                    'strength_score': row[8],
                    'created_at': row[9],
                    'updated_at': row[10]
                })
            except:
                continue  # Ignorer les entrées corrompues
        
        conn.close()
        return passwords
    
    def check_breaches(self, password):
        """Vérifie si le mot de passe est dans des fuites."""
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                headers={'User-Agent': 'PasswordManager-Web'},
                timeout=5
            )
            
            if response.status_code == 200:
                suffix = sha1_hash[5:]
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        return int(line.split(':')[1])
            return 0
        except:
            return 0  # Retourne 0 en cas d'erreur
    
    def calculate_strength(self, password):
        """Calcule un score de force (0-100)."""
        score = 0
        
        # Longueur
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Diversité des caractères
        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 10
        if any(c in "!@#$%^&*()_-+=[]{}|;:,.<>?" for c in password):
            score += 10
        
        # Pas de motifs simples
        motifs = ["123", "abc", "password", "admin", "qwerty", "azerty"]
        if not any(motif in password.lower() for motif in motifs):
            score += 20
        
        return min(score, 100)
    
    def generate_password(self, length=16, use_lower=True, use_upper=True, 
                         use_digits=True, use_symbols=True):
        """Génère un mot de passe aléatoire."""
        chars = ''
        if use_lower:
            chars += string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()_-+=[]{}|;:,.<>?"
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        # Garantir au moins un de chaque type sélectionné
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
        while len(password) < length:
            password.append(random.choice(chars))
        
        random.shuffle(password)
        return ''.join(password)

# Routes Flask
@app.route('/')
def index():
    """Page d'accueil."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        manager = PasswordManager()
        user_id = manager.authenticate_user(username, password)
        
        if user_id:
            session['user_id'] = user_id
            session['username'] = username
            session['master_password'] = password  # Temporaire pour la session
            flash('Connexion réussie !', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Page d'inscription."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            flash('Tous les champs sont requis.', 'danger')
        elif password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        elif len(password) < 8:
            flash('Le mot de passe doit faire au moins 8 caractères.', 'danger')
        else:
            manager = PasswordManager()
            user_id = manager.create_user(username, password)
            
            if user_id:
                flash('Compte créé avec succès ! Connectez-vous.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Ce nom d\'utilisateur existe déjà.', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Tableau de bord."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager(session['user_id'])
    passwords = manager.get_passwords(session['user_id'], session.get('master_password', ''))
    
    # Statistiques
    stats = {
        'total': len(passwords),
        'compromised': sum(1 for p in passwords if p['breach_count'] > 0),
        'average_strength': sum(p['strength_score'] for p in passwords) / max(len(passwords), 1),
        'categories': {}
    }
    
    for p in passwords:
        cat = p['category']
        stats['categories'][cat] = stats['categories'].get(cat, 0) + 1
    
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         stats=stats,
                         passwords=passwords[:5])

@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    """Ajouter un mot de passe."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager(session['user_id'])
    
    if request.method == 'POST':
        service = request.form.get('service')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url', '')
        category = request.form.get('category', 'Autre')
        notes = request.form.get('notes', '')
        
        if not service or not username or not password:
            flash('Les champs Service, Utilisateur et Mot de passe sont requis.', 'danger')
        else:
            pid = manager.add_password(
                session['user_id'],
                session.get('master_password', ''),
                service, username, password, url, category, notes
            )
            
            if pid:
                flash('Mot de passe ajouté avec succès !', 'success')
                return redirect(url_for('view_passwords'))
            else:
                flash('Erreur lors de l\'ajout.', 'danger')
    
    return render_template('add_password.html')

@app.route('/view-passwords')
def view_passwords():
    """Voir tous les mots de passe."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager(session['user_id'])
    passwords = manager.get_passwords(session['user_id'], session.get('master_password', ''))
    
    # Filtrer par catégorie si spécifié
    category = request.args.get('category', '')
    if category:
        passwords = [p for p in passwords if p['category'] == category]
    
    # Recherche
    search = request.args.get('search', '')
    if search:
        passwords = [p for p in passwords 
                    if search.lower() in p['service'].lower() 
                    or search.lower() in p['username'].lower()]
    
    return render_template('view_passwords.html', passwords=passwords)

@app.route('/generator', methods=['GET', 'POST'])
def generator():
    """Générateur de mots de passe."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager(session['user_id'])
    generated_password = None
    breach_check = None
    
    if request.method == 'POST':
        length = int(request.form.get('length', 16))
        use_lower = 'lowercase' in request.form
        use_upper = 'uppercase' in request.form
        use_digits = 'digits' in request.form
        use_symbols = 'symbols' in request.form
        
        generated_password = manager.generate_password(
            length, use_lower, use_upper, use_digits, use_symbols
        )
        
        # Vérifier les fuites
        breach_check = manager.check_breaches(generated_password)
    
    return render_template('generator.html', 
                         generated_password=generated_password,
                         breach_check=breach_check)

@app.route('/api/generate', methods=['POST'])
def api_generate():
    """API pour générer un mot de passe."""
    data = request.json
    length = data.get('length', 16)
    use_lower = data.get('lowercase', True)
    use_upper = data.get('uppercase', True)
    use_digits = data.get('digits', True)
    use_symbols = data.get('symbols', True)
    
    manager = PasswordManager()
    password = manager.generate_password(length, use_lower, use_upper, use_digits, use_symbols)
    
    return jsonify({
        'password': password,
        'length': len(password),
        'breach_count': manager.check_breaches(password),
        'strength': manager.calculate_strength(password)
    })

@app.route('/api/check', methods=['POST'])
def api_check():
    """API pour vérifier un mot de passe."""
    data = request.json
    password = data.get('password', '')
    
    manager = PasswordManager()
    breach_count = manager.check_breaches(password)
    strength = manager.calculate_strength(password)
    
    return jsonify({
        'breach_count': breach_count,
        'strength': strength,
        'status': 'safe' if breach_count == 0 else 'compromised'
    })

@app.route('/settings')
def settings():
    """Paramètres."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('settings.html')

@app.route('/logout')
def logout():
    """Déconnexion."""
    session.clear()
    flash('Déconnexion réussie.', 'info')
    return redirect(url_for('index'))

# Gestion des erreurs
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Créer les tables
    manager = PasswordManager()
    
    # Démarrer Flask
    print("🔐 Password Manager Web")
    print("🌐 Serveur démarré sur http://localhost:5000")
    print("📁 Base de données : data/passwords.db")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
