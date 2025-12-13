from flask import Flask, render_template_string, request, jsonify, g, redirect, url_for, flash
import sqlite3
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os 
from werkzeug.utils import secure_filename
import base64
from PIL import Image
import io
import tempfile
from pathlib import Path

# --- 0. INITIALISATION DE LA DB ---
def init_db():
    # Sur Vercel, on utilise /tmp pour les fichiers temporaires
    db_path = '/tmp/tacheo_auth.db' if os.environ.get('VERCEL') else 'tacheo_auth.db'
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Table des utilisateurs
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            profile_photo TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Table des tâches AVEC LE BON SCHÉMA
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            due_date TEXT,
            priority TEXT DEFAULT 'important',
            category TEXT DEFAULT 'personnel',
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

# --- APPEL UNIQUE POUR CREER LES TABLES ---
# Initialisation différée pour Vercel
if not os.environ.get('VERCEL'):
    init_db()

# --- 1. INITIALISATION ET CONFIGURATION ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
# Configuration pour Vercel (utilise /tmp pour les fichiers)
app.config['DATABASE'] = '/tmp/tacheo_auth.db' if os.environ.get('VERCEL') else 'tacheo_auth.db'

# Configuration pour les fichiers
if os.environ.get('VERCEL'):
    # Sur Vercel, on utilise /tmp pour les uploads
    app.config['UPLOAD_FOLDER'] = '/tmp/static/uploads'
else:
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} 

# Créer le dossier uploads s'il n'existe pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def process_image(file_stream, max_size=(400, 400)):
    """Traite l'image pour qu'elle soit carrée et de taille optimale"""
    try:
        img = Image.open(file_stream)
        
        # Convertir en RGB si nécessaire
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        
        # Rendre l'image carrée
        width, height = img.size
        min_dimension = min(width, height)
        
        # Calculer les coordonnées de recadrage
        left = (width - min_dimension) / 2
        top = (height - min_dimension) / 2
        right = (width + min_dimension) / 2
        bottom = (height + min_dimension) / 2
        
        # Recadrer l'image pour la rendre carrée
        img = img.crop((left, top, right, bottom))
        
        # Redimensionner l'image
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Sauvegarder en mémoire
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=85, optimize=True)
        buffer.seek(0)
        
        return buffer
    except Exception as e:
        print(f"Erreur lors du traitement de l'image: {e}")
        return None

# --- 2. GESTION DE LA BASE DE DONNÉES (GLOBAL ET AUTH) ---

class User(UserMixin):
    def __init__(self, id, username, password_hash, profile_photo=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.profile_photo = profile_photo

def get_db():
    if 'db' not in g:
        # Initialiser la base de données si elle n'existe pas encore
        if not os.path.exists(app.config['DATABASE']):
            init_db()
            
        g.db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row 
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- 3. FLASK-LOGIN (AUTHENTIFICATION) ---

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute('SELECT id, username, password_hash, profile_photo FROM users WHERE id = ?', (user_id,)).fetchone()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['profile_photo'])
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            return render_template_string(AUTH_FORM, error="Tous les champs sont requis.", is_register=True) 
            
        hashed_password = generate_password_hash(password)
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password_hash, profile_photo) VALUES (?, ?, NULL)', (username, hashed_password))
            db.commit()
            
            # Connexion automatique après inscription
            user_data = db.execute('SELECT id, username, password_hash, profile_photo FROM users WHERE username = ?', (username,)).fetchone()
            if user_data:
                user = User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['profile_photo'])
                login_user(user)
                return redirect(url_for('index'))
            
        except sqlite3.IntegrityError:
            return render_template_string(AUTH_FORM, error="Ce nom d'utilisateur existe déjà. Veuillez en choisir un autre.", is_register=True)
        except Exception as e:
            return render_template_string(AUTH_FORM, error=f"Erreur d'enregistrement: {e}", is_register=True)
            
    return render_template_string(AUTH_FORM, is_register=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember_me') == 'on'
        
        db = get_db()
        user_data = db.execute('SELECT id, username, password_hash, profile_photo FROM users WHERE username = ?', (username,)).fetchone() 
        
        if user_data:
            if check_password_hash(user_data['password_hash'], password):
                user = User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['profile_photo'])
                login_user(user, remember=remember)
                return redirect(url_for('index'))
            else:
                return render_template_string(AUTH_FORM, error="Mot de passe incorrect.", is_register=False)
        else:
            return render_template_string(AUTH_FORM, error="Compte introuvable.", is_register=False)
    
    return render_template_string(AUTH_FORM, is_register=False)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# --- 4. TEMPLATE HTML D'AUTHENTIFICATION (AUTH_FORM) ---

AUTH_FORM = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ 'Inscription' if is_register else 'Connexion' }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .main-auth-wrapper { display: flex; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 900px; width: 90%; min-height: 500px; overflow: hidden; }
        
        .promo-side { flex: 1; background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); color: white; padding: 40px; display: flex; flex-direction: column; justify-content: center; text-align: left; position: relative; }
        .promo-side h2 { font-size: 2.5em; margin-bottom: 20px; border-bottom: 3px solid rgba(255,255,255,0.3); padding-bottom: 10px; }
        .promo-side p { font-size: 1.1em; line-height: 1.6; margin-bottom: 20px; }
        .promo-side ul { list-style: none; padding-left: 0; }
        .promo-side ul li { margin-bottom: 10px; font-weight: bold; }

        .auth-side { flex: 1; padding: 40px; display: flex; flex-direction: column; justify-content: center; text-align: center; }
        .auth-side h1 { color: #667eea; margin-bottom: 30px; }
        
        input[type="text"], input[type="password"] { width: 100%; padding: 15px; margin-bottom: 20px; border: 2px solid #ccc; border-radius: 10px; box-sizing: border-box; font-size: 16px; transition: border-color 0.3s; }
        input[type="text"]:focus, input[type="password"]:focus { border-color: #667eea; outline: none; }
        
        .form-group-checkbox { display: flex; align-items: center; justify-content: flex-start; margin-bottom: 20px; }
        .form-group-checkbox input[type="checkbox"] { width: auto; margin: 0 10px 0 0; }
        .form-group-checkbox label { color: #667eea; font-weight: bold; display: inline; cursor: pointer; }
        
        button { width: 100%; padding: 15px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; border: none; border-radius: 10px; font-size: 18px; font-weight: bold; cursor: pointer; transition: opacity 0.3s, transform 0.3s; }
        button:hover { opacity: 0.9; transform: translateY(-2px); }
        .error { color: #dc3545; margin-bottom: 15px; font-weight: bold; }
        .link { margin-top: 20px; font-size: 14px; }
        .link a { color: #667eea; text-decoration: none; font-weight: bold; }
        .link a:hover { text-decoration: underline; }

        /* Mobile promo - visible uniquement sur mobile */
        .mobile-promo { display: none; background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); color: white; padding: 25px; border-radius: 15px 15px 0 0; margin-bottom: 20px; }
        .mobile-promo h3 { font-size: 1.5em; margin-bottom: 15px; text-align: center; border-bottom: 2px solid rgba(255,255,255,0.3); padding-bottom: 10px; }
        .mobile-promo p { font-size: 0.95em; line-height: 1.5; margin-bottom: 15px; }
        .mobile-promo ul { list-style: none; padding-left: 0; margin: 0; }
        .mobile-promo ul li { margin-bottom: 8px; font-size: 0.9em; padding-left: 20px; position: relative; }
        .mobile-promo ul li:before { content: "✓"; position: absolute; left: 0; color: #4CAF50; font-weight: bold; }
        
        @media (max-width: 768px) {
            .main-auth-wrapper { flex-direction: column; min-height: auto; border-radius: 15px; }
            .promo-side { display: none; } 
            .mobile-promo { display: block; }
            .auth-side { padding: 30px 25px; }
            input[type="text"], input[type="password"] { padding: 14px; font-size: 16px; }
            button { padding: 14px; font-size: 17px; }
            .auth-side h1 { font-size: 1.8em; margin-bottom: 25px; }
            .mobile-promo h3 { font-size: 1.4em; }
        }
        
        @media (max-width: 480px) {
            .main-auth-wrapper { width: 95%; border-radius: 12px; }
            .auth-side { padding: 25px 20px; }
            .auth-side h1 { font-size: 1.6em; margin-bottom: 20px; }
            .form-group-checkbox { margin-bottom: 15px; }
            .mobile-promo { padding: 20px; }
            .mobile-promo h3 { font-size: 1.3em; }
        }
        
        /* Pour les très petits écrans */
        @media (max-width: 360px) {
            .auth-side h1 { font-size: 1.5em; }
            input[type="text"], input[type="password"] { padding: 12px; font-size: 15px; }
            button { padding: 12px; font-size: 16px; }
            .mobile-promo { padding: 18px 15px; }
        }
        
        /* Améliorations pour tablette */
        @media (min-width: 769px) and (max-width: 1024px) {
            .main-auth-wrapper { max-width: 850px; }
            .promo-side { padding: 30px; }
            .auth-side { padding: 30px; }
            .promo-side h2 { font-size: 2.2em; }
            .promo-side p { font-size: 1em; }
        }
    </style>
</head>
<body>
    <div class="main-auth-wrapper">
        <!-- Mobile promo - visible uniquement sur mobile -->
        <div class="mobile-promo">
            <h3>📝 Tacheo - Gérez vos tâches facilement</h3>
            <p>Votre assistant personnel pour une productivité maximale. Organisez, priorisez et accomplissez vos tâches en toute simplicité.</p>
            <ul>
                <li>Création et gestion intuitive de tâches</li>
                <li>Catégories personnalisables</li>
                <li>Rappels et échéances</li>
                <li>Accès sécurisé et synchronisé</li>
                <li>Interface optimisée mobile et desktop</li>
            </ul>
        </div>
        
        <!-- Desktop promo - visible uniquement sur desktop -->
        <div class="promo-side">
            <h2>📝 Tacheo : Gérez vos tâches facilement !</h2>
            <p>Notre gestionnaire de tâches intuitive vous offre une organisation parfaite et une productivité maximale. Simplifiez votre quotidien dès maintenant !</p>
            <ul>
                <li>✅ Catégorisation Intuitive (Travail, Perso, Sport)</li>
                <li>📅 Tri par Date (Plus proche d'abord)</li>
                <li>🗑 Corbeille Sécurisée pour ne rien perdre</li>
                <li>🔒 Accès Sécurisé et Personnalisé</li>
                <li>📱 Interface Mobile Optimisée</li>
            </ul>
        </div>
        
        <div class="auth-side">
            <h1>{{ 'Créer un Compte' if is_register else 'Connexion' }}</h1>
            {% if error %}<div class="error">{{ error }}</div>{% endif %}

            <form method="POST" id="authForm" style="margin-top: 20px;">
                <input type="text" name="username" placeholder="Nom d'utilisateur" required id="usernameInput">
                
                <div id="passwordContainer">
                    <input type="password" name="password" placeholder="Mot de Passe" required id="passwordInput">
                </div>
                
                {% if not is_register %}
                <div class="form-group-checkbox" id="rememberMeContainer">
                    <input type="checkbox" name="remember_me" id="remember_me">
                    <label for="remember_me">Rester connecté</label>
                </div>
                {% endif %}
                
                <button type="submit" id="loginButton">{{ "S'inscrire" if is_register else "Se Connecter" }}</button>
            </form>
            <div class="link">
                {% if is_register %}
                    Déjà un compte ? <a href="{{ url_for('login') }}">Connectez-vous</a>
                {% else %}
                    Pas encore de compte ? <a href="{{ url_for('register') }}">Inscrivez-vous</a>
                {% endif %}
            </div>
        </div>
    </div>
</body>
</html>
'''

# --- 5. TEMPLATE HTML/JAVASCRIPT DU GESTIONNAIRE DE TÂCHES (FRONTEND) ---

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
    <title>📝 Tacheo</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --primary-light: rgba(102, 126, 234, 0.1);
            --white: #ffffff;
            --gray-light: #f8f9fa;
            --gray: #6c757d;
            --gray-dark: #343a40;
            --success: #28a745;
            --warning: #ffc107;
            --danger: #dc3545;
            --info: #17a2b8;
            --shadow: 0 4px 12px rgba(0,0,0,0.1);
            --shadow-heavy: 0 8px 25px rgba(0,0,0,0.2);
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-xl: 24px;
            --radius-xxl: 30px;
        }
        
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
            -webkit-tap-highlight-color: transparent;
        }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            min-height: 100vh; 
            padding: 16px;
            position: relative; 
            overflow-x: hidden;
            line-height: 1.5;
            font-size: 16px;
            color: var(--gray-dark);
        }
        
        /* Améliorations pour mobile */
        @media (max-width: 768px) {
            body {
                padding: 12px;
                font-size: 15px;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 10px;
                font-size: 14px;
            }
        }
        
        /* Suppression des sidebars sur mobile */
        .sidebar-left, .sidebar-right {
            position: fixed; 
            top: 0; 
            width: 80px; 
            height: 100vh; 
            z-index: 1;
            background: linear-gradient(180deg, rgba(255,255,255,0.1) 0%, transparent 70%);
            backdrop-filter: blur(20px); 
            border-radius: 0 var(--radius-xl) var(--radius-xl) 0;
        }
        
        .sidebar-left { 
            left: 0; 
            transform: skew(-15deg); 
        }
        
        .sidebar-right { 
            right: 0; 
            transform: skew(15deg); 
            border-radius: var(--radius-xl) 0 0 var(--radius-xl); 
        }
        
        @media (max-width: 992px) {
            .sidebar-left, .sidebar-right {
                display: none;
            }
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            position: relative; 
            z-index: 10; 
            width: 100%;
        }
        
        h1 { 
            text-align: center; 
            color: var(--white); 
            margin-bottom: 24px; 
            text-shadow: 0 2px 10px rgba(0,0,0,0.3); 
            font-size: 1.8em; 
            font-weight: 700;
            line-height: 1.3;
            padding: 0 20px;
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 1.6em;
                margin-bottom: 20px;
                padding: 0 15px;
            }
        }
        
        @media (max-width: 480px) {
            h1 {
                font-size: 1.4em;
                margin-bottom: 18px;
                padding: 0 10px;
            }
        }
        
        /* User info amélioré pour mobile */
        .user-info { 
            color: var(--white); 
            font-weight: 600; 
            margin-bottom: 24px; 
            text-align: right; 
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
            background: rgba(255,255,255,0.15);
            padding: 14px 20px;
            border-radius: var(--radius-xl);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        @media (max-width: 768px) {
            .user-info {
                justify-content: center;
                text-align: center;
                margin-bottom: 20px;
                flex-direction: column;
                gap: 12px;
                padding: 16px;
            }
        }
        
        .user-avatar-wrapper {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .user-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: #764ba2; /* Violet pour l'arrière-plan */
            color: var(--white); 
            font-size: 20px;
            font-weight: 700;
            display: flex;
            justify-content: center;
            align-items: center;
            border: 3px solid rgba(255,255,255,0.5);
            flex-shrink: 0;
            overflow: hidden;
            object-fit: cover;
        }
        
        .user-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .user-info a { 
            background: rgba(255,255,255,0.2); 
            padding: 10px 18px; 
            border-radius: var(--radius-lg); 
            color: var(--white); 
            text-decoration: none; 
            transition: all 0.3s; 
            font-weight: 600;
            font-size: 15px;
            white-space: nowrap;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(255,255,255,0.3);
            position: relative;
            overflow: hidden;
        }
        
        .user-info a::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        
        .user-info a:hover::before {
            left: 100%;
        }
        
        .user-info a:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        
        @media (max-width: 768px) {
            .user-info a {
                width: 100%;
                justify-content: center;
                padding: 12px;
                font-size: 16px;
            }
        }
        
        /* Tabs améliorés pour mobile */
        .tabs { 
            display: flex; 
            gap: 10px; 
            justify-content: center; 
            margin: 24px 0; 
            flex-wrap: wrap; 
            position: relative;
            z-index: 5;
        }
        
        .tab-btn { 
            padding: 16px 28px; 
            border: none; 
            border-radius: var(--radius-xl); 
            cursor: pointer; 
            font-weight: 600; 
            font-size: 16px; 
            transition: all 0.3s; 
            background: rgba(255,255,255,0.2); 
            color: var(--white); 
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            flex: 1;
            min-width: 140px;
            max-width: 220px;
            position: relative;
            overflow: hidden;
        }
        
        .tab-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        
        .tab-btn:hover::before {
            left: 100%;
        }
        
        .tab-btn:hover { 
            background: rgba(255,255,255,0.3); 
            transform: translateY(-3px); 
        }
        
        .tab-btn.active { 
            background: var(--white); 
            color: #667eea; 
            box-shadow: var(--shadow-heavy);
            font-weight: 700;
        }
        
        @media (max-width: 768px) {
            .tabs {
                flex-direction: column;
                align-items: center;
                gap: 10px;
                margin: 20px 0;
            }
            
            .tab-btn {
                width: 100%;
                max-width: 100%;
                padding: 18px 24px;
                font-size: 17px;
                min-width: unset;
            }
        }
        
        @media (max-width: 480px) {
            .tab-btn {
                padding: 16px 20px;
                font-size: 16px;
            }
        }
        
        /* Stats cards améliorées pour mobile */
        .stats { 
            display: grid; 
            gap: 20px; 
            margin: 30px 0; 
            width: 100%;
        }
        
        .stats.active-mode { 
            grid-template-columns: repeat(3, 1fr); 
        }
        
        .stats.trash-mode { 
            grid-template-columns: 1fr; 
        } 
        
        @media (max-width: 992px) {
            .stats.active-mode {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .stats.active-mode {
                grid-template-columns: 1fr;
                gap: 16px;
                margin: 20px 0;
            }
        }
        
        .stat-card { 
            background: rgba(0,0,0,0.4); 
            padding: 28px 20px; 
            border-radius: var(--radius-xl); 
            text-align: center; 
            box-shadow: var(--shadow-heavy); 
            backdrop-filter: blur(25px); 
            border: 2px solid rgba(255,255,255,0.2); 
            transition: all 0.4s; 
            position: relative; 
            overflow: hidden;
            cursor: pointer;
        }
        
        @media (max-width: 768px) {
            .stat-card {
                padding: 24px 16px;
            }
        }
        
        .stat-card::before {
            content: ""; 
            position: absolute; 
            top: 0; 
            left: 0; 
            right: 0; 
            height: 4px;
            background: linear-gradient(90deg, var(--white), rgba(255,255,255,0.5), var(--white));
        }
        
        .stat-card:hover { 
            transform: translateY(-8px) scale(1.03); 
            background: rgba(0,0,0,0.5); 
            box-shadow: 0 25px 50px rgba(0,0,0,0.3); 
            border-color: rgba(255,255,255,0.3);
        }
        
        .stat-card.active { 
            background: linear-gradient(135deg, #FFFFFF, #F0F0F0) !important; 
            border: 3px solid #FFFFFF !important; 
            box-shadow: 0 0 50px rgba(255,255,255,0.8), 0 20px 60px rgba(0,0,0,0.3) !important;
            transform: scale(1.03);
            cursor: default;
        }
        
        .stat-card.active .stat-number { 
            color: #333 !important; 
            text-shadow: none; 
        }
        
        .stat-card.active .stat-label { 
            color: #666 !important; 
            text-shadow: none; 
        }
        
        .stat-number { 
            font-size: 36px; 
            font-weight: 800; 
            color: var(--white) !important; 
            text-shadow: 0 2px 10px rgba(0,0,0,0.8), 0 0 20px rgba(255,255,255,0.5);
            margin-bottom: 10px; 
            letter-spacing: 1px; 
            line-height: 1;
        }
        
        @media (max-width: 768px) {
            .stat-number {
                font-size: 32px;
            }
        }
        
        @media (max-width: 480px) {
            .stat-number {
                font-size: 28px;
            }
        }
        
        .stat-label { 
            font-size: 15px; 
            font-weight: 600; 
            color: rgba(255,255,255,0.95); 
            text-shadow: 0 1px 5px rgba(0,0,0,0.5); 
            text-transform: uppercase; 
            letter-spacing: 0.5px;
            margin-bottom: 15px;
            display: block;
        }
        
        .stat-actions {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 15px;
        }
        
        .btn-action-in-card {
            background: linear-gradient(45deg, var(--info), #20c997);
            color: var(--white); 
            border: none; 
            padding: 10px 16px; 
            border-radius: var(--radius-lg); 
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 4px 12px rgba(23,162,184,0.4);
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            white-space: nowrap;
            position: relative;
            overflow: hidden;
        }
        
        .btn-action-in-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        
        .btn-action-in-card:hover::before {
            left: 100%;
        }
        
        .btn-action-in-card.delete-all {
            background: linear-gradient(45deg, var(--danger), #fd7e14);
            box-shadow: 0 4px 12px rgba(220,53,69,0.4);
        }
        
        .btn-action-in-card:hover {
            transform: scale(1.05);
            box-shadow: 0 6px 18px rgba(23,162,184,0.6);
        }
        
        /* Formulaire d'ajout amélioré pour mobile */
        .add-form { 
            background: rgba(255,255,255,0.2); 
            padding: 30px; 
            border-radius: var(--radius-xl); 
            margin: 20px auto; 
            max-width: 800px; 
            width: 100%;
            box-shadow: var(--shadow-heavy); 
            backdrop-filter: blur(20px); 
        }
        
        @media (max-width: 768px) {
            .add-form {
                padding: 24px;
                margin: 16px auto;
            }
        }
        
        @media (max-width: 480px) {
            .add-form {
                padding: 20px;
            }
        }
        
        .add-form h2 {
            color: var(--white); 
            text-align: center; 
            margin-bottom: 25px; 
            font-size: 1.8em;
            font-weight: 600;
        }
        
        @media (max-width: 768px) {
            .add-form h2 {
                font-size: 1.6em;
                margin-bottom: 20px;
            }
        }
        
        .form-row { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); 
            gap: 16px; 
            margin-bottom: 20px; 
            width: 100%;
        }
        
        .form-full-row { 
            grid-column: 1 / -1; 
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
                gap: 14px;
            }
        }
        
        input, select, button[type="button"] { 
            padding: 16px; 
            border: 2px solid rgba(255,255,255,0.3); 
            border-radius: var(--radius-lg); 
            font-size: 16px; 
            transition: all 0.3s; 
            background: rgba(255,255,255,0.95); 
            font-family: inherit;
            color: var(--gray-dark);
            width: 100%;
            position: relative;
            overflow: hidden;
        }
        
        @media (max-width: 768px) {
            input, select, button[type="button"] {
                padding: 14px;
                font-size: 16px;
            }
        }
        
        input:focus, select:focus { 
            outline: none; 
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        
        #title { 
            border-color: #667eea; 
            font-weight: 600; 
            font-size: 17px;
        }
        
        #title:focus { 
            outline: none; 
            box-shadow: 0 0 0 4px rgba(102,126,234,0.4); 
            transform: scale(1.01); 
        }
        
        button[type="button"] { 
            background: var(--primary-gradient); 
            color: var(--white); 
            border: none; 
            cursor: pointer; 
            font-weight: 600; 
            box-shadow: 0 6px 20px rgba(102,126,234,0.4); 
            font-size: 17px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            position: relative;
            overflow: hidden;
        }
        
        button[type="button"]::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        
        button[type="button"]:hover::before {
            left: 100%;
        }
        
        button[type="button"]:hover { 
            transform: translateY(-3px); 
            box-shadow: 0 10px 25px rgba(102,126,234,0.6); 
        }
        
        /* Tasks grid améliorée pour mobile */
        .tasks-grid { 
            display: grid; 
            grid-template-columns: repeat(3, 1fr); 
            gap: 20px; 
            width: 100%;
        }
        
        @media (max-width: 1200px) {
            .tasks-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .tasks-grid {
                grid-template-columns: 1fr;
                gap: 16px;
            }
        }
        
        /* Task cards améliorées pour mobile avec séparation */
        .task { 
            background: var(--white) !important; 
            margin: 0; 
            padding: 20px; 
            border-radius: var(--radius-lg); 
            box-shadow: var(--shadow); 
            transition: all 0.3s; 
            position: relative;
            width: 100%;
            margin-bottom: 15px; /* Séparation entre les tâches */
            border: 1px solid rgba(0,0,0,0.05);
        }
        
        .task:last-child {
            margin-bottom: 0;
        }
        
        @media (max-width: 768px) {
            .task {
                padding: 18px;
                margin-bottom: 12px;
            }
        }
        
        .task-check-toggle {
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            user-select: none;
            font-weight: 600;
            font-size: 17px;
        }
        
        .task.completed { 
            opacity: 0.7; 
            text-decoration: line-through; 
        }
        
        .priority-standard { 
            border-left: 6px solid #4CAF50 !important; 
            background: linear-gradient(135deg, #f8fff8, #f0fff0) !important; 
            box-shadow: 0 6px 20px rgba(76,175,80,0.2) !important; 
        }
        
        .priority-important { 
            border-left: 6px solid #FF9800 !important; 
            background: linear-gradient(135deg, #fff8f0, #fff0e0) !important; 
            box-shadow: 0 6px 20px rgba(255,152,0,0.2) !important; 
        }
        
        .priority-urgent { 
            border-left: 6px solid #F44336 !important; 
            background: linear-gradient(135deg, #fff8f8, #fff0f0) !important; 
            box-shadow: 0 6px 20px rgba(244,67,54,0.25) !important; 
        }
        
        @keyframes pulse-task { 
            0%, 100% { box-shadow: 0 6px 20px rgba(244,67,54,0.25); } 
            50% { box-shadow: 0 10px 30px rgba(244,67,54,0.4); } 
        }
        
        .task:hover { 
            transform: translateY(-5px) scale(1.01); 
            box-shadow: 0 12px 30px rgba(0,0,0,0.15); 
        }
        
        @media (max-width: 768px) {
            .task:hover {
                transform: translateY(-3px);
            }
        }
        
        /* Task actions améliorées pour mobile */
        .task-actions { 
            display: flex; 
            flex-direction: row; 
            gap: 10px; 
            margin-left: 0;
            margin-top: 15px;
        }
        
        @media (min-width: 769px) {
            .task-actions {
                flex-direction: column;
                margin-left: 10px;
                margin-top: 0;
            }
        }
        
        .btn-icon { 
            width: 44px; 
            height: 44px; 
            border-radius: 50%; 
            border: none; 
            cursor: pointer; 
            font-size: 16px; 
            font-weight: bold; 
            transition: all 0.3s; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            box-shadow: var(--shadow); 
            position: relative; 
            overflow: hidden;
        }
        
        @media (max-width: 768px) {
            .btn-icon {
                width: 42px;
                height: 42px;
                font-size: 15px;
            }
        }
        
        .btn-edit { 
            background: linear-gradient(135deg, var(--info), #20c997); 
            color: var(--white); 
        }
        
        .btn-edit:hover { 
            transform: scale(1.1) rotate(5deg); 
            box-shadow: 0 8px 20px rgba(23,162,184,0.6); 
        }
        
        .btn-delete { 
            background: linear-gradient(135deg, var(--danger), #fd7e14); 
            color: var(--white); 
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .btn-delete:hover { 
            transform: scale(1.1) rotate(-5deg); 
            box-shadow: 0 8px 20px rgba(220,53,69,0.6); 
            background: linear-gradient(135deg, #ff4757, #ff6b81);
        }
        
        .btn-restore { 
            background: linear-gradient(135deg, var(--success), #20c997); 
            color: var(--white); 
        }
        
        .btn-restore:hover { 
            transform: scale(1.1) rotate(360deg); 
            box-shadow: 0 8px 20px rgba(40,167,69,0.6); 
        }
        
        /* Category sections améliorées pour mobile */
        .category { 
            background: rgba(255,255,255,0.15); 
            border-radius: var(--radius-xl); 
            padding: 24px; 
            box-shadow: var(--shadow-heavy); 
            backdrop-filter: blur(20px); 
            margin-bottom: 20px; 
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .category {
                padding: 20px;
                margin-bottom: 16px;
            }
        }
        
        .cat-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 3px solid var(--cat-color); 
            flex-wrap: wrap;
            gap: 10px;
        }
        
        @media (max-width: 768px) {
            .cat-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
                margin-bottom: 16px;
            }
        }
        
        .cat-header-text-white {
            color: var(--white) !important;
            text-shadow: 0 1px 5px rgba(0,0,0,0.5);
            font-size: 1.4em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .cat-progress-text-white { 
            font-weight: 600; 
            color: var(--white) !important; 
            font-size: 14px;
            background: rgba(0,0,0,0.3);
            padding: 6px 12px;
            border-radius: var(--radius-lg);
        }
        
        /* Trash container amélioré pour mobile */
        .trash-container { 
            background: rgba(255,255,255,0.15); 
            border-radius: var(--radius-xl); 
            padding: 30px; 
            box-shadow: var(--shadow-heavy); 
            backdrop-filter: blur(20px); 
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .trash-container {
                padding: 24px;
            }
        }
        
        .trash-header { 
            text-align: center; 
            color: rgba(255,255,255,0.95); 
            font-size: 1.5em; 
            font-weight: 600; 
            margin-bottom: 25px; 
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
        }
        
        @media (max-width: 768px) {
            .trash-header {
                font-size: 1.3em;
                margin-bottom: 20px;
            }
        }
        
        /* Task badges améliorés pour mobile */
        .task-badges { 
            display: flex; 
            gap: 10px; 
            margin-top: 15px; 
            flex-wrap: wrap; 
        }
        
        .badge { 
            padding: 6px 14px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: 600; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.15); 
            color: var(--white) !important; 
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .badge.bg-standard { 
            background: linear-gradient(135deg, #4CAF50, #66BB6A); 
            border: none; 
        }
        
        .badge.bg-important { 
            background: linear-gradient(135deg, #FF9800, #FFB74D); 
            border: none; 
        }
        
        .badge.bg-urgent { 
            background: linear-gradient(135deg, #F44336, #EF5350); 
            border: none; 
        }
        
        /* Filter panel amélioré pour mobile */
        .filter-panel { 
            background: rgba(0,0,0,0.4); 
            padding: 24px; 
            border-radius: var(--radius-xl); 
            margin: 20px 0; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.25); 
            backdrop-filter: blur(15px); 
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .filter-panel {
                padding: 20px;
                margin: 16px 0;
            }
        }
        
        .filter-panel h3 {
            color: var(--white); 
            margin-bottom: 20px; 
            font-size: 1.3em;
            font-weight: 600;
        }
        
        @media (max-width: 768px) {
            .filter-panel h3 {
                font-size: 1.2em;
                margin-bottom: 16px;
            }
        }
        
        .filter-panel > div {
            display: flex; 
            gap: 20px; 
            flex-wrap: wrap;
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .filter-panel > div {
                flex-direction: column;
                gap: 16px;
            }
        }
        
        .filter-panel > div > div {
            flex: 1; 
            min-width: 200px;
        }
        
        @media (max-width: 768px) {
            .filter-panel > div > div {
                min-width: 100%;
            }
        }
        
        .filter-panel label {
            color: #ccc; 
            font-weight: 600; 
            margin-bottom: 10px; 
            display: block; 
            font-size: 14px;
        }
        
        /* Notification améliorée pour mobile */
        .notification { 
            position: fixed; 
            top: 20px; 
            right: 20px; 
            background: linear-gradient(45deg, #4CAF50, #45a049); 
            color: var(--white); 
            padding: 16px 24px; 
            border-radius: var(--radius-lg); 
            box-shadow: 0 12px 30px rgba(76,175,80,0.4); 
            transform: translateX(400px); 
            transition: all 0.4s; 
            z-index: 1000; 
            font-weight: 600; 
            max-width: 350px;
            word-wrap: break-word;
        }
        
        @media (max-width: 768px) {
            .notification {
                top: 10px;
                right: 10px;
                left: 10px;
                max-width: calc(100% - 20px);
                padding: 14px 20px;
                text-align: center;
            }
        }
        
        .notification.show { 
            transform: translateX(0); 
        }
        
        /* Modal amélioré pour mobile */
        .modal { 
            display: none; 
            position: fixed; 
            top: 0; 
            left: 0; 
            width: 100%; 
            height: 100%; 
            background: rgba(0,0,0,0.7); 
            z-index: 2000; 
            overflow-y: auto;
            padding: 20px;
        }
        
        .modal-content { 
            position: relative; 
            background: rgba(255,255,255,0.98); 
            padding: 30px; 
            border-radius: var(--radius-xl); 
            width: 90%; 
            max-width: 600px; 
            box-shadow: 0 25px 80px rgba(0,0,0,0.4); 
            margin: 40px auto;
        }
        
        @media (max-width: 768px) {
            .modal-content {
                padding: 24px;
                width: 95%;
                margin: 20px auto;
            }
        }
        
        .modal-row { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 16px; 
            margin-bottom: 25px; 
        }
        
        @media (max-width: 768px) {
            .modal-row {
                grid-template-columns: 1fr;
            }
        }
        
        .modal-buttons { 
            display: flex; 
            gap: 15px; 
            justify-content: center; 
            flex-wrap: wrap;
        }
        
        @media (max-width: 768px) {
            .modal-buttons {
                flex-direction: column;
                gap: 12px;
            }
        }
        
        /* Nouveau style pour le bouton Annuler */
        .btn-cancel {
            background: linear-gradient(45deg, #dc3545, #c82333) !important;
            color: white !important;
            border: none !important;
            padding: 12px 24px !important;
            border-radius: var(--radius-lg) !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            font-size: 16px !important;
            transition: all 0.3s !important;
            box-shadow: 0 6px 20px rgba(220, 53, 69, 0.4) !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 10px !important;
            width: 140px !important;
            height: 45px !important;
            position: relative !important;
            overflow: hidden !important;
        }
        
        .btn-cancel::before {
            content: '' !important;
            position: absolute !important;
            top: 0 !important;
            left: -100% !important;
            width: 100% !important;
            height: 100% !important;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent) !important;
            transition: left 0.5s !important;
        }
        
        .btn-cancel:hover::before {
            left: 100% !important;
        }
        
        .btn-cancel:hover {
            transform: translateY(-3px) !important;
            box-shadow: 0 10px 25px rgba(220, 53, 69, 0.6) !important;
        }
        
        /* Nouveau style pour le bouton Enregistrer */
        .btn-save {
            background: linear-gradient(45deg, #17a2b8, #20c997) !important;
            color: white !important;
            border: none !important;
            padding: 12px 24px !important;
            border-radius: var(--radius-lg) !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            font-size: 16px !important;
            transition: all 0.3s !important;
            box-shadow: 0 6px 20px rgba(23, 162, 184, 0.4) !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 10px !important;
            width: 140px !important;
            height: 45px !important;
            position: relative !important;
            overflow: hidden !important;
        }
        
        .btn-save::before {
            content: '' !important;
            position: absolute !important;
            top: 0 !important;
            left: -100% !important;
            width: 100% !important;
            height: 100% !important;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent) !important;
            transition: left 0.5s !important;
        }
        
        .btn-save:hover::before {
            left: 100% !important;
        }
        
        .btn-save:hover {
            transform: translateY(-3px) !important;
            box-shadow: 0 10px 25px rgba(23, 162, 184, 0.6) !important;
        }
        
        /* Améliorations pour l'accessibilité mobile */
        @media (hover: none) and (pointer: coarse) {
            .task:hover {
                transform: none;
            }
            
            .stat-card:hover {
                transform: none;
            }
            
            .btn-action-in-card:hover,
            .btn-icon:hover,
            button[type="button"]:hover,
            .user-info a:hover {
                transform: none;
            }
        }
        
        /* Support pour iOS */
        @supports (-webkit-touch-callout: none) {
            body {
                min-height: -webkit-fill-available;
            }
            
            .container {
                min-height: -webkit-fill-available;
            }
        }
        
        /* Optimisations pour les petits écrans */
        @media (max-width: 360px) {
            .user-avatar {
                width: 42px;
                height: 42px;
                font-size: 18px;
            }
            
            .badge {
                padding: 5px 10px;
                font-size: 11px;
            }
            
            .btn-icon {
                width: 40px;
                height: 40px;
                font-size: 14px;
            }
            
            .stat-number {
                font-size: 26px;
            }
            
            .stat-label {
                font-size: 13px;
            }
        }
        
        /* Amélioration de la lisibilité sur mobile */
        @media (max-width: 768px) {
            .task-check-toggle {
                font-size: 16px;
            }
            
            .task {
                font-size: 15px;
            }
            
            .cat-header-text-white {
                font-size: 1.2em;
            }
            
            .trash-header {
                font-size: 1.2em;
            }
        }
        
        /* Support pour le dark mode des appareils */
        @media (prefers-color-scheme: dark) {
            .task {
                background: #2d3748 !important;
                color: #e2e8f0;
            }
            
            .task .badge {
                color: white !important;
            }
        }
        
        /* Modal À propos */
        #aboutModal .modal-content {
            max-width: 700px;
        }
        
        .about-content {
            color: #333;
            line-height: 1.7;
        }
        
        .about-content h2 {
            color: #667eea;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .about-content p {
            margin-bottom: 20px;
            text-align: justify;
        }
        
        .signature {
            text-align: right;
            font-style: italic;
            color: #764ba2;
            font-weight: 600;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #e2e8f0;
        }
    </style>
</head>
<body>
    <div class="sidebar-left"></div>
    <div class="sidebar-right"></div>
    
    <div class="container">
        
        <div class="user-info">
            <div class="user-avatar-wrapper">
                {% if profile_photo %}
                <img src="{{ profile_photo }}?t={{ range(1, 10000) | random }}" alt="Photo de profil" class="user-avatar">
                {% else %}
                <span class="user-avatar">{{ username[0]|upper }}</span> 
                {% endif %}
                <span>Bienvenue, {{ username }} !</span>
            </div>
            <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                <a href="javascript:void(0)" onclick="openAboutModal()"><i class="fas fa-info-circle"></i> À propos</a>
                <a href="{{ url_for('settings') }}"><i class="fas fa-cog"></i> Paramètres</a>
                <a href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Déconnexion</a>
            </div>
        </div>
        
        <h1>Personnaliser la gestion de vos tâches avec Tacheo</h1>
        
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('active')" id="tabActive"><i class="fas fa-tasks"></i> Mes Tâches</button>
            <button class="tab-btn" onclick="switchTab('add')" id="tabAdd"><i class="fas fa-plus-circle"></i> Ajouter une Tâche</button>
            <button class="tab-btn" onclick="switchTab('trash')" id="tabTrash"><i class="fas fa-trash"></i> Corbeille</button>
        </div>
        
        <div id="activeContent">
            <div class="stats active-mode" id="stats"></div>
            
            <div class="filter-panel" id="filterPanel" style="display: none;">
                <h3>Filtres Avancés (Catégorie & Priorité)</h3>
                <div>
                    <div>
                        <label>Catégorie</label>
                        <select id="categoryFilterSelect" onchange="setAdvancedFilter()">
                            <option value="all">Toutes les catégories</option>
                            <option value="travail">💼 Travail</option>
                            <option value="personnel">👤 Personnel</option>
                            <option value="etude">📚 Étude</option>
                            <option value="sport">⚽ Sport</option>
                        </select>
                    </div>
                    
                    <div>
                        <label>Priorité</label>
                        <select id="priorityFilterSelect" onchange="setAdvancedFilter()">
                            <option value="all">Toutes les priorités</option>
                            <option value="urgent">🚨 Urgent</option>
                            <option value="important">⭐ Important</option>
                            <option value="standard">✅ Standard</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="tasks-grid" id="tasksContainer"></div>
        </div>

        <div id="addContent" style="display: none;">
             <div class="add-form">
                <h2><i class="fas fa-plus-circle"></i> Créer une nouvelle tâche</h2>
                <div class="form-full-row">
                    <input type="text" id="title" placeholder="Tâche à faire (Titre)" required autofocus>
                </div>
                <div class="form-full-row">
                     <input type="text" id="description" placeholder="Description (Optionnel)">
                </div>
                
                <div class="form-row">
                    <label style="color: white; display: block; grid-column: 1 / -1; font-weight: 600; margin-top: 10px;">Détails de la tâche</label>
                </div>

                <div class="form-row">
                    <input type="date" id="due_date" title="Date Limite">
                    <select id="priority" title="Priorité">
                        <option value="standard">✅ Standard</option>
                        <option value="important" selected>⭐ Important</option>
                        <option value="urgent">🚨 Urgent</option>
                    </select>
                    <select id="category" title="Catégorie">
                        <option value="travail">💼 Travail</option>
                        <option value="personnel">👤 Personnel</option>
                        <option value="etude">📚 Étude</option>
                        <option value="sport">⚽ Sport</option>
                    </select>
                    <button type="button" onclick="addTask()"><i class="fas fa-plus"></i> Ajouter</button>
                </div>
            </div>
        </div>

        <div id="trashContent" style="display: none;">
            <div class="trash-container">
                 <div class="trash-header">
                    <div><i class="fas fa-trash"></i> Tâches Supprimées</div>
                    <div class="stat-actions">
                        <button class="btn-action-in-card" onclick="event.stopPropagation(); toggleFilterPanel('deleted');" style="cursor: pointer;">
                            <i class="fas fa-filter"></i> Filtre Avancé
                        </button>
                        <button class="btn-action-in-card delete-all" onclick="event.stopPropagation(); confirmHardDelete('all');" style="cursor: pointer;">
                            <i class="fas fa-trash-alt"></i> Vider Corbeille
                        </button>
                    </div>
                 </div>
                 
                 <div class="filter-panel" id="trashFilterPanel" style="display: none;">
                    <h3>Filtres Avancés (Catégorie & Priorité) - Corbeille</h3>
                    <div>
                        <div>
                            <label>Catégorie</label>
                            <select id="trashCategoryFilterSelect" onchange="setTrashAdvancedFilter()">
                                <option value="all">Toutes les catégories</option>
                                <option value="travail">💼 Travail</option>
                                <option value="personnel">👤 Personnel</option>
                                <option value="etude">📚 Étude</option>
                                <option value="sport">⚽ Sport</option>
                            </select>
                        </div>
                        
                        <div>
                            <label>Priorité</label>
                            <select id="trashPriorityFilterSelect" onchange="setTrashAdvancedFilter()">
                                <option value="all">Toutes les priorités</option>
                                <option value="urgent">🚨 Urgent</option>
                                <option value="important">⭐ Important</option>
                                <option value="standard">✅ Standard</option>
                            </select>
                        </div>
                    </div>
                 </div>
                 
                 <div class="tasks-grid" id="trashContainer"></div>
            </div>
        </div>

    </div>
    
    <div id="editModal" class="modal">
        <div class="modal-content">
            <h2><i class="fas fa-edit"></i> Modifier Tâche</h2>
            <div class="modal-row">
                <input type="text" id="editTitle" required placeholder="Titre">
                <input type="text" id="editDescription" placeholder="Description">
                <input type="date" id="editDueDate">
                <select id="editPriority">
                    <option value="standard">✅ Standard</option>
                    <option value="important">⭐ Important</option>
                    <option value="urgent">🚨 Urgent</option>
                </select>
                <select id="editCategory">
                    <option value="travail">💼 Travail</option>
                    <option value="personnel">👤 Personnel</option>
                    <option value="etude">📚 Étude</option>
                    <option value="sport">⚽ Sport</option>
                </select>
            </div>
            <div class="modal-buttons">
                <button onclick="saveEdit()" class="btn-save"><i class="fas fa-save"></i> Enregistrer</button>
                <button onclick="closeEdit()" class="btn-cancel"><i class="fas fa-times"></i> Annuler</button>
            </div>
        </div>
    </div>
    
    <!-- Modal À propos -->
    <div id="aboutModal" class="modal">
        <div class="modal-content">
            <h2><i class="fas fa-info-circle"></i> À propos de Tacheo</h2>
            <div class="about-content">
                <p>Je m'appelle <strong>Abdellah Rezzag</strong>, créateur de Tacheo, une application pensée pour simplifier l'organisation quotidienne. Passionné par l'efficacité, la gestion et l'optimisation du travail, j'ai développé cet outil pour permettre à chacun de planifier ses tâches facilement, suivre sa progression et gagner en productivité.</p>
                
                <p>Avec une interface moderne, des catégories intuitives, des priorités personnalisables et une expérience fluide sur mobile comme sur ordinateur, Tacheo a été conçu pour aider les utilisateurs à mieux gérer leur temps et atteindre leurs objectifs plus sereinement.</p>
                
                <p>Mon objectif est de fournir un outil simple, rapide et agréable à utiliser — un assistant qui vous accompagne chaque jour.</p>
                
                <div class="signature">
                    Abdellah Rezzag<br>
                    Créateur de Tacheo
                </div>
            </div>
            <div class="modal-buttons" style="margin-top: 30px;">
                <button onclick="closeAboutModal()" class="btn-cancel" style="width: 140px;"><i class="fas fa-times"></i> Fermer</button>
            </div>
        </div>
    </div>
    
    <div id="notification" class="notification"></div>

    <script>
        let tasks = [];
        let allTasks = [];
        let currentTab = 'active'; 
        let currentFilter = 'all'; 
        let editingTaskId = null;
        
        let currentCategoryFilter = 'all'; 
        let currentPriorityFilter = 'all';
        
        let trashCategoryFilter = 'all';
        let trashPriorityFilter = 'all';
        
        const categoryColors = {
            'travail': '#3498db', 
            'personnel': '#27ae60', 
            'etude': '#9b59b6',
            'sport': '#e74c3c'
        };
        const priorityPalette = {
            'urgent': '#F44336', 
            'important': '#FF9800', 
            'standard': '#4CAF50'
        };
        const categoryEmojis = {
            'travail': '💼', 
            'personnel': '👤', 
            'etude': '📚',
            'sport': '⚽'
        };
        const priorityEmojis = {
            'standard': '✅', 
            'important': '⭐', 
            'urgent': '🚨'
        };
        const priorityOrder = { 'urgent': 1, 'important': 2, 'standard': 3 };
        
        // CORRECTION IMPORTANTE : Modifier l'ordre des catégories
        const allCategories = ['travail', 'personnel', 'etude', 'sport'];
        
        document.addEventListener('DOMContentLoaded', function() {
            const titleInput = document.getElementById('title');
            if (titleInput) {
                titleInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        addTask();
                    }
                });
            }
            loadAllTasks();
            switchTab('active');
            
            // Amélioration pour mobile: ajuster la hauteur de la fenêtre
            function adjustViewportHeight() {
                let vh = window.innerHeight * 0.01;
                document.documentElement.style.setProperty('--vh', `${vh}px`);
            }
            
            window.addEventListener('resize', adjustViewportHeight);
            adjustViewportHeight();
            
            // Prévenir le zoom sur les inputs sur iOS
            document.addEventListener('touchstart', function() {}, {passive: true});
        });
        
        function showNotification(msg) {
            const notif = document.getElementById('notification');
            notif.textContent = msg;
            notif.classList.add('show');
            setTimeout(() => notif.classList.remove('show'), 3000);
        }
        
        // Fonctions pour le modal À propos
        function openAboutModal() {
            document.getElementById('aboutModal').style.display = 'block';
        }
        
        function closeAboutModal() {
            document.getElementById('aboutModal').style.display = 'none';
        }
        
        async function loadAllTasks() {
            try {
                const res = await fetch('/api/alltasks');
                if (res.ok) {
                    allTasks = await res.json();
                    if (currentTab === 'active') {
                        updateStats();
                    }
                }
            } catch(e) {
                console.error('Erreur comptage:', e);
            }
        }
        
        async function loadTasks() {
            if (currentTab === 'add') return; 
            
            try {
                const filterForApi = currentTab === 'trash' ? 'deleted' : currentFilter; 
                let url = '';
                
                if (currentTab === 'trash') {
                    url = `/api/tasks?filter=deleted&category_filter=${trashCategoryFilter}&priority_filter=${trashPriorityFilter}`;
                } else {
                    url = `/api/tasks?filter=${filterForApi}&category_filter=${currentCategoryFilter}&priority_filter=${currentPriorityFilter}`;
                }
                
                const res = await fetch(url);
                if (res.ok) {
                    tasks = await res.json();
                    renderTasks();
                    loadAllTasks(); 
                }
            } catch(e) {
                console.error('Erreur:', e);
            }
        }
        
        function renderTasks() {
            const container = currentTab === 'trash' ? document.getElementById('trashContainer') : document.getElementById('tasksContainer');
            if (!container) return; 

            const categoriesByTask = {};
            tasks.forEach(task => {
                if (!categoriesByTask[task.category]) categoriesByTask[task.category] = [];
                categoriesByTask[task.category].push(task);
            });
            
            // Utiliser le nouvel ordre des catégories
            const categoriesOrder = allCategories;
            
            if (currentTab !== 'active' || tasks.length > 0 || currentCategoryFilter !== 'all' || currentPriorityFilter !== 'all') {
                container.style.gridTemplateColumns = 'repeat(3, 1fr)'; 
            }
            
            if (currentTab === 'active' && tasks.length === 0 && currentFilter === 'all' && currentCategoryFilter === 'all' && currentPriorityFilter === 'all') {
                container.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 60px 20px; color: rgba(255,255,255,0.8); font-size: 18px; background: rgba(0,0,0,0.2); border-radius: 20px; backdrop-filter: blur(10px);">
                    <div style="font-size: 48px; margin-bottom: 20px;">🎉</div>
                    <div style="font-weight: 600; margin-bottom: 10px;">Vous n'avez aucune tâche active !</div>
                    <div style="font-size: 14px; opacity: 0.8;">Cliquez sur "Ajouter une Tâche" pour commencer</div>
                </div>`;
                container.style.gridTemplateColumns = '1fr';
                return;
            }

            container.innerHTML = categoriesOrder.map(catName => {
                const catTasks = categoriesByTask[catName] || [];
                const total = catTasks.length;
                
                if (total === 0 && (currentCategoryFilter !== 'all' || currentPriorityFilter !== 'all')) {
                    return '';
                }
                
                const countText = currentTab === 'trash'
                    ? `(${total} éléments supprimés)`
                    : `(${catTasks.filter(t => t.status === 'completed').length} / ${total} accomplies)`;

                const color = categoryColors[catName];
                
                const taskHTML = total > 0 
                    ? catTasks.map(task => createTaskHTML(task)).join('')
                    : `<div style="text-align: center; color: rgba(255,255,255,0.7); padding: 30px 20px; background: rgba(0,0,0,0.1); border-radius: 15px; margin-top: 10px;">
                        <i class="fas fa-inbox" style="font-size: 24px; margin-bottom: 10px; display: block;"></i>
                        Pas de tâches ici.
                       </div>`;
                
                return `
                    <div class="category" style="--cat-color: ${color}">
                        <div class="cat-header">
                            <h3 class="cat-header-text-white">${categoryEmojis[catName]} ${catName.charAt(0).toUpperCase() + catName.slice(1)}</h3>
                            ${total > 0 ? `<span class="cat-progress-text-white">${countText}</span>` : ''}
                        </div>
                        ${taskHTML}
                    </div>
                `;
            }).join('');
        }
        
        function createTaskHTML(task) {
            const isCompleted = task.status === 'completed';
            const isDeleted = task.status === 'deleted';
            const priorityEmoji = priorityEmojis[task.priority];
            
            const onClickAttr = isDeleted ? '' : `onclick="toggleTask(${task.id})"`;
            
            const priorityBgClass = `bg-${task.priority}`;
            
            // Formatage de la date pour mobile
            let dueDateDisplay = '📅 Pas de date';
            if (task.due_date) {
                const date = new Date(task.due_date);
                dueDateDisplay = date.toLocaleDateString('fr-FR', { 
                    day: '2-digit', 
                    month: '2-digit',
                    year: 'numeric'
                });
            }

            return `
                <div class="task priority-${task.priority} ${isCompleted ? 'completed' : ''} ${isDeleted ? 'deleted' : ''}">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px;">
                        <div style="flex: 1; min-width: 200px;">
                            <div style="font-size: 18px; margin-bottom: 12px; font-weight: ${isCompleted || isDeleted ? '500' : '600'};">
                                <span class="task-check-toggle" ${onClickAttr}>
                                    ${isCompleted ? '✅' : isDeleted ? '🗑' : '○'} ${task.title}
                                </span>
                            </div>
                            ${task.description ? `<div style="color: #666; margin-bottom: 12px; font-size: 14px; line-height: 1.4;">${task.description}</div>` : ''}
                            <div class="task-badges">
                                <span class="badge ${priorityBgClass}">${priorityEmoji} ${task.priority.charAt(0).toUpperCase() + task.priority.slice(1)}</span>
                                <span class="badge ${priorityBgClass}">${dueDateDisplay}</span>
                            </div>
                        </div>
                        <div class="task-actions">
                            ${isDeleted ? 
                                `
                                <button class="btn-icon btn-restore" onclick="event.stopPropagation(); restoreTask(${task.id});" title="Restaurer"><i class="fas fa-redo"></i></button>
                                <button class="btn-icon btn-delete" onclick="event.stopPropagation(); confirmHardDelete(${task.id});" title="Supprimer Définitivement"><i class="fas fa-times"></i></button>
                                ` :
                                `
                                <button class="btn-icon btn-edit" onclick="event.stopPropagation(); editTask(${task.id});" title="Modifier"><i class="fas fa-edit"></i></button>
                                <button class="btn-icon btn-delete" onclick="event.stopPropagation(); deleteTask(${task.id});" title="Supprimer"><i class="fas fa-trash"></i></button>
                                `
                            }
                        </div>
                    </div>
                </div>
            `;
        }
        
        function updateStats() {
            const statsElement = document.getElementById('stats');
            const totalActive = allTasks.filter(t => t.status !== 'deleted').length;
            const pendingCount = allTasks.filter(t => t.status === 'pending').length;
            const completedCount = allTasks.filter(t => t.status === 'completed').length;
            
            const getAdvancedFilterButton = (status) => {
                return `
                    <button class="btn-action-in-card" onclick="event.stopPropagation(); toggleFilterPanel('${status}');" style="cursor: pointer;">
                        <i class="fas fa-filter"></i> Filtre Avancé
                    </button>
                `;
            };

            let activeFilterStatus = currentFilter;
            const advancedFiltersActive = currentCategoryFilter !== 'all' || currentPriorityFilter !== 'all';

            if (advancedFiltersActive && currentFilter !== 'deleted') { 
                activeFilterStatus = currentFilter; 
            }

            if (currentTab === 'active') {
                statsElement.style.display = 'grid';
                statsElement.innerHTML = `
                    <div class="stat-card ${activeFilterStatus === 'all' && !advancedFiltersActive ? 'active' : ''}" onclick="filterTasks('all')" title="🔵 Voir toutes les tâches" style="cursor: pointer;">
                        <div class="stat-number">${totalActive}</div>
                        <div class="stat-label">Toutes les Tâches</div>
                        <div class="stat-actions">
                             ${getAdvancedFilterButton('all')}
                        </div>
                    </div>
                    <div class="stat-card ${activeFilterStatus === 'pending' && !advancedFiltersActive ? 'active' : ''}" onclick="filterTasks('pending')" title="🟠 Voir seulement les tâches à faire" style="cursor: pointer;">
                        <div class="stat-number">${pendingCount}</div>
                        <div class="stat-label">Tâches à Faire</div>
                        <div class="stat-actions">
                            ${getAdvancedFilterButton('pending')}
                        </div>
                    </div>
                    <div class="stat-card ${activeFilterStatus === 'completed' && !advancedFiltersActive ? 'active' : ''}" onclick="filterTasks('completed')" title="🟢 Voir seulement les tâches terminées" style="cursor: pointer;">
                        <div class="stat-number">${completedCount}</div>
                        <div class="stat-label">Tâches Terminées</div>
                        <div class="stat-actions">
                            ${getAdvancedFilterButton('completed')}
                        </div>
                    </div>
                `;
                statsElement.classList.add('active-mode');
                statsElement.classList.remove('trash-mode');
            } else {
                 statsElement.style.display = 'none';
            }
        }
        
        function resetAdvancedFilters() {
            currentCategoryFilter = 'all';
            currentPriorityFilter = 'all';
            const catSelect = document.getElementById('categoryFilterSelect');
            const prioSelect = document.getElementById('priorityFilterSelect');
            if (catSelect) catSelect.value = 'all';
            if (prioSelect) prioSelect.value = 'all';
        }
        
        function resetTrashAdvancedFilters() {
            trashCategoryFilter = 'all';
            trashPriorityFilter = 'all';
            const catSelect = document.getElementById('trashCategoryFilterSelect');
            const prioSelect = document.getElementById('trashPriorityFilterSelect');
            if (catSelect) catSelect.value = 'all';
            if (prioSelect) prioSelect.value = 'all';
        }

        function toggleFilterPanel(statusForFilter) {
            const panel = document.getElementById('filterPanel');
            const trashPanel = document.getElementById('trashFilterPanel');
            
            if (currentTab === 'trash') {
                // Gestion pour la corbeille
                const isCurrentlyOpen = trashPanel.style.display !== 'none';
                
                if (isCurrentlyOpen) {
                    trashPanel.style.display = 'none';
                    resetTrashAdvancedFilters();
                    showNotification(`Filtres avancés désactivés pour la corbeille.`);
                } else {
                    trashPanel.style.display = 'block';
                    showNotification(`Panneau de filtres avancés ouvert pour la corbeille.`);
                }
                
                // Fermer l'autre panneau si ouvert
                if (panel.style.display !== 'none') {
                    panel.style.display = 'none';
                    resetAdvancedFilters();
                }
            } else {
                // Gestion pour les onglets actifs
                const isCurrentlyOpenForThisStatus = panel.style.display !== 'none' && currentFilter === statusForFilter;
                
                if (isCurrentlyOpenForThisStatus) {
                    panel.style.display = 'none';
                    resetAdvancedFilters();
                    currentFilter = statusForFilter; 
                    showNotification(`Filtres avancés désactivés.`);
                } else {
                    panel.style.display = 'block';
                    currentFilter = statusForFilter; 
                    showNotification(`Panneau de filtres avancés ouvert pour ${statusForFilter}.`);
                }
                
                // Fermer le panneau de la corbeille si ouvert
                if (trashPanel.style.display !== 'none') {
                    trashPanel.style.display = 'none';
                    resetTrashAdvancedFilters();
                }
            }
            
            loadTasks();
            updateStats();
        }

        function setAdvancedFilter() {
            const catSelect = document.getElementById('categoryFilterSelect');
            const prioSelect = document.getElementById('priorityFilterSelect');
            
            currentCategoryFilter = catSelect.value;
            currentPriorityFilter = prioSelect.value;
            
            let msg = 'Filtre avancé appliqué : ';
            
            if (currentCategoryFilter !== 'all' || currentPriorityFilter !== 'all') {
                if (currentCategoryFilter !== 'all') {
                    msg += `Catégorie: ${catSelect.options[catSelect.selectedIndex].text.trim()}`;
                }
                if (currentPriorityFilter !== 'all') {
                    msg += (currentCategoryFilter !== 'all' ? ' & ' : '') + `Priorité: ${prioSelect.options[prioSelect.selectedIndex].text.trim()}`;
                }
                document.getElementById('filterPanel').style.display = 'block';
            } else {
                msg = 'Filtres avancés réinitialisés';
                document.getElementById('filterPanel').style.display = 'none';
            } 
            
            showNotification(msg);
            loadTasks();
        }
        
        function setTrashAdvancedFilter() {
            const catSelect = document.getElementById('trashCategoryFilterSelect');
            const prioSelect = document.getElementById('trashPriorityFilterSelect');
            
            trashCategoryFilter = catSelect.value;
            trashPriorityFilter = prioSelect.value;
            
            let msg = 'Filtre avancé (corbeille) appliqué : ';
            
            if (trashCategoryFilter !== 'all' || trashPriorityFilter !== 'all') {
                if (trashCategoryFilter !== 'all') {
                    msg += `Catégorie: ${catSelect.options[catSelect.selectedIndex].text.trim()}`;
                }
                if (trashPriorityFilter !== 'all') {
                    msg += (trashCategoryFilter !== 'all' ? ' & ' : '') + `Priorité: ${prioSelect.options[prioSelect.selectedIndex].text.trim()}`;
                }
                document.getElementById('trashFilterPanel').style.display = 'block';
            } else {
                msg = 'Filtres avancés (corbeille) réinitialisés';
                document.getElementById('trashFilterPanel').style.display = 'none';
            } 
            
            showNotification(msg);
            loadTasks();
        }

        function filterTasks(filter) {
            resetAdvancedFilters();
            document.getElementById('filterPanel').style.display = 'none';

            currentFilter = filter;
            
            let filterName;
            if (filter === 'all') filterName = 'Toutes les Tâches';
            else if (filter === 'pending') filterName = 'Tâches à Faire';
            else if (filter === 'completed') filterName = 'Tâches Terminées';

            showNotification(`✅ Filtré : ${filterName}`);

            loadTasks();
            updateStats();
        }
        
        async function addTask() {
            const title = document.getElementById('title').value.trim();
            if (!title) return showNotification('⚠ Titre requis');
            
            const taskData = {
                title, 
                description: document.getElementById('description').value.trim(),
                due_date: document.getElementById('due_date').value || null,
                priority: document.getElementById('priority').value,
                category: document.getElementById('category').value,
                status: 'pending'
            };
            
            try {
                const response = await fetch('/api/tasks', {
                    method: 'POST', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify(taskData)
                });
                
                if (response.ok) {
                    document.getElementById('title').value = ''; 
                    document.getElementById('description').value = ''; 
                    document.getElementById('due_date').value = '';
                    document.getElementById('priority').value = 'important'; 
                    document.getElementById('category').value = 'travail'; 
                    document.getElementById('title').focus();
                    
                    showNotification('✅ Tâche ajoutée !');
                    switchTab('active');
                } else {
                    const error = await response.text();
                    showNotification('❌ Erreur lors de l\\'ajout: ' + error);
                }
            } catch(e) { 
                console.error('Erreur ajout:', e);
                showNotification('❌ Erreur de connexion au serveur'); 
            }
        }
        
        async function toggleTask(id) {
            const task = allTasks.find(t => t.id === id); 
            if (!task || task.status === 'deleted') return; 
            
            const newStatus = task.status === 'completed' ? 'pending' : 'completed';
            
            try {
                const res = await fetch(`/api/tasks/${id}`, {
                    method: 'PUT', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({status: newStatus})
                });
                
                if (res.ok) {
                    showNotification(newStatus === 'completed' ? '✅ Tâche Terminée!' : '🔄 Tâche Rouverte');
                    loadTasks(); 
                } else {
                     showNotification('❌ Erreur de mise à jour');
                }
            } catch(e) {
                console.error("Erreur toggle:", e);
                showNotification('❌ Erreur de connexion');
            }
        }
        
        async function deleteTask(id) {
            if (!confirm('Déplacer en corbeille?')) return;
            try {
                const res = await fetch(`/api/tasks/${id}`, {
                    method: 'PUT', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({status: 'deleted'})
                });
                if (res.ok) {
                    showNotification('🗑 En corbeille');
                    loadTasks(); 
                } else {
                    showNotification('❌ Erreur lors de la suppression');
                }
            } catch(e) {
                console.error("Erreur delete:", e);
                showNotification('❌ Erreur de connexion');
            }
        }
        
        function confirmHardDelete(id) {
            const isAll = id === 'all';
            const message = isAll 
                ? "Êtes-vous SÛR de vouloir VIDER la corbeille ? Cette action est IRREVERSIBLE." 
                : "Êtes-vous SÛR de vouloir supprimer DÉFINITIVEMENT cette tâche ? Cette action est IRREVERSIBLE.";
            
            if (confirm(message)) {
                hardDeleteTask(id);
            }
        }

        async function hardDeleteTask(id) {
            try {
                const isAll = id === 'all';
                const url = isAll ? '/api/tasks/clear_trash' : `/api/tasks/${id}`;
                
                const res = await fetch(url, {method: 'DELETE'});
                if (res.ok) {
                    showNotification(isAll ? '🗑 Corbeille vidée!' : '🗑 Tâche supprimée définitivement!');
                    loadTasks();
                } else {
                    showNotification('❌ Erreur lors de la suppression.');
                }
            } catch (e) {
                console.error('Erreur suppression définitive:', e);
                showNotification('❌ Erreur serveur lors de la suppression.');
            }
        }

        
        async function restoreTask(id) {
            try {
                const res = await fetch(`/api/tasks/${id}`, {
                    method: 'PUT', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({status: 'pending'})
                });
                if (res.ok) {
                    showNotification('↻ Restaurée!');
                    loadTasks();
                } else {
                    showNotification('❌ Erreur lors de la restauration');
                }
            } catch(e) {
                console.error("Erreur restore:", e);
                showNotification('❌ Erreur de connexion');
            }
        }
        
        function editTask(id) {
            const task = allTasks.find(t => t.id === id); 
            if (!task) return showNotification('Tâche introuvable pour édition.');

            editingTaskId = id;
            document.getElementById('editTitle').value = task.title;
            document.getElementById('editDescription').value = task.description || '';
            document.getElementById('editDueDate').value = task.due_date || '';
            document.getElementById('editPriority').value = task.priority;
            document.getElementById('editCategory').value = task.category;
            document.getElementById('editModal').style.display = 'block';
            
            // Focus sur le titre pour mobile
            setTimeout(() => document.getElementById('editTitle').focus(), 100);
        }
        
        function closeEdit() { 
            document.getElementById('editModal').style.display = 'none'; 
            editingTaskId = null;
        }
        
        async function saveEdit() {
            const updatedTask = {
                title: document.getElementById('editTitle').value,
                description: document.getElementById('editDescription').value,
                due_date: document.getElementById('editDueDate').value || null,
                priority: document.getElementById('editPriority').value,
                category: document.getElementById('editCategory').value
            };
            
            try {
                const res = await fetch(`/api/tasks/${editingTaskId}`, {
                    method: 'PUT', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify(updatedTask)
                });
                if (res.ok) {
                    showNotification('✎ Tâche modifiée!');
                    closeEdit();
                    loadTasks();
                } else {
                    showNotification('❌ Erreur lors de la modification');
                }
            } catch(e) {
                console.error("Erreur saveEdit:", e);
                showNotification('❌ Erreur de connexion');
            }
        }
        
        function switchTab(tab) {
            currentTab = tab;
            
            // Masquer tous les contenus
            document.getElementById('activeContent').style.display = 'none';
            document.getElementById('addContent').style.display = 'none';
            document.getElementById('trashContent').style.display = 'none';
            document.getElementById('filterPanel').style.display = 'none'; 
            document.getElementById('trashFilterPanel').style.display = 'none';
            
            // Retirer active de tous les boutons
            document.getElementById('tabActive').classList.remove('active');
            document.getElementById('tabAdd').classList.remove('active');
            document.getElementById('tabTrash').classList.remove('active');
            
            resetAdvancedFilters(); 
            resetTrashAdvancedFilters();
            
            if (tab === 'active') {
                currentFilter = 'all'; 
                document.getElementById('activeContent').style.display = 'block';
                document.getElementById('tabActive').classList.add('active');
                updateStats(); 
            } else if (tab === 'add') {
                document.getElementById('addContent').style.display = 'block';
                document.getElementById('tabAdd').classList.add('active');
                // Focus sur le champ titre pour mobile
                setTimeout(() => document.getElementById('title').focus(), 100);
            } else if (tab === 'trash') {
                currentFilter = 'deleted'; 
                document.getElementById('trashContent').style.display = 'block';
                document.getElementById('tabTrash').classList.add('active');
                document.getElementById('stats').style.display = 'none'; 
            }
            
            loadTasks();
        }
        
        window.onclick = function(event) {
            if (event.target.id === 'editModal') closeEdit();
            if (event.target.id === 'aboutModal') closeAboutModal();
        }
        
        // Gestion du clavier pour mobile
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeEdit();
                closeAboutModal();
            }
        });
    </script>
</body>
</html>
'''

# --- 6. LOGIQUE API FLASK (BACKEND PROTÉGÉ) ---

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_TEMPLATE, 
                                  username=current_user.username,
                                  profile_photo=current_user.profile_photo)

# --- ROUTE : PARAMÈTRES DU COMPTE (SETTINGS) ---

SETTINGS_TEMPLATE = '''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
    <title>⚙ Paramètres du compte Tacheo</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --primary-light: rgba(102, 126, 234, 0.1);
            --white: #ffffff;
            --gray-light: #f8f9fa;
            --gray: #6c757d;
            --gray-dark: #343a40;
            --success: #28a745;
            --warning: #ffc107;
            --danger: #dc3545;
            --info: #17a2b8;
            --shadow: 0 4px 12px rgba(0,0,0,0.1);
            --shadow-heavy: 0 8px 25px rgba(0,0,0,0.2);
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-xl: 24px;
            --radius-xxl: 30px;
        }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            margin: 0; 
            padding: 20px;
            line-height: 1.5;
            font-size: 16px;
        }
        
        @media (max-width: 768px) {
            body {
                padding: 16px;
                font-size: 15px;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 12px;
                font-size: 14px;
            }
        }
        
        .settings-container { 
            background: rgba(255, 255, 255, 0.98); 
            backdrop-filter: blur(20px);
            padding: 40px; 
            border-radius: var(--radius-xxl); 
            box-shadow: 0 25px 80px rgba(0,0,0,0.25); 
            max-width: 700px; 
            width: 100%;
            border: 1px solid rgba(255,255,255,0.2);
            position: relative;
            overflow: hidden;
        }
        
        @media (max-width: 768px) {
            .settings-container {
                padding: 30px 25px;
            }
        }
        
        @media (max-width: 480px) {
            .settings-container {
                padding: 25px 20px;
                border-radius: var(--radius-xl);
            }
        }
        
        .settings-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 6px;
            background: var(--primary-gradient);
        }
        
        h1 { 
            color: #2d3748; 
            margin-bottom: 30px; 
            text-align: center;
            font-size: 2em;
            font-weight: 700;
            letter-spacing: -0.5px;
            position: relative;
            display: inline-block;
            left: 50%;
            transform: translateX(-50%);
            width: 100%;
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 1.7em;
                margin-bottom: 25px;
            }
        }
        
        h1::after {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 25%;
            width: 50%;
            height: 4px;
            background: var(--primary-gradient);
            border-radius: 2px;
        }
        
        h2 { 
            color: #4a5568; 
            margin-top: 0; 
            margin-bottom: 20px; 
            padding-bottom: 12px;
            border-bottom: 2px solid #e2e8f0;
            font-size: 1.2em;
            font-weight: 800; /* Plus gras comme demandé */
            letter-spacing: -0.3px;
        }
        
        @media (max-width: 768px) {
            h2 {
                font-size: 1.1em;
                margin-bottom: 18px;
            }
        }
        
        .settings-section {
            background: #f8f9fa;
            border-radius: var(--radius-xl);
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid #e9ecef;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        
        .settings-section:last-child {
            margin-bottom: 0;
        }
        
        .form-group { 
            margin-bottom: 20px; 
            position: relative;
            width: 100%;
        }
        
        label { 
            display: block; 
            font-weight: 600; 
            margin-bottom: 8px; 
            color: #2d3748;
            font-size: 0.95em;
            letter-spacing: 0.3px;
        }
        
        @media (max-width: 768px) {
            label {
                font-size: 0.9em;
            }
        }
        
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 15px 18px; 
            border: 2px solid #e2e8f0; 
            border-radius: var(--radius-lg); 
            box-sizing: border-box; 
            font-size: 16px;
            font-family: inherit;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            background: rgba(255,255,255,0.9);
            position: relative;
            overflow: hidden;
        }
        
        input[type="text"]:focus, input[type="password"]:focus { 
            border-color: #667eea; 
            outline: none;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.15);
            transform: translateY(-2px);
        }
        
        @media (max-width: 768px) {
            input[type="text"], input[type="password"] {
                padding: 14px 16px;
                font-size: 16px;
            }
        }
        
        /* Photo de profil améliorée */
        .profile-pic-preview-wrapper { 
            text-align: center; 
            margin-bottom: 25px; 
            position: relative;
            width: 100%;
        }
        
        .profile-pic-preview { 
            width: 140px; 
            height: 140px; 
            border-radius: 50%; 
            object-fit: cover; 
            border: 4px solid white;
            box-shadow: 0 15px 40px rgba(0,0,0,0.2), 0 0 0 6px var(--primary-gradient);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            z-index: 2;
            background: #764ba2; /* Couleur de fond par défaut */
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 50px;
            font-weight: 800;
        }
        
        @media (max-width: 768px) {
            .profile-pic-preview {
                width: 120px;
                height: 120px;
                font-size: 40px;
            }
        }
        
        @media (max-width: 480px) {
            .profile-pic-preview {
                width: 100px;
                height: 100px;
                font-size: 35px;
            }
        }
        
        .profile-pic-preview.preview-updating {
            animation: pulse-preview 1.5s infinite;
            border-color: #667eea;
        }
        
        @keyframes pulse-preview {
            0% { box-shadow: 0 0 0 0 rgba(102, 126, 234, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(102, 126, 234, 0); }
            100% { box-shadow: 0 0 0 0 rgba(102, 126, 234, 0); }
        }
        
        /* Upload file amélioré pour mobile - Correction du bouton Parcourir */
        .custom-file-upload {
            display: flex;
            flex-direction: column;
            gap: 12px;
            width: 100%;
        }
        
        .file-input-wrapper {
            position: relative;
            display: flex;
            align-items: center;
            width: 100%;
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            border: 2px dashed #cbd5e0;
            border-radius: var(--radius-lg);
            overflow: hidden;
            transition: all 0.3s;
            position: relative;
        }
        
        .file-input-wrapper:hover {
            border-color: #667eea;
            background: linear-gradient(135deg, #f1f5f9, #e2e8f0);
        }
        
        .file-input-wrapper input[type="file"] {
            opacity: 0;
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
            z-index: 2;
        }
        
        .file-name-display {
            flex: 1;
            padding: 16px 20px;
            color: #4a5568;
            font-weight: 500;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 14px;
        }
        
        .file-name-display.has-file {
            color: #667eea;
            font-weight: 600;
        }
        
        .browse-btn {
            background: var(--primary-gradient);
            color: white;
            padding: 16px 24px;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s;
            white-space: nowrap;
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 120px;
            position: relative;
            overflow: hidden;
        }
        
        .browse-btn:hover {
            background: linear-gradient(135deg, #764ba2, #667eea);
        }
        
        @media (max-width: 768px) {
            .file-input-wrapper {
                flex-direction: column;
                align-items: stretch;
            }
            
            .file-name-display {
                padding: 14px 18px;
                text-align: center;
                border-bottom: 1px solid #e2e8f0;
            }
            
            .browse-btn {
                width: 100%;
                padding: 14px;
                min-width: auto;
            }
        }
        
        .upload-hint {
            display: block;
            text-align: center;
            color: #718096;
            font-size: 14px;
            margin-top: 12px;
            font-weight: 500;
        }
        
        /* Buttons améliorés pour mobile - MODIFICATION IMPORTANTE */
        .btn-submit { 
            width: auto !important; 
            min-width: 200px !important;
            padding: 12px 24px !important; 
            background: var(--primary-gradient) !important; 
            color: white !important; 
            border: none !important; 
            border-radius: var(--radius-lg) !important; 
            font-size: 16px !important; 
            font-weight: 600 !important; 
            cursor: pointer !important; 
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
            letter-spacing: 0.5px !important;
            font-family: inherit !important;
            margin-top: 10px !important;
            position: relative !important;
            overflow: hidden !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: flex-start !important;
            gap: 10px !important;
            text-align: left !important;
            float: left !important;
            margin-right: 15px !important;
        }
        
        .btn-submit:hover { 
            transform: translateY(-3px) !important;
            box-shadow: 0 15px 40px rgba(102, 126, 234, 0.4) !important;
        }
        
        .btn-submit:active { 
            transform: translateY(-1px) !important;
        }
        
        .btn-danger { 
            background: linear-gradient(45deg, var(--danger), #fd7e14) !important;
            margin-top: 20px !important;
        }
        
        .btn-danger:hover {
            box-shadow: 0 15px 40px rgba(220, 53, 69, 0.4) !important;
        }
        
        /* Messages améliorés pour mobile */
        .message { 
            padding: 18px; 
            border-radius: var(--radius-lg); 
            margin-bottom: 20px; 
            font-weight: 600;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.3);
            animation: slideIn 0.5s ease-out;
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .message {
                padding: 16px;
                margin-bottom: 18px;
            }
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message.success { 
            background: linear-gradient(135deg, rgba(212, 237, 218, 0.9), rgba(195, 230, 203, 0.9)); 
            color: #155724; 
            border-color: #c3e6cb;
        }
        
        .message.error { 
            background: linear-gradient(135deg, rgba(248, 215, 218, 0.9), rgba(245, 198, 203, 0.9)); 
            color: #721c24; 
            border-color: #f5c6cb;
        }
        
        /* Back link amélioré pour mobile - Style violet moderne */
        .back-link { 
            display: inline-flex !important;
            align-items: center !important;
            gap: 15px !important;
            margin-bottom: 30px !important; 
            font-size: 18px !important;
            font-weight: 700 !important;
            cursor: pointer !important;
            transition: all 0.3s !important;
            color: #764ba2 !important;
            text-decoration: none !important;
            padding: 16px 28px !important;
            border-radius: var(--radius-xl) !important;
            background: linear-gradient(135deg, rgba(118, 75, 162, 0.1), rgba(102, 126, 234, 0.1)) !important;
            border: 2px solid rgba(118, 75, 162, 0.3) !important;
            box-shadow: 0 6px 20px rgba(118, 75, 162, 0.2) !important;
            width: auto !important;
            position: relative !important;
            overflow: hidden !important;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
            letter-spacing: 0.3px !important;
        }
        
        .back-link:hover {
            transform: translateX(-5px) !important;
            background: linear-gradient(135deg, rgba(118, 75, 162, 0.2), rgba(102, 126, 234, 0.2)) !important;
            box-shadow: 0 12px 30px rgba(118, 75, 162, 0.3) !important;
            color: #667eea !important;
            border-color: #667eea !important;
        }
        
        .back-link i {
            font-size: 24px !important;
            transition: transform 0.3s !important;
            color: #764ba2 !important;
        }
        
        .back-link:hover i {
            transform: translateX(-3px) !important;
            color: #667eea !important;
        }
        
        @media (max-width: 768px) {
            .back-link {
                margin-bottom: 25px !important;
                padding: 14px 22px !important;
                font-size: 17px !important;
                width: 100% !important;
                justify-content: center !important;
            }
        }
        
        .section-divider {
            height: 1px;
            background: linear-gradient(90deg, transparent, #e2e8f0, transparent);
            margin: 30px 0;
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .section-divider {
                margin: 25px 0;
            }
        }
        
        /* Delete section améliorée pour mobile */
        .delete-section {
            background: linear-gradient(135deg, rgba(254, 226, 226, 0.2), rgba(254, 215, 215, 0.1));
            padding: 25px;
            border-radius: var(--radius-xl);
            border: 2px solid #fed7d7;
            margin-top: 25px;
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .delete-section {
                padding: 20px;
                margin-top: 20px;
            }
        }
        
        .delete-section h2 {
            color: #c53030;
            border-bottom-color: #fed7d7;
        }
        
        /* Preview notification */
        .preview-notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 12px 20px;
            border-radius: var(--radius-lg);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
            z-index: 1000;
            font-weight: 600;
            max-width: 300px;
            animation: slideUp 0.3s ease-out;
            display: none;
        }
        
        @keyframes slideUp {
            from { transform: translateY(100px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        /* Améliorations pour les très petits écrans */
        @media (max-width: 360px) {
            h1 {
                font-size: 1.5em;
            }
            
            h2 {
                font-size: 1em;
            }
            
            .profile-pic-preview {
                width: 90px;
                height: 90px;
                font-size: 30px;
            }
            
            .btn-submit {
                padding: 12px 20px !important;
                font-size: 15px !important;
                min-width: 180px !important;
            }
            
            .file-name-display {
                padding: 12px 16px;
                font-size: 13px;
            }
            
            .browse-btn {
                padding: 12px;
                font-size: 13px;
                min-width: 100px;
            }
            
            .back-link {
                font-size: 16px !important;
                padding: 14px 20px !important;
            }
            
            .back-link i {
                font-size: 20px !important;
            }
        }
        
        /* Support pour l'accessibilité mobile */
        @media (hover: none) and (pointer: coarse) {
            .profile-pic-preview:hover,
            .back-link:hover,
            .btn-submit:hover,
            .file-input-wrapper:hover,
            .browse-btn:hover {
                transform: none !important;
            }
        }
        
        /* Support pour iOS */
        @supports (-webkit-touch-callout: none) {
            body {
                min-height: -webkit-fill-available;
            }
            
            .settings-container {
                min-height: -webkit-fill-available;
            }
        }
        
        /* Correction pour aligner les boutons à gauche */
        .settings-section form {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }
        
        /* Clear fix pour les boutons flottants */
        .settings-section::after {
            content: "";
            display: table;
            clear: both;
        }
    </style>
    <script>
        function confirmDelete() {
            return confirm("ATTENTION : Êtes-vous ABSOLUMENT CERTAIN de vouloir SUPPRIMER votre compte ? Cette action est IRREVERSIBLE et toutes vos tâches seront perdues.");
        }
        
        let currentPreviewImage = null;
        
        function previewImage(input) {
            const preview = document.getElementById('profile-pic-preview');
            const fileNameDisplay = document.getElementById('file-name');
            
            if (input.files && input.files[0]) {
                const file = input.files[0];
                
                // Validation du fichier
                const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
                if (!allowedTypes.includes(file.type)) {
                    showPreviewMessage('❌ Type de fichier non supporté. Utilisez JPG, PNG ou GIF.', 'error');
                    input.value = '';
                    fileNameDisplay.textContent = 'Choisir un fichier';
                    fileNameDisplay.classList.remove('has-file');
                    return;
                }
                
                // Vérifier la taille (max 5MB)
                if (file.size > 5 * 1024 * 1024) {
                    showPreviewMessage('❌ Fichier trop volumineux (max 5MB)', 'error');
                    input.value = '';
                    fileNameDisplay.textContent = 'Choisir un fichier';
                    fileNameDisplay.classList.remove('has-file');
                    return;
                }
                
                // Mettre à jour le nom du fichier IMMÉDIATEMENT
                fileNameDisplay.textContent = file.name;
                fileNameDisplay.classList.add('has-file');
                
                // Aperçu instantané avec URL.createObjectURL
                const objectURL = URL.createObjectURL(file);
                
                // Remplacer le div par une image si nécessaire
                if (preview.tagName === 'DIV') {
                    const newImg = document.createElement('img');
                    newImg.id = 'profile-pic-preview';
                    newImg.className = 'profile-pic-preview';
                    newImg.alt = 'Photo de profil';
                    preview.parentNode.replaceChild(newImg, preview);
                }
                
                // Mettre à jour l'image avec la nouvelle source
                const imgElement = document.getElementById('profile-pic-preview');
                imgElement.classList.add('preview-updating');
                imgElement.src = objectURL;
                imgElement.style.background = 'transparent';
                
                // Afficher le message de prévisualisation
                showPreviewMessage('✅ Photo sélectionnée avec succès !', 'success');
                
                // Nettoyer l'URL et retirer l'animation après 2 secondes
                setTimeout(() => {
                    imgElement.classList.remove('preview-updating');
                    URL.revokeObjectURL(objectURL);
                }, 2000);
                
            } else {
                // Réinitialiser si aucun fichier sélectionné
                fileNameDisplay.textContent = 'Choisir un fichier';
                fileNameDisplay.classList.remove('has-file');
            }
        }
        
        function showPreviewMessage(message, type) {
            // Supprimer tout message existant
            const existingMessage = document.getElementById('preview-notification');
            if (existingMessage) existingMessage.remove();
            
            // Créer un nouveau message
            const messageDiv = document.createElement('div');
            messageDiv.id = 'preview-notification';
            messageDiv.className = 'preview-notification';
            messageDiv.textContent = message;
            messageDiv.style.cssText = `
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: linear-gradient(45deg, ${type === 'success' ? '#667eea' : '#F44336'}, ${type === 'success' ? '#764ba2' : '#fd7e14'});
                color: white;
                padding: 12px 20px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                z-index: 1000;
                font-weight: 600;
                max-width: 300px;
                display: block;
            `;
            
            document.body.appendChild(messageDiv);
            
            // Supprimer après 3 secondes
            setTimeout(() => {
                messageDiv.style.opacity = '0';
                messageDiv.style.transform = 'translateY(100px)';
                setTimeout(() => messageDiv.remove(), 300);
            }, 3000);
        }
        
        function resetPreview() {
            const preview = document.getElementById('profile-pic-preview');
            const fileNameDisplay = document.getElementById('file-name');
            const fileInput = document.getElementById('profile_photo');
            
            if (currentPreviewImage) {
                preview.src = currentPreviewImage;
                if (currentPreviewImage.includes('default-avatar')) {
                    preview.classList.add('default-avatar');
                }
            }
            
            fileNameDisplay.textContent = 'Choisir un fichier';
            fileNameDisplay.classList.remove('has-file');
            fileInput.value = '';
        }
        
        // Initialiser l'aperçu actuel
        document.addEventListener('DOMContentLoaded', function() {
            const preview = document.getElementById('profile-pic-preview');
            if (preview.tagName === 'IMG') {
                currentPreviewImage = preview.src;
            }
            
            // Mettre à jour le texte initial du nom de fichier
            const fileNameDisplay = document.getElementById('file-name');
            if (preview.src && !preview.src.includes('default-avatar')) {
                fileNameDisplay.textContent = 'Photo actuelle sélectionnée';
                fileNameDisplay.classList.add('has-file');
            }
            
            // Prévenir le zoom sur les inputs sur iOS
            document.addEventListener('touchstart', function() {}, {passive: true});
        });
    </script>
</head>
<body>
    <div class="settings-container">
        <a href="{{ url_for('index') }}" class="back-link">
            <i class="fas fa-arrow-left"></i>
            <span>Retour à la page d'accueil</span>
        </a>
        
        <h1>Paramètres du compte</h1>
        
        {% if message %}
            <div class="message {{ 'success' if is_success else 'error' }}">{{ message }}</div>
        {% endif %}

        <div class="settings-section">
            <h2>Photo de profil</h2>
            <div class="profile-pic-preview-wrapper">
                <div class="preview-container">
                    {% if current_user.profile_photo %}
                    <img id="profile-pic-preview" src="{{ current_user.profile_photo }}?t={{ range(1, 10000) | random }}" alt="Photo de profil" class="profile-pic-preview">
                    {% else %}
                    <div id="profile-pic-preview" class="profile-pic-preview default-avatar">
                        {{ current_user.username[0]|upper }}
                    </div>
                    {% endif %}
                </div>
            </div>
            
            <form method="POST" action="{{ url_for('settings') }}" enctype="multipart/form-data" id="uploadForm">
                <input type="hidden" name="action" value="upload_photo">
                <div class="form-group">
                    <label for="profile_photo">Choisissez votre photo de profil</label>
                    <div class="custom-file-upload">
                        <div class="file-input-wrapper">
                            <input type="file" id="profile_photo" name="profile_photo" accept=".png, .jpg, .jpeg, .gif" onchange="previewImage(this);">
                            <div class="file-name-display {% if current_user.profile_photo %}has-file{% endif %}" id="file-name">
                                {% if current_user.profile_photo %}Photo actuelle sélectionnée{% else %}Choisir un fichier{% endif %}
                            </div>
                            <button type="button" class="browse-btn" onclick="document.getElementById('profile_photo').click()">
                                <i class="fas fa-folder-open"></i> Parcourir
                            </button>
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-upload"></i> Changer la photo
                </button>
            </form>
            
            {% if current_user.profile_photo %}
            <form method="POST" action="{{ url_for('settings') }}" style="margin-top: 15px; float: left;">
                <input type="hidden" name="action" value="delete_photo">
                <button type="submit" class="btn-submit btn-danger">
                    <i class="fas fa-trash"></i> Supprimer la photo actuelle
                </button>
            </form>
            {% endif %}
        </div>
        
        <div class="settings-section">
            <h2>Changer le nom d'utilisateur</h2>
            <form method="POST" action="{{ url_for('settings') }}">
                <input type="hidden" name="action" value="change_username">
                <div class="form-group">
                    <label for="new_username">Nouveau nom d'utilisateur</label>
                    <input type="text" id="new_username" name="new_username" required value="{{ current_user.username }}">
                </div>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-user"></i> Mettre à jour le nom
                </button>
            </form>
        </div>

        <div class="settings-section">
            <h2>Changer le mot de passe</h2>
            <form method="POST" action="{{ url_for('settings') }}">
                <input type="hidden" name="action" value="change_password">
                <div class="form-group">
                    <label for="old_password">Ancien mot de passe</label>
                    <input type="password" id="old_password" name="old_password" required>
                </div>
                <div class="form-group">
                    <label for="new_password">Nouveau mot de passe</label>
                    <input type="password" id="new_password" name="new_password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirmer nouveau mot de passe</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-lock"></i> Mettre à jour le mot de passe
                </button>
            </form>
        </div>
        
        <div class="settings-section delete-section">
            <h2>Supprimer le compte</h2>
            <form method="POST" action="{{ url_for('settings') }}" onsubmit="return confirmDelete()">
                <input type="hidden" name="action" value="delete_account">
                <div class="form-group">
                     <label for="delete_password">Confirmez votre mot de passe pour la suppression</label>
                     <input type="password" id="delete_password" name="delete_password" required>
                </div>
                <button type="submit" class="btn-submit btn-danger">
                    <i class="fas fa-exclamation-triangle"></i> Supprimer définitivement le compte
                </button>
            </form>
        </div>
        
    </div>
</body>
</html>'''

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    message = None
    is_success = False
    db = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload_photo':
            file = request.files.get('profile_photo')
            
            if file and allowed_file(file.filename):
                # Créer le dossier s'il n'existe pas
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                # Supprimer l'ancienne photo si elle existe
                if current_user.profile_photo and current_user.profile_photo.startswith('/static/uploads/'):
                    old_relative_path = current_user.profile_photo.replace('/static/', '')
                    old_full_path = os.path.join('static', old_relative_path)
                    if os.path.exists(old_full_path):
                        try:
                            os.remove(old_full_path)
                        except Exception as e:
                            print(f"Erreur suppression ancien fichier: {e}")
                
                try:
                    # Traiter l'image pour la rendre carrée
                    processed_image = process_image(file.stream)
                    
                    if processed_image:
                        # Générer un nom de fichier unique
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = secure_filename(file.filename)
                        file_ext = 'jpg'  # Toujours sauvegarder en JPEG pour meilleure compression
                        filename_with_id = f'{current_user.id}_{timestamp}.{file_ext}'
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename_with_id)
                        
                        # Sauvegarder l'image traitée
                        with open(filepath, 'wb') as f:
                            f.write(processed_image.getvalue())
                        
                        photo_path = f'/static/uploads/{filename_with_id}'
                        
                        db.execute('UPDATE users SET profile_photo = ? WHERE id = ?', (photo_path, current_user.id))
                        db.commit()
                        
                        # Mettre à jour l'objet current_user
                        current_user.profile_photo = photo_path
                        
                        message = "✅ Photo de profil mise à jour avec succès !"
                        is_success = True
                    else:
                        message = "❌ Erreur lors du traitement de l'image."
                        
                except Exception as e:
                    message = f"❌ Erreur lors de la sauvegarde : {str(e)}"
            else:
                message = "❌ Veuillez sélectionner un fichier valide (png, jpg, jpeg, gif)."

        elif action == 'delete_photo':
            if current_user.profile_photo and current_user.profile_photo.startswith('/static/uploads/'):
                relative_path = current_user.profile_photo.replace('/static/', '')
                full_path = os.path.join('static', relative_path)
                if os.path.exists(full_path):
                    try:
                        os.remove(full_path)
                    except Exception as e:
                        print(f"Erreur suppression fichier: {e}")

            db.execute('UPDATE users SET profile_photo = NULL WHERE id = ?', (current_user.id,))
            db.commit()
            current_user.profile_photo = None 
            message = "✅ Photo de profil supprimée avec succès. L'avatar par défaut est restauré."
            is_success = True
        
        elif action == 'change_username':
            new_username = request.form.get('new_username', '').strip()
            
            if not new_username:
                message = "❌ Le nom d'utilisateur ne peut pas être vide."
            elif new_username == current_user.username:
                message = "ℹ️ Le nouveau nom d'utilisateur est le même que l'actuel."
                is_success = True
            else:
                try:
                    existing_user = db.execute('SELECT id FROM users WHERE username = ?', (new_username,)).fetchone()
                    if existing_user and existing_user['id'] != current_user.id:
                        message = "❌ Nom d'utilisateur existe déjà."
                    else:
                        db.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, current_user.id))
                        db.commit()
                        # CORRECTION : On ne déconnecte PAS l'utilisateur, on met juste à jour l'objet current_user
                        current_user.username = new_username
                        message = f"✅ Nom d'utilisateur modifié avec succès en: {new_username}."
                        is_success = True
                        # On NE redirige PAS vers login, on reste sur la page settings

                except Exception as e:
                    message = f"❌ Erreur lors du changement de nom d'utilisateur: {e}"
        
        elif action == 'change_password':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not all([old_password, new_password, confirm_password]):
                message = "❌ Tous les champs de mot de passe sont requis."
            elif new_password != confirm_password:
                message = "❌ Le nouveau mot de passe et sa confirmation ne correspondent pas."
            else:
                user_data = db.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,)).fetchone()
                if user_data and check_password_hash(user_data['password_hash'], old_password):
                    hashed_password = generate_password_hash(new_password)
                    db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, current_user.id))
                    db.commit()
                    message = "✅ Mot de passe changé avec succès."
                    is_success = True
                    # On NE déconnecte PAS l'utilisateur, on met juste à jour le mot de passe
                else:
                    message = "❌ L'ancien mot de passe est incorrect."
                    
        elif action == 'delete_account':
            delete_password = request.form.get('delete_password')
            
            if not delete_password:
                message = "❌ Le mot de passe de confirmation est requis pour supprimer le compte."
            else:
                user_data = db.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,)).fetchone()
                if user_data and check_password_hash(user_data['password_hash'], delete_password):
                    # Suppression des tâches associées
                    db.execute('DELETE FROM tasks WHERE user_id = ?', (current_user.id,))
                    # Suppression de l'utilisateur
                    db.execute('DELETE FROM users WHERE id = ?', (current_user.id,))
                    db.commit()
                    
                    logout_user() 
                    return render_template_string(AUTH_FORM, error="✅ Votre compte et toutes vos tâches ont été supprimés avec succès. Merci d'avoir utilisé Tacheo.", is_register=False)
                else:
                    message = "❌ Mot de passe de confirmation incorrect."
    
    return render_template_string(SETTINGS_TEMPLATE, current_user=current_user, message=message, is_success=is_success)


# Les routes API
@app.route('/api/tasks')
@login_required
def get_tasks():
    user_id = current_user.id
    status_filter = request.args.get('filter', 'all')
    category_filter = request.args.get('category_filter', 'all')
    priority_filter = request.args.get('priority_filter', 'all')
    
    db = get_db()
    c = db.cursor()
    
    base_query = "SELECT * FROM tasks WHERE user_id = ?"
    params = [user_id]
    
    if status_filter == 'deleted':
        base_query += " AND status = 'deleted'"
    elif status_filter == 'pending':
        base_query += " AND status = 'pending'"
    elif status_filter == 'completed':
        base_query += " AND status = 'completed'"
    else: 
        base_query += " AND status != 'deleted'" 

    if category_filter != 'all':
        base_query += " AND category = ?"
        params.append(category_filter)

    if priority_filter != 'all':
        base_query += " AND priority = ?"
        params.append(priority_filter)

    # Trier uniquement par date (la plus proche en premier) sans tenir compte de la priorité
    base_query += " ORDER BY COALESCE(due_date, '9999-12-31') ASC, created_at DESC"
    
    c.execute(base_query, tuple(params))
    rows = c.fetchall()
    
    tasks = [dict(row) for row in rows]
    
    return jsonify(tasks)

@app.route('/api/alltasks')
@login_required
def get_all_tasks():
    user_id = current_user.id
    db = get_db()
    c = db.cursor()
    # Trier uniquement par date (la plus proche en premier) sans tenir compte de la priorité
    c.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY COALESCE(due_date, '9999-12-31') ASC, created_at DESC", (user_id,))
    rows = c.fetchall()
    
    tasks = [dict(row) for row in rows]
    
    return jsonify(tasks)

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    try:
        data = request.json
        if not data or 'title' not in data:
            return jsonify({'error': 'Données invalides'}), 400
            
        user_id = current_user.id
        db = get_db()
        c = db.cursor()
        c.execute('INSERT INTO tasks (title, description, due_date, priority, category, status, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                  (data['title'], data.get('description', ''), data.get('due_date'), 
                   data.get('priority', 'important'), data.get('category', 'personnel'), 
                   data.get('status', 'pending'), user_id))
        db.commit()
        return jsonify({'success': True}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@login_required
def update_task(task_id):
    data = request.json
    user_id = current_user.id
    db = get_db()
    c = db.cursor()
    
    if 'status' in data and len(data) == 1:
        c.execute('UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?', (data['status'], task_id, user_id))
    else:
        c.execute('UPDATE tasks SET title=?, description=?, due_date=?, priority=?, category=? WHERE id=? AND user_id = ?',
                  (data['title'], data['description'], data['due_date'], data['priority'], data['category'], task_id, user_id))
    db.commit()
    return jsonify({'success': True})


@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def hard_delete_single_task(task_id):
    user_id = current_user.id
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/tasks/clear_trash', methods=['DELETE'])
@login_required
def clear_trash():
    user_id = current_user.id
    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM tasks WHERE status = 'deleted' AND user_id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True})

# --- 7. DÉMARRAGE DU SERVEUR ---

# Handler pour Vercel
def create_app():
    return app

if __name__ == '__main__':
    # Vérifier si la base de données existe déjà
    db_exists = os.path.exists(app.config['DATABASE'])
    
    if not db_exists:
        print(f"Création de la base de données {app.config['DATABASE']}...")
        init_db()
    
    # Créer le dossier uploads s'il n'existe pas
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        print(f"Dossier créé: {app.config['UPLOAD_FOLDER']}")
         
        
    print("🚀 Serveur Tacheo démarré: http://localhost:5000/login")
    print("📱 Interface optimisée pour mobile")
    print(f"💾 Base de données: {app.config['DATABASE']}")
    print(f"📸 Dossier des photos: {app.config['UPLOAD_FOLDER']}")
    print("✨ Adapté pour Vercel")
    app.run(debug=True, host='0.0.0.0', port=5000)