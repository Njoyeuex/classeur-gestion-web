"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         CLASSEUR DE GESTION FINANCIÈRE  —  Version Web 2.0                  ║
║  Avec base de données SQLite et authentification multi-utilisateurs          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import sqlite3, os, datetime, io, hashlib, secrets
from collections import defaultdict
from functools import wraps
from pathlib import Path

# ── ReportLab (export PDF) ───────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ── Base de données ───────────────────────────────────────────────────────────
DB_PATH = os.environ.get('DB_PATH', 'classeur.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS entreprise (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            nom TEXT DEFAULT 'Mon Entreprise',
            adresse TEXT DEFAULT '',
            telephone TEXT DEFAULT '',
            email TEXT DEFAULT '',
            nif TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT,
            description TEXT,
            client TEXT,
            categorie TEXT,
            extra TEXT,
            montant REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS biens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT,
            description TEXT,
            client TEXT,
            categorie TEXT,
            extra REAL DEFAULT 1,
            montant REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sorties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT,
            description TEXT,
            client TEXT,
            categorie TEXT,
            extra TEXT,
            montant REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            nom TEXT,
            categorie TEXT,
            quantite REAL DEFAULT 0,
            cout_unitaire REAL DEFAULT 0,
            fournisseur TEXT,
            date_entree TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS stock_mouvements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stock_id INTEGER NOT NULL,
            date TEXT,
            type TEXT,
            quantite REAL DEFAULT 0,
            montant REAL DEFAULT 0,
            FOREIGN KEY (stock_id) REFERENCES stock(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS caisse (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT,
            type TEXT,
            description TEXT,
            categorie TEXT,
            reference TEXT,
            montant REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS budget (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mois TEXT,
            categorie TEXT,
            prevu REAL DEFAULT 0,
            description TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

# Initialiser la BDD au démarrage
init_db()

# ── Authentification ──────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'ok': False, 'error': 'Non authentifié'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def current_user_id():
    return session.get('user_id')

# ── Utilitaires ───────────────────────────────────────────────────────────────

def parse_date(s):
    for fmt in ('%d/%m/%Y', '%Y-%m-%d', '%d-%m-%Y'):
        try:
            return datetime.datetime.strptime(s.strip(), fmt).date()
        except (ValueError, AttributeError):
            pass
    return None

def get_month_key(date_str):
    d = parse_date(date_str)
    return d.strftime('%Y-%m') if d else '0000-00'

def row_to_dict(row):
    return dict(row) if row else None

def rows_to_list(rows):
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════════════════════
# PAGES D'AUTHENTIFICATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('auth.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('auth.html', mode='register')

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not username or not email or not password:
        return jsonify({'ok': False, 'error': 'Tous les champs sont requis'}), 400
    if len(password) < 6:
        return jsonify({'ok': False, 'error': 'Mot de passe trop court (6 caractères min)'}), 400
    if len(username) < 3:
        return jsonify({'ok': False, 'error': 'Nom trop court (3 caractères min)'}), 400

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hash_password(password))
            )
            user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            uid = user['id']
            # Créer entrée entreprise par défaut
            conn.execute(
                "INSERT INTO entreprise (user_id, nom) VALUES (?, ?)",
                (uid, f"Entreprise de {username}")
            )
            session['user_id'] = uid
            session['username'] = username
            return jsonify({'ok': True, 'username': username})
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return jsonify({'ok': False, 'error': 'Ce nom d\'utilisateur est déjà pris'}), 400
        return jsonify({'ok': False, 'error': 'Cet email est déjà utilisé'}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({'ok': False, 'error': 'Email et mot de passe requis'}), 400

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ? AND password_hash = ?",
            (email, hash_password(password))
        ).fetchone()

    if not user:
        return jsonify({'ok': False, 'error': 'Email ou mot de passe incorrect'}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({'ok': True, 'username': user['username']})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me')
def me():
    if 'user_id' not in session:
        return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'username': session.get('username'), 'user_id': session.get('user_id')})

# ══════════════════════════════════════════════════════════════════════════════
# PAGE PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))

# ══════════════════════════════════════════════════════════════════════════════
# API — DONNÉES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/data')
@login_required
def get_all_data():
    uid = current_user_id()
    with get_db() as conn:
        services = rows_to_list(conn.execute("SELECT * FROM services WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        biens    = rows_to_list(conn.execute("SELECT * FROM biens WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        sorties  = rows_to_list(conn.execute("SELECT * FROM sorties WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        caisse   = rows_to_list(conn.execute("SELECT * FROM caisse WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        budget   = rows_to_list(conn.execute("SELECT * FROM budget WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        entreprise = row_to_dict(conn.execute("SELECT * FROM entreprise WHERE user_id=?", (uid,)).fetchone())
        stock_rows = rows_to_list(conn.execute("SELECT * FROM stock WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())

        # Charger les mouvements pour chaque article de stock
        for item in stock_rows:
            movs = rows_to_list(conn.execute(
                "SELECT * FROM stock_mouvements WHERE stock_id=? ORDER BY id", (item['id'],)
            ).fetchall())
            item['mouvements'] = movs

    if not entreprise:
        entreprise = {'nom': 'Mon Entreprise', 'adresse': '', 'telephone': '', 'email': '', 'nif': ''}

    return jsonify({
        'services': services, 'biens': biens, 'sorties': sorties,
        'caisse': caisse, 'budget': budget, 'stock': stock_rows,
        'entreprise': entreprise
    })

@app.route('/api/entreprise', methods=['POST'])
@login_required
def update_entreprise():
    uid = current_user_id()
    d = request.json
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM entreprise WHERE user_id=?", (uid,)).fetchone()
        if existing:
            conn.execute("""
                UPDATE entreprise SET nom=?, adresse=?, telephone=?, email=?, nif=?
                WHERE user_id=?
            """, (d.get('nom',''), d.get('adresse',''), d.get('telephone',''),
                  d.get('email',''), d.get('nif',''), uid))
        else:
            conn.execute("""
                INSERT INTO entreprise (user_id, nom, adresse, telephone, email, nif)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uid, d.get('nom',''), d.get('adresse',''), d.get('telephone',''),
                  d.get('email',''), d.get('nif','')))
    return jsonify({'ok': True})

# ── CRUD générique ─────────────────────────────────────────────────────────

def crud_add_generic(table):
    uid = current_user_id()
    rec = request.json
    with get_db() as conn:
        conn.execute(f"""
            INSERT INTO {table} (user_id, date, description, client, categorie, extra, montant)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (uid, rec.get('date',''), rec.get('description',''), rec.get('client',''),
              rec.get('categorie',''), rec.get('extra',''), float(rec.get('montant',0))))
        rows = rows_to_list(conn.execute(f"SELECT * FROM {table} WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify({'ok': True, 'data': rows})

def crud_delete_generic(table, row_id):
    uid = current_user_id()
    with get_db() as conn:
        result = conn.execute(f"DELETE FROM {table} WHERE id=? AND user_id=?", (row_id, uid))
        if result.rowcount == 0:
            return jsonify({'ok': False, 'error': 'Enregistrement introuvable'}), 404
    return jsonify({'ok': True})

@app.route('/api/services', methods=['GET', 'POST'])
@login_required
def services():
    if request.method == 'POST':
        return crud_add_generic('services')
    uid = current_user_id()
    with get_db() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM services WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify(rows)

@app.route('/api/services/<int:row_id>', methods=['DELETE'])
@login_required
def service_delete(row_id):
    return crud_delete_generic('services', row_id)

@app.route('/api/biens', methods=['GET', 'POST'])
@login_required
def biens():
    if request.method == 'POST':
        uid = current_user_id()
        rec = request.json
        qty = float(rec.get('extra', 0) or 1)
        desc = (rec.get('description') or '').lower().strip()
        with get_db() as conn:
            # Mise à jour stock si l'article existe
            stock_item = conn.execute(
                "SELECT id, quantite FROM stock WHERE user_id=? AND LOWER(nom)=?",
                (uid, desc)
            ).fetchone()
            if stock_item:
                new_qte = max(0, float(stock_item['quantite']) - qty)
                conn.execute("UPDATE stock SET quantite=? WHERE id=?", (new_qte, stock_item['id']))
                conn.execute("""
                    INSERT INTO stock_mouvements (stock_id, date, type, quantite, montant)
                    VALUES (?, ?, 'vente', ?, ?)
                """, (stock_item['id'], rec.get('date',''), -qty, float(rec.get('montant',0))))
            # Ajouter la vente
            conn.execute("""
                INSERT INTO biens (user_id, date, description, client, categorie, extra, montant)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (uid, rec.get('date',''), rec.get('description',''), rec.get('client',''),
                  rec.get('categorie',''), qty, float(rec.get('montant',0))))
            rows = rows_to_list(conn.execute("SELECT * FROM biens WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        return jsonify({'ok': True, 'data': rows})
    uid = current_user_id()
    with get_db() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM biens WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify(rows)

@app.route('/api/biens/<int:row_id>', methods=['DELETE'])
@login_required
def bien_delete(row_id):
    return crud_delete_generic('biens', row_id)

@app.route('/api/sorties', methods=['GET', 'POST'])
@login_required
def sorties():
    if request.method == 'POST':
        return crud_add_generic('sorties')
    uid = current_user_id()
    with get_db() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM sorties WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify(rows)

@app.route('/api/sorties/<int:row_id>', methods=['DELETE'])
@login_required
def sortie_delete(row_id):
    return crud_delete_generic('sorties', row_id)

@app.route('/api/caisse', methods=['GET', 'POST'])
@login_required
def caisse():
    if request.method == 'POST':
        uid = current_user_id()
        rec = request.json
        with get_db() as conn:
            conn.execute("""
                INSERT INTO caisse (user_id, date, type, description, categorie, reference, montant)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (uid, rec.get('date',''), rec.get('type','entrée'),
                  rec.get('description',''), rec.get('categorie',''),
                  rec.get('reference',''), float(rec.get('montant',0))))
            rows = rows_to_list(conn.execute("SELECT * FROM caisse WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        return jsonify({'ok': True, 'data': rows})
    uid = current_user_id()
    with get_db() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM caisse WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify(rows)

@app.route('/api/caisse/<int:row_id>', methods=['DELETE'])
@login_required
def caisse_delete(row_id):
    uid = current_user_id()
    with get_db() as conn:
        conn.execute("DELETE FROM caisse WHERE id=? AND user_id=?", (row_id, uid))
    return jsonify({'ok': True})

@app.route('/api/budget', methods=['GET', 'POST'])
@login_required
def budget():
    if request.method == 'POST':
        uid = current_user_id()
        rec = request.json
        with get_db() as conn:
            conn.execute("""
                INSERT INTO budget (user_id, mois, categorie, prevu, description)
                VALUES (?, ?, ?, ?, ?)
            """, (uid, rec.get('mois',''), rec.get('categorie',''),
                  float(rec.get('prevu',0)), rec.get('description','')))
            rows = rows_to_list(conn.execute("SELECT * FROM budget WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        return jsonify({'ok': True, 'data': rows})
    uid = current_user_id()
    with get_db() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM budget WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify(rows)

@app.route('/api/budget/<int:row_id>', methods=['DELETE'])
@login_required
def budget_delete(row_id):
    return crud_delete_generic('budget', row_id)

# ── STOCK ──────────────────────────────────────────────────────────────────

@app.route('/api/stock', methods=['GET', 'POST'])
@login_required
def stock():
    if request.method == 'POST':
        uid = current_user_id()
        rec = request.json
        nom = (rec.get('nom') or '').strip()
        qte = float(rec.get('quantite', 0))
        cout = float(rec.get('cout_unitaire', 0))

        with get_db() as conn:
            existing = conn.execute(
                "SELECT id, quantite FROM stock WHERE user_id=? AND LOWER(nom)=LOWER(?)",
                (uid, nom)
            ).fetchone()

            if existing:
                new_qte = float(existing['quantite']) + qte
                conn.execute("UPDATE stock SET quantite=?, cout_unitaire=? WHERE id=?",
                             (new_qte, cout, existing['id']))
                conn.execute("""
                    INSERT INTO stock_mouvements (stock_id, date, type, quantite, montant)
                    VALUES (?, ?, 'réappro', ?, ?)
                """, (existing['id'], rec.get('date_entree',''), qte, qte*cout))
            else:
                conn.execute("""
                    INSERT INTO stock (user_id, nom, categorie, quantite, cout_unitaire, fournisseur, date_entree)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (uid, nom, rec.get('categorie',''), qte, cout,
                      rec.get('fournisseur',''), rec.get('date_entree','')))
                new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.execute("""
                    INSERT INTO stock_mouvements (stock_id, date, type, quantite, montant)
                    VALUES (?, ?, 'entrée initiale', ?, ?)
                """, (new_id, rec.get('date_entree',''), qte, qte*cout))

            stock_rows = rows_to_list(conn.execute("SELECT * FROM stock WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
        return jsonify({'ok': True, 'data': stock_rows})

    uid = current_user_id()
    with get_db() as conn:
        rows = rows_to_list(conn.execute("SELECT * FROM stock WHERE user_id=? ORDER BY created_at", (uid,)).fetchall())
    return jsonify(rows)

@app.route('/api/stock/<int:row_id>', methods=['DELETE'])
@login_required
def stock_delete(row_id):
    uid = current_user_id()
    with get_db() as conn:
        conn.execute("DELETE FROM stock WHERE id=? AND user_id=?", (row_id, uid))
    return jsonify({'ok': True})

@app.route('/api/stock/<int:row_id>/adjust', methods=['POST'])
@login_required
def stock_adjust(row_id):
    uid = current_user_id()
    qty = float(request.json.get('quantite', 0))
    with get_db() as conn:
        item = conn.execute("SELECT * FROM stock WHERE id=? AND user_id=?", (row_id, uid)).fetchone()
        if not item:
            return jsonify({'ok': False, 'error': 'Article introuvable'}), 404
        new_qte = float(item['quantite']) + qty
        conn.execute("UPDATE stock SET quantite=? WHERE id=?", (new_qte, row_id))
        conn.execute("""
            INSERT INTO stock_mouvements (stock_id, date, type, quantite, montant)
            VALUES (?, ?, 'ajustement', ?, ?)
        """, (row_id, datetime.date.today().strftime('%d/%m/%Y'), qty,
              qty * float(item['cout_unitaire'])))
    return jsonify({'ok': True})

# ── ANALYTICS ──────────────────────────────────────────────────────────────

@app.route('/api/analytics')
@login_required
def analytics():
    uid = current_user_id()
    with get_db() as conn:
        services_rows = rows_to_list(conn.execute("SELECT * FROM services WHERE user_id=?", (uid,)).fetchall())
        biens_rows    = rows_to_list(conn.execute("SELECT * FROM biens WHERE user_id=?", (uid,)).fetchall())
        sorties_rows  = rows_to_list(conn.execute("SELECT * FROM sorties WHERE user_id=?", (uid,)).fetchall())
        caisse_rows   = rows_to_list(conn.execute("SELECT * FROM caisse WHERE user_id=?", (uid,)).fetchall())
        budget_rows   = rows_to_list(conn.execute("SELECT * FROM budget WHERE user_id=?", (uid,)).fetchall())
        stock_rows    = rows_to_list(conn.execute("SELECT * FROM stock WHERE user_id=?", (uid,)).fetchall())

    svc   = sum(float(r.get('montant',0)) for r in services_rows)
    biens = sum(float(r.get('montant',0)) for r in biens_rows)
    sort  = sum(float(r.get('montant',0)) for r in sorties_rows)
    stock_val = sum(float(i.get('quantite',0)) * float(i.get('cout_unitaire',0)) for i in stock_rows)
    entrees = svc + biens

    months_set = set()
    for key, rows in [('services', services_rows), ('biens', biens_rows), ('sorties', sorties_rows)]:
        for r in rows:
            mk = get_month_key(r.get('date', ''))
            if mk != '0000-00':
                months_set.add(mk)

    sorted_months = sorted(months_set)[-12:]

    def monthly_totals(records):
        result = defaultdict(float)
        for r in records:
            mk = get_month_key(r.get('date', ''))
            result[mk] += float(r.get('montant', 0))
        return result

    mc_svc  = monthly_totals(services_rows)
    mc_bien = monthly_totals(biens_rows)
    mc_sort = monthly_totals(sorties_rows)

    monthly = []
    for mk in sorted_months:
        try:
            label = datetime.datetime.strptime(mk, '%Y-%m').strftime('%b %Y')
        except ValueError:
            label = mk
        e = mc_svc.get(mk, 0) + mc_bien.get(mk, 0)
        s = mc_sort.get(mk, 0)
        monthly.append({'mois': mk, 'label': label, 'entrees': e, 'sorties': s, 'net': e-s})

    entrees_c = sum(float(r.get('montant',0)) for r in caisse_rows if r.get('type') == 'entrée')
    sorties_c = sum(float(r.get('montant',0)) for r in caisse_rows if r.get('type') == 'sortie')

    reel_map = defaultdict(float)
    for rec in sorties_rows:
        mk = get_month_key(rec.get('date',''))
        try:
            d = datetime.datetime.strptime(mk, '%Y-%m')
            mois_lbl = d.strftime('%m/%Y')
        except ValueError:
            mois_lbl = mk
        cat = (rec.get('categorie','') or 'Autres').strip()
        reel_map[(mois_lbl, cat)] += float(rec.get('montant',0))

    bgt_rows_out = []
    for bgt in budget_rows:
        mois = bgt.get('mois','')
        cat  = bgt.get('categorie','')
        prev = float(bgt.get('prevu', 0))
        reel = reel_map.get((mois, cat), 0.0)
        ecart = reel - prev
        taux  = (reel / prev * 100) if prev > 0 else 0.0
        bgt_rows_out.append({'id': bgt['id'], 'mois': mois, 'categorie': cat, 'prevu': prev,
                              'reel': reel, 'ecart': ecart, 'taux': round(taux, 1)})

    return jsonify({
        'kpis': {
            'services': svc, 'biens': biens, 'sorties': sort,
            'stock': stock_val, 'entrees': entrees, 'solde': entrees - sort
        },
        'monthly': monthly,
        'caisse': {'entrees': entrees_c, 'sorties': sorties_c, 'solde': entrees_c - sorties_c},
        'budget_rows': bgt_rows_out,
        'low_stock': [i for i in stock_rows if float(i.get('quantite',0)) <= 10],
    })

# ══════════════════════════════════════════════════════════════════════════════
# EXPORT PDF (identique à v1, adapté pour multi-user)
# ══════════════════════════════════════════════════════════════════════════════

def get_data_for_pdf():
    uid = current_user_id()
    with get_db() as conn:
        services = rows_to_list(conn.execute("SELECT * FROM services WHERE user_id=?", (uid,)).fetchall())
        biens    = rows_to_list(conn.execute("SELECT * FROM biens WHERE user_id=?", (uid,)).fetchall())
        sorties  = rows_to_list(conn.execute("SELECT * FROM sorties WHERE user_id=?", (uid,)).fetchall())
        stock    = rows_to_list(conn.execute("SELECT * FROM stock WHERE user_id=?", (uid,)).fetchall())
        entreprise = row_to_dict(conn.execute("SELECT * FROM entreprise WHERE user_id=?", (uid,)).fetchone())
    if not entreprise:
        entreprise = {'nom': 'Mon Entreprise', 'adresse': '', 'telephone': '', 'email': '', 'nif': ''}
    return {'services': services, 'biens': biens, 'sorties': sorties,
            'stock': stock, 'entreprise': entreprise}

def build_pdf_rapport(data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm,
                             leftMargin=2*cm, rightMargin=2*cm)
    VERT  = colors.HexColor('#1A6B3C')
    BLEU  = colors.HexColor('#154360')
    ROUGE = colors.HexColor('#922B21')
    OR    = colors.HexColor('#B7770D')
    VIOLET= colors.HexColor('#5B2C8D')
    GRIS  = colors.HexColor('#F0F3F8')
    GRIS2 = colors.HexColor('#D8DCE5')
    NOIR  = colors.HexColor('#1C2833')

    styles = getSampleStyleSheet()
    s_title  = ParagraphStyle('t',  parent=styles['Normal'], fontSize=22, textColor=BLEU,
                               fontName='Helvetica-Bold', alignment=TA_LEFT, spaceAfter=4)
    s_h2     = ParagraphStyle('h2', parent=styles['Normal'], fontSize=13, textColor=BLEU,
                               fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6)
    s_normal = ParagraphStyle('n',  parent=styles['Normal'], fontSize=9, fontName='Helvetica', textColor=NOIR)
    s_bold   = ParagraphStyle('b',  parent=styles['Normal'], fontSize=9, fontName='Helvetica-Bold', textColor=NOIR)
    s_right  = ParagraphStyle('r',  parent=styles['Normal'], fontSize=9, fontName='Helvetica', textColor=NOIR, alignment=TA_RIGHT)
    s_center = ParagraphStyle('c',  parent=styles['Normal'], fontSize=9, fontName='Helvetica', textColor=NOIR, alignment=TA_CENTER)
    s_sub    = ParagraphStyle('s',  parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#717D86'), fontName='Helvetica')

    ent = data.get('entreprise', {})
    now = datetime.datetime.now()
    story = []

    hdr_data = [[
        Paragraph(f"<b>{ent.get('nom','Mon Entreprise')}</b>", s_title),
        Paragraph(f"<b>RAPPORT FINANCIER</b><br/>Généré le {now.strftime('%d/%m/%Y à %H:%M')}",
                  ParagraphStyle('rh', parent=styles['Normal'], fontSize=11, textColor=BLEU,
                                 fontName='Helvetica-Bold', alignment=TA_RIGHT))
    ]]
    hdr_tbl = Table(hdr_data, colWidths=[10*cm, 7.7*cm])
    hdr_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'BOTTOM'),('BOTTOMPADDING',(0,0),(0,-1),20)]))
    story.append(hdr_tbl)

    infos = []
    for k, lbl in [('adresse','Adresse'),('telephone','Tél'),('email','Email'),('nif','NIF')]:
        v = (ent.get(k) or '').strip()
        if v: infos.append(f'{lbl} : {v}')
    if infos: story.append(Paragraph('  |  '.join(infos), s_sub))
    story.append(HRFlowable(width='100%', thickness=2, color=BLEU, spaceAfter=12, spaceBefore=8))

    svc  = sum(float(r.get('montant',0)) for r in data.get('services',[]))
    bien = sum(float(r.get('montant',0)) for r in data.get('biens',[]))
    sort = sum(float(r.get('montant',0)) for r in data.get('sorties',[]))
    entrees = svc + bien
    solde   = entrees - sort
    stock_val = sum(float(i.get('quantite',0))*float(i.get('cout_unitaire',0))
                    for i in data.get('stock',[]))

    story.append(Paragraph('BILAN GLOBAL', s_h2))
    bilan_rows = [
        ['', 'LIBELLÉ', 'MONTANT (BIF)'],
        ['ENTRÉES', 'Services Rendus', f'{svc:,.0f}'],
        ['', 'Biens Vendus', f'{bien:,.0f}'],
        ['', 'Total Entrées', f'{entrees:,.0f}'],
        ['SORTIES', 'Dépenses & Charges', f'{sort:,.0f}'],
        ['STOCK', 'Valeur totale stock', f'{stock_val:,.0f}'],
        ['RÉSULTAT', 'Bénéfice / Perte NET', f"{'+' if solde>=0 else ''}{solde:,.0f}"],
    ]
    bilan_tbl = Table(bilan_rows, colWidths=[3.5*cm, 9*cm, 5.2*cm])
    bilan_tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BLEU),('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),9),
        ('ALIGN',(2,0),(2,-1),'RIGHT'),('GRID',(0,0),(-1,-1),0.4,GRIS2),
        ('BACKGROUND',(0,3),(-1,3),colors.HexColor('#D0EBD9')),
        ('FONTNAME',(0,3),(-1,3),'Helvetica-Bold'),
        ('BACKGROUND',(0,6),(-1,6),
            colors.HexColor('#D0EBD9') if solde>=0 else colors.HexColor('#FDECEA')),
        ('FONTNAME',(0,6),(-1,6),'Helvetica-Bold'),
        ('TEXTCOLOR',(2,6),(2,6), VERT if solde>=0 else ROUGE),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(bilan_tbl)
    story.append(Spacer(1,14))

    story.append(HRFlowable(width='100%', thickness=0.5, color=GRIS2, spaceAfter=8))
    story.append(Paragraph('LIVRE JOURNAL — HISTORIQUE DES MOUVEMENTS', s_h2))

    all_recs = []
    for key, label, side in [('services','Services Rendus','credit'),
                               ('biens','Biens Vendus','credit'),
                               ('sorties','Dépenses','debit')]:
        for rec in data.get(key,[]):
            all_recs.append((label, side, rec))
    all_recs.sort(key=lambda x: (parse_date(x[2].get('date','')) or datetime.date.min))

    hist_rows = [[
        Paragraph('<b>N°</b>', s_center), Paragraph('<b>Date</b>', s_center),
        Paragraph('<b>Type</b>', s_center), Paragraph('<b>Description</b>', s_bold),
        Paragraph('<b>Réf./Client</b>', s_normal),
        Paragraph('<b>DÉBIT (BIF)</b>', s_right), Paragraph('<b>CRÉDIT (BIF)</b>', s_right),
    ]]
    td = tc = 0.0
    for i, (label, side, rec) in enumerate(all_recs, 1):
        m = float(rec.get('montant',0))
        if side=='debit': deb,cre=f'{m:,.0f}',''; td+=m
        else: deb,cre='',f'{m:,.0f}'; tc+=m
        hist_rows.append([
            Paragraph(str(i),s_center), Paragraph(rec.get('date',''),s_center),
            Paragraph(label[:14],s_center),
            Paragraph((rec.get('description','') or '')[:40],s_normal),
            Paragraph((rec.get('client','') or '')[:22],s_normal),
            Paragraph(deb,s_right), Paragraph(cre,s_right),
        ])
    net = tc - td
    s_tot = ParagraphStyle('st', parent=styles['Normal'], fontSize=9, fontName='Helvetica-Bold', alignment=TA_RIGHT)
    hist_rows.append(['','','',Paragraph('<b>TOTAUX</b>',s_bold),'',
                      Paragraph(f'<b>{td:,.0f}</b>',s_tot), Paragraph(f'<b>{tc:,.0f}</b>',s_tot)])
    hist_rows.append(['','','',Paragraph('<b>SOLDE NET</b>',s_bold),'','',
                      Paragraph(f'<b>{net:,.0f}</b>',
                                ParagraphStyle('sn',parent=styles['Normal'],fontSize=9,
                                               fontName='Helvetica-Bold',alignment=TA_RIGHT,
                                               textColor=VERT if net>=0 else ROUGE))])
    hist_tbl = Table(hist_rows, colWidths=[1.2*cm,2.2*cm,2.8*cm,5.5*cm,3.3*cm,2.8*cm,2.8*cm])
    n = len(hist_rows)
    ts = [
        ('BACKGROUND',(0,0),(-1,0),BLEU),('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTSIZE',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),('LEFTPADDING',(0,0),(-1,-1),5),
        ('RIGHTPADDING',(0,0),(-1,-1),5),('GRID',(0,0),(-1,-2),0.3,GRIS2),
        ('LINEABOVE',(0,n-2),(-1,n-2),1.2,BLEU),
        ('BACKGROUND',(0,n-2),(-1,n-2),GRIS),
        ('BACKGROUND',(0,n-1),(-1,n-1),
            colors.HexColor('#D0EBD9') if net>=0 else colors.HexColor('#FDECEA')),
    ]
    for ri in range(1,n-2):
        if ri%2==0: ts.append(('BACKGROUND',(0,ri),(-1,ri),GRIS))
    hist_tbl.setStyle(TableStyle(ts))
    story.append(hist_tbl)
    story.append(Spacer(1,14))

    stock_items = data.get('stock',[])
    if stock_items:
        story.append(PageBreak())
        story.append(Paragraph('ÉTAT DU STOCK', s_h2))
        stk_hdr = [Paragraph(f'<b>{h}</b>',s_bold) for h in
                   ['Article','Catégorie','Qté','Coût unit. (BIF)','Valeur tot. (BIF)','Statut']]
        stk_rows = [stk_hdr]
        for item in stock_items:
            qte=float(item.get('quantite',0)); cout=float(item.get('cout_unitaire',0))
            statut = 'VIDE' if qte<=0 else ('FAIBLE' if qte<=10 else 'OK')
            stk_rows.append([
                Paragraph(item.get('nom',''),s_normal),
                Paragraph(item.get('categorie',''),s_normal),
                Paragraph(f'{qte:.0f}',s_center),
                Paragraph(f'{cout:,.0f}',s_right),
                Paragraph(f'{qte*cout:,.0f}',s_right),
                Paragraph(statut,s_center),
            ])
        stk_tbl = Table(stk_rows, colWidths=[4.5*cm,3*cm,2.5*cm,3.5*cm,3.5*cm,2.2*cm])
        stk_tbl.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),VIOLET),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('FONTSIZE',(0,0),(-1,-1),8),('GRID',(0,0),(-1,-1),0.3,GRIS2),
            ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ]))
        story.append(stk_tbl)

    story.append(Spacer(1,100))
    story.append(HRFlowable(width='100%',thickness=1,color=BLEU,spaceAfter=6))
    story.append(Paragraph(
        f"Document généré automatiquement — Classeur de Gestion v2.0 Web — {now.strftime('%d/%m/%Y à %H:%M')}",
        ParagraphStyle('ft',parent=styles['Normal'],fontSize=7,
                       textColor=colors.HexColor('#717D86'),
                       fontName='Helvetica',alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer

@app.route('/api/pdf/rapport')
@login_required
def pdf_rapport():
    data = get_data_for_pdf()
    buf = build_pdf_rapport(data)
    nom = data.get('entreprise',{}).get('nom','rapport').replace(' ','_')
    today = datetime.date.today().strftime('%Y%m%d')
    return send_file(buf, as_attachment=True,
                     download_name=f'rapport_{nom}_{today}.pdf',
                     mimetype='application/pdf')

@app.route('/api/pdf/facture')
@login_required
def pdf_facture():
    data = get_data_for_pdf()
    buffer = io.BytesIO()
    all_recs = data.get('services',[]) + data.get('biens',[])
    all_recs.sort(key=lambda r: (parse_date(r.get('date','')) or datetime.date.min))

    doc = SimpleDocTemplate(buffer, pagesize=A4,
                             topMargin=2*cm,bottomMargin=2*cm,
                             leftMargin=2*cm,rightMargin=2*cm)
    BLEU=colors.HexColor('#154360'); VERT=colors.HexColor('#1A6B3C')
    ROUGE=colors.HexColor('#922B21'); GRIS=colors.HexColor('#F0F3F8')
    GRIS2=colors.HexColor('#D8DCE5')
    styles=getSampleStyleSheet()
    s_n=ParagraphStyle('n',parent=styles['Normal'],fontSize=9,fontName='Helvetica')
    s_r=ParagraphStyle('r',parent=styles['Normal'],fontSize=9,fontName='Helvetica',alignment=TA_RIGHT)
    s_c=ParagraphStyle('c',parent=styles['Normal'],fontSize=9,fontName='Helvetica',alignment=TA_CENTER)
    s_b=ParagraphStyle('b',parent=styles['Normal'],fontSize=9,fontName='Helvetica-Bold')

    ent=data.get('entreprise',{}); now=datetime.datetime.now(); story=[]
    story.append(Paragraph(f"<b>{ent.get('nom','Mon Entreprise')}</b>",
                            ParagraphStyle('ht',parent=styles['Normal'],fontSize=20,
                                           textColor=BLEU,fontName='Helvetica-Bold')))
    story.append(Spacer(1,4))
    story.append(HRFlowable(width='100%',thickness=2,color=BLEU,spaceBefore=8,spaceAfter=14))
    info_data=[[
        Paragraph('<b>FACTURE</b>',ParagraphStyle('ti',parent=styles['Normal'],fontSize=18,
                  fontName='Helvetica-Bold',textColor=BLEU)),
        Paragraph(f"N° : <b>{len(all_recs):04d}</b><br/>Date : {now.strftime('%d/%m/%Y')}",
                  ParagraphStyle('di',parent=styles['Normal'],fontSize=10,alignment=TA_RIGHT))
    ]]
    info_tbl=Table(info_data,colWidths=[9*cm,8.7*cm])
    info_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(info_tbl); story.append(Spacer(1,16))

    hdr=[Paragraph('<b>N°</b>',s_c),Paragraph('<b>Description</b>',s_b),
         Paragraph('<b>Client</b>',s_b),Paragraph('<b>Catégorie</b>',s_b),
         Paragraph('<b>Date</b>',s_c),Paragraph('<b>Montant (BIF)</b>',s_r)]
    rows=[hdr]; total=0.0
    for i,rec in enumerate(all_recs,1):
        m=float(rec.get('montant',0)); total+=m
        rows.append([Paragraph(str(i),s_c),
                     Paragraph((rec.get('description','') or '')[:45],s_n),
                     Paragraph((rec.get('client','') or '')[:30],s_n),
                     Paragraph((rec.get('categorie','') or '')[:25],s_n),
                     Paragraph(rec.get('date',''),s_c),
                     Paragraph(f'{m:,.0f}',s_r)])
    rows.append(['','','','',Paragraph('<b>TOTAL</b>',s_b),
                 Paragraph(f'<b>{total:,.0f}</b>',
                            ParagraphStyle('tot',parent=styles['Normal'],fontSize=11,
                                           fontName='Helvetica-Bold',textColor=VERT,alignment=TA_RIGHT))])
    tbl=Table(rows,colWidths=[1.2*cm,5.5*cm,3.5*cm,2.8*cm,2.5*cm,3.2*cm])
    nr=len(rows)
    tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BLEU),('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTSIZE',(0,0),(-1,-1),8),('GRID',(0,0),(-1,-2),0.3,GRIS2),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LINEABOVE',(0,nr-1),(-1,nr-1),1.5,BLEU),
        ('BACKGROUND',(0,nr-1),(-1,nr-1),colors.HexColor('#E3F5EC')),
    ]+[('BACKGROUND',(0,i),(-1,i),GRIS) for i in range(1,nr-1) if i%2==0]))
    story.append(tbl)
    doc.build(story)
    buffer.seek(0)
    nom=ent.get('nom','facture').replace(' ','_')
    today=datetime.date.today().strftime('%Y%m%d')
    return send_file(buffer,as_attachment=True,
                     download_name=f'facture_{nom}_{today}.pdf',
                     mimetype='application/pdf')

# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
