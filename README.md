# 📒 Classeur de Gestion Financière — Version Web 2.0
## Avec base de données SQLite et authentification multi-utilisateurs

---

## ✅ Nouveautés v2.0

- **Authentification** : inscription, connexion, déconnexion
- **Multi-utilisateurs** : chaque utilisateur a ses propres données isolées
- **Base de données SQLite** : remplacement du fichier JSON par une vraie BDD relationnelle
- **IDs stables** : les suppressions utilisent des IDs fixes (plus de bugs d'index)
- **Sécurité** : mots de passe hashés (SHA-256), sessions Flask sécurisées

---

## 🚀 Déploiement en ligne — Render.com

### Étape 1 — Préparer le code

1. Créez un compte sur [GitHub](https://github.com) (gratuit)
2. Créez un nouveau dépôt GitHub (ex: `classeur-gestion`)
3. Uploadez tous les fichiers de ce dossier dans le dépôt

### Étape 2 — Déployer sur Render

1. Allez sur [render.com](https://render.com) → créez un compte gratuit
2. Cliquez **"New +"** → **"Web Service"**
3. Connectez votre dépôt GitHub
4. Remplissez les champs :
   - **Name** : `classeur-gestion`
   - **Environment** : Python 3
   - **Build Command** : `pip install -r requirements.txt`
   - **Start Command** : `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2`
5. Variables d'environnement à ajouter :
   - `SECRET_KEY` = une longue chaîne aléatoire (ex: `mon-secret-super-long-2024`)
   - `DB_PATH` = `/data/classeur.db` (si vous ajoutez un disque persistant)
6. Cliquez **"Create Web Service"**

### Étape 3 — Disque persistant (IMPORTANT)

Sur Render plan gratuit, les fichiers sont effacés à chaque redémarrage.
Pour conserver vos données :

**Render Disk ($0.25/mois)**
- Dans votre service Render → **"Disks"** → **"Add Disk"**
- Mount Path : `/data`
- Ajoutez la variable d'environnement :
  - `DB_PATH` = `/data/classeur.db`

---

## 🖥️ Lancer en local

```bash
# 1. Ouvrir un terminal dans le dossier classeur-web-db/
# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application
python app.py

# 4. Ouvrir dans le navigateur
# → http://localhost:5000
# → Page de connexion / inscription
```

---

## 🏗️ Structure de la base de données

```
classeur.db (SQLite)
├── users           — Comptes utilisateurs (id, username, email, password_hash)
├── entreprise      — Infos entreprise par utilisateur
├── services        — Services rendus (lié à users.id)
├── biens           — Biens vendus (lié à users.id)
├── sorties         — Dépenses & charges (lié à users.id)
├── stock           — Articles en stock (lié à users.id)
├── stock_mouvements— Historique des mouvements de stock
├── caisse          — Mouvements de caisse (lié à users.id)
└── budget          — Lignes de budget (lié à users.id)
```

---

## 🔧 Structure des fichiers

```
classeur-web-db/
├── app.py                  ← Application Flask + BDD SQLite
├── requirements.txt        ← Dépendances Python
├── Procfile                ← Config serveur production
├── README.md               ← Ce fichier
├── classeur.db             ← BDD créée automatiquement au premier démarrage
└── templates/
    ├── auth.html           ← Page de connexion / inscription
    └── index.html          ← Interface principale
```

---

## 🔒 Sécurité

- Mots de passe hashés avec SHA-256 (jamais stockés en clair)
- Sessions sécurisées avec clé secrète Flask
- Toutes les routes API nécessitent une authentification
- Isolation complète des données par utilisateur (user_id dans chaque requête SQL)
- Pour un usage en production, envisagez bcrypt pour un hachage plus robuste

---

## ❓ Questions fréquentes

**Q: Peut-on migrer les données d'un fichier JSON existant ?**
R: Oui. Les données JSON peuvent être importées via un script Python
   utilisant `sqlite3` pour insérer les enregistrements dans la BDD.

**Q: Peut-on utiliser PostgreSQL en production ?**
R: Oui. Remplacez `sqlite3` par `psycopg2` et adaptez les requêtes SQL
   (les syntaxes sont très proches, surtout les placeholders `?` → `%s`).

**Q: L'application est-elle responsive (mobile) ?**
R: Oui, Bootstrap 5 assure la compatibilité mobile.
