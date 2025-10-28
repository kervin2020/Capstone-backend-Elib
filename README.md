# eLib — Modern Library Management System (LMS)

##  Aperçu

Application full‑stack de gestion de bibliothèque (emprunt physique/numérique, lecture en ligne, avis, administration). Backend Flask + SQLAlchemy + JWT, Flasgger. Frontend React + Vite + Redux + Tailwind.

---

##  Architecture

- `backend/` — Flask API (SQLAlchemy, JWT, CORS, Migrate, Bcrypt)
- `frontend/` — React (Vite, React Router, Redux Toolkit, Tailwind, PDF.js)

---

## Prérequis

- Python 3.12+
- Node.js 18+

---

## Installation

### Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PORT=5001 python app.py
```

**Notes:**
- Utiliser `python app.py` (pas `flask run`) pour éviter l'erreur d'import.
- DB SQLite par défaut: `instance/bibliotheque.db` (créée auto).

### Frontend

```bash
cd frontend
npm install
VITE_API_URL=http://localhost:5001 npm run dev
```

Ouvrir l'URL Vite affichée (ex: http://localhost:5179).

---

##  Variables d'environnement (Backend)

- `SECRET_KEY`, `JWT_SECRET_KEY` (défauts en dev)
- `SQLALCHEMY_DATABASE_URI` (défaut SQLite local)

---

##  Principales Routes API (extraits)

## Auth
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`

## Ebooks
- `GET /ebooks`
- `GET /ebooks/<id>`
- `POST/PUT/DELETE /ebooks` (admin)

## Prêts
- `POST /loans`
- `POST /loans/<loan_id>/return`
- `GET /my/loans`
- `GET /loans` (admin)

## Reviews
- `GET /ebooks/<ebook_id>/reviews`
- `POST /ebooks/<ebook_id>/reviews`

## Admin Users
- `GET /admin/users`
- `POST /admin/users/<id>/ban`
- `POST /admin/users/<id>/unban`

---

##  Modèles (simplifié)

- `User(id, username, email, password, is_admin, is_banned)`
- `Ebook(id, title, author, description, file_path, total_copies, available_copies, categories)`
- `Category(id, name)`
- `Loan(id, user_id, ebook_id, loan_date, due_date, is_returned)`
- `Review(id, user_id, ebook_id, rating, comment)`

---

## Frontend — Pages & Routes

- `/` Accueil
- `/ebooks` Liste
- `/ebooks/:id` Détail + avis
- `/profile` Profil + historique
- `/books/:id/read` Lecteur PDF.js
- `/admin` Tableau de bord (base)

---

##  UI/UX

- Tailwind CSS, navbar responsive avec hamburger (Lucide)
- Validations (react-hook-form), toasts (react-hot-toast)

---

## Tests

- Backend (pytest): voir `backend/tests/`
- Frontend (Vitest/RTL): `npm run test`

---

## Lancement rapide (deux terminaux)

# Terminal A — Backend

```bash
lsof -ti:5000,5001 | xargs -r kill -9
cd backend && source .venv/bin/activate
PORT=5001 python app.py
```

# Terminal B — Frontend

```bash
cd frontend
VITE_API_URL=http://localhost:5001 npm run dev
```

---

# Notes

- CORS ouverts en dev.
- Les opérations admin exigent un compte `is_admin=true`.
# Capstone-backend-Elib
