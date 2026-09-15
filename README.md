# 🔐 Salyzer

> A full-stack web application built with **Python (Django)** featuring secure authentication, real-time analytics dashboard, audit logging, and user management.

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-4.x-green?logo=django)](https://www.djangoproject.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-lightblue?logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 📌 Features

- 🔑 **Secure Authentication** — Login, logout, session management with rate limiting (blocks brute-force after 5 failed attempts)
- 📊 **Analytics Dashboard** — Weekly login trends, activity metrics, and login streaks
- 🗂️ **Audit Logging** — Tracks every user action (login, logout, profile update, password change) with IP address & timestamp
- 🛡️ **Login History** — Records device info, IP address, session duration, and login status
- 👤 **User Profile Management** — Edit personal info, bio, profile picture, and social links
- 🔒 **Security Settings** — Password change with real-time strength checker (0–100 score), 2FA toggle
- ⚙️ **User Settings** — Theme preference (Light/Dark/Auto), notification controls, privacy settings
- 🚨 **Custom Error Pages** — Handles 400, 403, 404, 500 errors gracefully
- 🔔 **Django Signals** — Auto-creates UserProfile & UserSettings on new user registration

---

## 🛠️ Tech Stack

| Layer      | Technology         |
|------------|--------------------|
| Backend    | Python, Django     |
| Database   | SQLite (Django ORM)|
| Frontend   | HTML, CSS, JavaScript |
| Auth       | Django Auth + Custom Security |
| Version Control | Git & GitHub |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.x
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Sarthak-Singhal007/Salyzer.git
cd Salyzer

# 2. Create and activate virtual environment
python -m venv env
env\Scripts\activate        # Windows
source env/bin/activate     # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Apply migrations
python manage.py migrate

# 5. Create superuser (admin)
python manage.py createsuperuser

# 6. Run the server
python manage.py runserver
```

Then open 👉 `http://127.0.0.1:8000` in your browser.

---

## 📁 Project Structure

```
Salyzer/
├── mainApp/
│   ├── models.py        # UserProfile, LoginHistory, AuditLog, UserSettings
│   ├── views.py         # All view logic & security functions
│   ├── urls.py          # App-level URL routing
│   ├── admin.py         # Django admin configuration
│   ├── templates/       # HTML templates (login, dashboard, profile, etc.)
│   └── static/          # CSS & static assets
├── myDjangoApp/
│   ├── settings.py      # Project settings
│   └── urls.py          # Project-level URL routing
├── manage.py
└── README.md
```

---

## 📸 Pages

| Page        | Description                              |
|-------------|------------------------------------------|
| Login       | Secure login with rate limiting          |
| Dashboard   | Analytics, login stats, recent activity  |
| Profile     | Edit personal info & profile picture     |
| Security    | Login history & audit logs               |
| Activity    | Daily/Weekly/Monthly activity overview   |

---

## 🔐 Security Highlights

- ✅ Rate limiting on login (5 attempts/min per IP)
- ✅ Password strength validation (0–100 score)
- ✅ Password complexity enforcement (uppercase, digits, special chars)
- ✅ Full audit trail for all user actions
- ✅ Session management with `update_session_auth_hash`
- ✅ UUID-based profile picture naming to prevent conflicts

---

## 👨‍💻 Author

**Sarthak Singhal**
- GitHub: [@Sarthak-Singhal007](https://github.com/Sarthak-Singhal007)
- Email: sarthaksinghal676@gmail.com

---

## 📄 License

This project is licensed under the **MIT License**.
