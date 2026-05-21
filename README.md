# Secure Student Management System 🔐

Secure Flask web application with RBAC, 2FA, and CI/CD pipeline — built using DevSecOps principles.

## 👥 Team
| Member | Role |
|--------|------|
| Bikesh | CI/CD Pipeline & GitHub |
| Kabita | Backend + Authentication |
| Susmita | Security Testing |
| Trian | Logging & Monitoring |

## 🚀 Features
- Secure user registration and login
- Password hashing with bcrypt
- Two-Factor Authentication (2FA) via TOTP (Google/Microsoft Authenticator)
- Role-Based Access Control (RBAC) — user/admin roles
- Session management
- Rate limiting on login (brute force protection)

## 🛠️ Tech Stack
- **Backend**: Python / Flask
- **Database**: SQLite (via SQLAlchemy)
- **Auth**: Flask-Login, PyOTP, bcrypt
- **Security**: Flask-Limiter, RBAC

## ⚙️ Setup Instructions

### 1. Clone the repository
git clone https://github.com/bks-ghi/ICT932-SecureWebApp.git
cd ICT932-SecureWebApp

### 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

### 3. Install dependencies
pip install -r requirements.txt

### 4. Run the application
cd src
python app.py

Visit http://127.0.0.1:5000

## 🔒 Security Features
| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt |
| 2FA | TOTP via PyOTP |
| RBAC | Flask roles (user/admin) |
| Session Management | Flask-Login |
| Rate Limiting | Flask-Limiter |
| SAST | Bandit (Week 8) |
| DAST | OWASP ZAP (Week 8) |

## 📁 Project Structure
ICT932-SecureWebApp/
├── src/          # Source code
├── tests/        # Unit tests
├── docs/         # Documentation
├── ci-cd/        # Pipeline configs
└── README.md

## 🧪 Running Tests
python -m pytest tests/ -v
