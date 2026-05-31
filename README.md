```markdown
# Secure Student Management System 🔐
Secure Flask web application with RBAC, 2FA, and CI/CD pipeline — built using DevSecOps principles.

## 👥 Team
| Member | Role |
|--------|------|
| Bikesh Ghimire | CI/CD Pipeline, GitHub Management & HTML Templates |
| Kabita Sharma | Backend, Authentication, RBAC & 2FA |
| Susmita Lamichhane | Security Testing & Remediation (ZAP, Bandit, pip-audit) |
| Trian Suleman | Audit Logging, Monitoring & Admin Panel |

## 🚀 Features
- Secure user registration and login
- Password hashing with bcrypt
- Two-Factor Authentication (2FA) via TOTP (Google/Microsoft Authenticator)
- Role-Based Access Control (RBAC) — Admin, Teacher, Student roles
- CSRF protection on all forms via Flask-WTF
- Session management with secure cookie flags
- Rate limiting on login (brute force protection)
- Audit logging for all important user actions
- Security headers via Flask-Talisman

## 🛠️ Tech Stack
- **Backend**: Python / Flask
- **Database**: SQLite (via SQLAlchemy)
- **Auth**: Flask-Login, PyOTP, bcrypt
- **Security**: Flask-Limiter, Flask-WTF, Flask-Talisman, RBAC

## ⚙️ Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/bks-ghi/ICT932-SecureWebApp.git
cd ICT932-SecureWebApp
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
cd src
python app.py
```
Visit http://127.0.0.1:5000

## 🔒 Security Features
| Feature | Implementation |
|---------|---------------|
| Password Hashing | bcrypt |
| 2FA | TOTP via PyOTP |
| RBAC | Admin, Teacher, Student roles |
| CSRF Protection | Flask-WTF |
| Session Management | Flask-Login + Secure Cookies |
| Rate Limiting | Flask-Limiter |
| Security Headers | Flask-Talisman |
| SAST | Bandit |
| Dependency Scanning | pip-audit |
| DAST | OWASP ZAP |

## 📁 Project Structure
```
ICT932-SecureWebApp/
├── src/          # Flask source code
├── tests/        # Unit tests
├── docs/         # ZAP reports, Bandit report, screenshots
├── .github/workflows/  # CI/CD pipeline
└── README.md
```

## 🧪 Running Tests
```bash
python -m pytest tests/ -v
```
```
