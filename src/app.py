from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_required, current_user, logout_user
from models import db, User
from logger import setup_logger
from auth.login import handle_login, handle_register, handle_2fa
import os

logger = setup_logger()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ict932-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secureapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    return handle_login()

@app.route('/register', methods=['GET', 'POST'])
def register():
    return handle_register()

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    return handle_2fa()

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        logger.warning(f"Unauthorized admin access by username: {current_user.username}")
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info("Secure app started")
    app.run(debug=True)