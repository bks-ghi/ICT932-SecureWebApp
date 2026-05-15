from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CHANGE_THIS_IN_PRODUCTION'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from logger import setup_logger
logger = setup_logger()

from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user.is_authenticated else 'login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    from auth.login import handle_login
    return handle_login()

@app.route('/register', methods=['GET', 'POST'])
def register():
    from auth.login import handle_register
    return handle_register()

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    from auth.login import handle_2fa
    return handle_2fa()

@app.route('/dashboard')
@login_required
def dashboard():
    logger.info(f"User {current_user.username} accessed dashboard")
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'error')
        logger.warning(f"Unauthorized admin access by {current_user.username}")
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
    app.run(debug=True)