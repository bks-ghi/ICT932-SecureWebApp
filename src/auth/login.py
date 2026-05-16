from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user
import logging

logger = logging.getLogger('secure_app')

def handle_login():
    from app import db
    from models import User
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_2fa_enabled:
                session['pre_2fa_user_id'] = user.id
                logger.info(f"Password OK for {username}, redirecting to 2FA")
                return redirect(url_for('verify_2fa'))
            login_user(user)
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        logger.warning(f"Failed login attempt for username: {username}")
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

def handle_register():
    from app import db
    from models import User
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        user = User(username=username, email=email, role='user')
        user.set_password(password)
        user.generate_totp_secret()
        user.is_2fa_enabled = True
        db.session.add(user)
        db.session.commit()
        logger.info(f"New user registered: {username}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

def handle_2fa():
    from models import User
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        token = request.form.get('token', '')
        if user.verify_totp(token):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            logger.info(f"2FA verified for {user.username}")
            return redirect(url_for('dashboard'))
        logger.warning(f"Failed 2FA attempt for user: {user.username}")
        flash('Invalid 2FA token. Try again.', 'error')
    return render_template('verify_2fa.html')