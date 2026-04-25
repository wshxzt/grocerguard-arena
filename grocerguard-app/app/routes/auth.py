from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from app.models import db, User
from app import mail

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('products.index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('products.index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('products.index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            user = User(username=username, email=email, full_name=full_name)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Account created! Welcome to GrocerGuard.', 'success')
            return redirect(url_for('products.index'))
    return render_template('register.html')


def _token_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        # Always show the same message to avoid email enumeration
        flash('If that email is registered, a reset link has been sent.', 'info')
        if user:
            token = _token_serializer().dumps(email, salt='password-reset')
            base_url = current_app.config.get('APP_BASE_URL', request.host_url.rstrip('/'))
            reset_url = f"{base_url}{url_for('auth.reset_password', token=token)}"
            if not current_app.config.get('MAIL_USERNAME'):
                # Mail not configured — surface the reset link directly so it still works
                flash(
                    f'Email not configured. Use this link to reset your password (expires in 1 hour): '
                    f'<a href="{reset_url}">{reset_url}</a>',
                    'warning'
                )
                return redirect(url_for('auth.login'))
            try:
                msg = Message(
                    subject='GrocerGuard — Reset your password',
                    recipients=[email],
                    body=(
                        f"Hi {user.full_name or user.username},\n\n"
                        f"Click the link below to reset your password. "
                        f"This link expires in 1 hour.\n\n"
                        f"{reset_url}\n\n"
                        f"If you didn't request this, you can safely ignore this email.\n\n"
                        f"— GrocerGuard"
                    ),
                )
                mail.send(msg)
            except Exception as e:
                current_app.logger.error(f'Failed to send password reset email: {e}')
                flash(
                    f'Could not send email. Use this link to reset your password (expires in 1 hour): '
                    f'<a href="{reset_url}">{reset_url}</a>',
                    'warning'
                )
                return redirect(url_for('auth.login'))
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html')


@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = _token_serializer().loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash('The reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    except BadSignature:
        flash('Invalid reset link.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            user.set_password(password)
            db.session.commit()
            flash('Password updated. Please log in.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)


@auth.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('cart', None)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name', '').strip()
        current_user.shipping_address = request.form.get('shipping_address', '').strip()
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('auth.profile'))
    return render_template('profile.html')


@auth.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    user = current_user._get_current_object()
    db.session.delete(user)
    db.session.commit()
    logout_user()
    session.pop('cart', None)
    flash('Your account has been deleted.', 'info')
    return redirect(url_for('auth.login'))
