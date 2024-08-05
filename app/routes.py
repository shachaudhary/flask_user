from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User
from app.forms import RegistrationForm
from app.forms import LoginForm, ForgotPasswordForm, ResetPasswordForm, ProfileForm
from werkzeug.security import generate_password_hash, check_password_hash
from app.utils import generate_verification_token, confirm_verification_token, send_verification_email
from app.utils import generate_reset_token, confirm_reset_token, send_reset_email

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        
        # Create a new user
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, is_verified=False)
        db.session.add(user)
        db.session.commit()
        
        # Generate verification token and link
        token = generate_verification_token(form.email.data)
        verification_link = url_for('main.verify_email', token=token, _external=True)
        
        # Send verification email
        response = send_verification_email(form.email.data, verification_link)
        
        if response.status_code == 200:
            flash('Your account has been created! Please check your email to verify your account.', 'success')
        else:
            flash('There was an issue sending the verification email.', 'danger')
        
        return redirect(url_for('main.index'))
    
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if user.is_verified: 
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('main.dashboard'))
            else:
                # Generate a new verification token and send email
                token = generate_verification_token(user.email)
                verification_link = url_for('main.verify_email', token=token, _external=True)
                send_verification_email(user.email, verification_link)
                flash('Check your Email for Verification', 'success')
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    
    return render_template('login.html', form=form)

@main.route('/verify/<token>')
def verify_email(token):
    email = confirm_verification_token(token)
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            if not user.is_verified:
                user.is_verified = True
                db.session.commit()
                return render_template('verify_result.html', status='verified')
            else:
                return render_template('verify_result.html', status='already_verified')
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('main.index'))
    else:
        return render_template('verify_result.html', status='expired')




@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@main.route('/resend_verification', methods=['POST'])
def resend_verification():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        verification_token = generate_verification_token(user.email)
        verification_link = url_for('main.verify_email', token=verification_token, _external=True)
        
        send_verification_email(user.email, verification_link)
        
        flash('A new verification email has been sent. Please check your inbox.', 'success')
    else:
        flash('User not found or already verified.', 'info')
    
    return redirect(url_for('main.index'))


@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            reset_link = url_for('main.reset_password', token=token, _external=True)
            send_reset_email(email, reset_link)
            flash('A password reset link has been sent to your email.', 'info')
            return redirect(url_for('main.index'))
        else:
            flash('No account with that email found.', 'warning')
    return render_template('forgot_password.html', form=form)

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash('The password reset link is invalid or has expired.', 'warning')
        return redirect(url_for('main.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated. You can now log in.', 'success')
            return redirect(url_for('main.login'))
    
    return render_template('reset_password.html', form=form, token=token)


@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.current_password.data):
            if form.new_password.data == form.confirm_new_password.data:
                hashed_password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
                current_user.password = hashed_password
                db.session.commit()
                flash('Your password has been updated successfully!', 'success')
            else:
                flash('New passwords do not match.', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('profile.html', form=form)







