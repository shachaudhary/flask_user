# utils.py or similar
from itsdangerous import URLSafeTimedSerializer
import requests
from flask import current_app as app

def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception:
        return None
    return email

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception:
        return None
    return email


def send_verification_email(email, verification_link):
    api_key = app.config['MAILGUN_API_KEY']
    domain = app.config['MAILGUN_DOMAIN']
    
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; color: #333;">
        <div style="background-color: #007bff; color: #fff; text-align: center; padding: 20px;">
            <h1 style="margin: 0;">Email Verification</h1>
        </div>
        <div style="padding: 20px; text-align: center;">
            <p>Please verify your email address by clicking the button below:</p>
            <p>
                <a href="{verification_link}" style="display: inline-block; padding: 15px 30px; font-size: 16px; color: #fff; background-color: #007bff; text-decoration: none; border-radius: 5px;">Verify Your Email</a>
            </p>
            <p>If you did not create an account, no further action is required.</p>
            <p>Thank you!</p>
        </div>
    </body>
    </html>
    """
    
    response = requests.post(
        f'https://api.mailgun.net/v3/{domain}/messages',
        auth=('api', api_key),
        data={
            'from': 'no-reply@your-domain.com',
            'to': email,
            'subject': 'Email Verification',
            'html': html_content
        }
    )
    return response


def send_reset_email(email, reset_link):
    api_key = app.config['MAILGUN_API_KEY']
    domain = app.config['MAILGUN_DOMAIN']
    
    response = requests.post(
        f'https://api.mailgun.net/v3/{domain}/messages',
        auth=('api', api_key),
        data={
            'from': 'no-reply@your-domain.com',
            'to': email,
            'subject': 'Password Reset Request',
            'html': f'''
            <html>
                <body>
                    <div style="background-color: #007bff; color: #ffffff; text-align: center; padding: 20px;">
                        <h1>Password Reset</h1>
                    </div>
                    <div style="text-align: center; padding: 20px;">
                        <p>To reset your password, click the following link:</p>
                        <a href="{reset_link}" style="background-color: #007bff; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
                    </div>
                </body>
            </html>
            '''
        }
    )
    return response
