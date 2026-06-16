from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64

db = SQLAlchemy()


class User(db.Model):
    """User model with password hashing and 2FA support"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # 2FA
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, nullable=True)  # Comma-separated
    
    # Account security
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_password_change = db.Column(db.DateTime, nullable=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    sessions = db.relationship('UserSession', back_populates='user', cascade='all, delete-orphan')
    login_history = db.relationship('LoginHistory', back_populates='user', cascade='all, delete-orphan')
    
    def set_password(self, password: str) -> None:
        """Hash and set password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        self.last_password_change = datetime.utcnow()
    
    def verify_password(self, password: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def is_account_locked(self) -> bool:
        """Check if account is locked due to failed login attempts"""
        if self.locked_until:
            if datetime.utcnow() < self.locked_until:
                return True
            else:
                # Unlock account
                self.locked_until = None
                self.failed_login_attempts = 0
        return False
    
    def increment_failed_login(self, lockout_duration: int) -> None:
        """Increment failed login attempts and lock account if needed"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 attempts
            self.locked_until = datetime.utcnow() + timedelta(seconds=lockout_duration)
    
    def reset_failed_login(self) -> None:
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
    
    def setup_totp(self) -> tuple:
        """
        Setup TOTP for 2FA
        Returns: (secret, qr_code_image_base64)
        """
        secret = pyotp.random_base32()
        self.totp_secret = secret
        
        # Generate QR code
        totp = pyotp.TOTP(secret)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp.provisioning_uri(name=self.email, issuer_name='SecureLogin'))
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        qr_code_base64 = base64.b64encode(img_io.getvalue()).decode()
        
        return secret, qr_code_base64
    
    def verify_totp(self, token: str) -> bool:
        """Verify TOTP token"""
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        # Allow 30 second window on each side for clock skew
        return totp.verify(token, valid_window=1)
    
    def enable_totp(self, backup_codes: list) -> None:
        """Enable TOTP and store backup codes"""
        self.totp_enabled = True
        self.backup_codes = ','.join(backup_codes)
    
    def disable_totp(self) -> None:
        """Disable TOTP"""
        self.totp_secret = None
        self.totp_enabled = False
        self.backup_codes = None
    
    def use_backup_code(self, code: str) -> bool:
        """Use a backup code and remove it from the list"""
        if not self.backup_codes:
            return False
        
        codes = self.backup_codes.split(',')
        if code in codes:
            codes.remove(code)
            self.backup_codes = ','.join(codes)
            return True
        return False
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'totp_enabled': self.totp_enabled,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }
        
        if include_sensitive:
            data['password_hash'] = self.password_hash
        
        return data


class UserSession(db.Model):
    """User session management"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 compatible
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', back_populates='sessions')
    
    def is_valid(self) -> bool:
        """Check if session is still valid"""
        return (
            self.is_active and
            datetime.utcnow() < self.expires_at
        )
    
    def refresh_activity(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()


class LoginHistory(db.Model):
    """Track login attempts for audit purposes"""
    __tablename__ = 'login_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    success = db.Column(db.Boolean, default=False)
    reason = db.Column(db.String(255), nullable=True)  # e.g., "invalid_password", "account_locked"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', back_populates='login_history')
