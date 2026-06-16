from models import db, User, UserSession, LoginHistory
from validators import InputValidator, PasswordValidator, ValidationError
from datetime import datetime, timedelta
from flask import current_app
import secrets
import string


class AuthService:
    """Handle authentication operations"""
    
    @staticmethod
    def register_user(username: str, email: str, password: str, password_confirm: str) -> User:
        """
        Register a new user
        
        Args:
            username: User's username
            email: User's email
            password: User's password
            password_confirm: Password confirmation
            
        Returns:
            User object if successful
            
        Raises:
            ValidationError: If validation fails
        """
        # Validate inputs
        InputValidator.validate_username(username)
        InputValidator.validate_email(email)
        InputValidator.validate_password(password)
        InputValidator.validate_password_confirmation(password, password_confirm)
        
        # Additional password checks
        PasswordValidator.check_common_password(password)
        PasswordValidator.check_sequential_characters(password)
        PasswordValidator.check_repeated_characters(password)
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            raise ValidationError("Username already exists")
        
        if User.query.filter_by(email=email).first():
            raise ValidationError("Email already registered")
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return user
    
    @staticmethod
    def authenticate_user(username: str, password: str, ip_address: str, user_agent: str) -> tuple:
        """
        Authenticate user with username and password
        
        Args:
            username: User's username
            password: User's password
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Tuple of (User object or None, message)
        """
        try:
            InputValidator.sanitize_sql_input(username)
            
            user = User.query.filter_by(username=username).first()
            
            # Create login history entry
            if user:
                # Check if account is locked
                if user.is_account_locked():
                    login_history = LoginHistory(
                        user_id=user.id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        success=False,
                        reason="account_locked"
                    )
                    db.session.add(login_history)
                    db.session.commit()
                    return None, "Account is locked due to multiple failed login attempts. Try again later."
                
                # Check password
                if user.verify_password(password):
                    user.reset_failed_login()
                    
                    # Create login history entry
                    login_history = LoginHistory(
                        user_id=user.id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        success=True
                    )
                    db.session.add(login_history)
                    db.session.commit()
                    
                    return user, "Login successful"
                else:
                    # Failed password
                    user.increment_failed_login(current_app.config['LOCKOUT_DURATION'])
                    
                    login_history = LoginHistory(
                        user_id=user.id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        success=False,
                        reason="invalid_password"
                    )
                    db.session.add(login_history)
                    db.session.commit()
                    
                    return None, "Invalid username or password"
            else:
                # User not found - still log the attempt
                return None, "Invalid username or password"
                
        except ValidationError as e:
            return None, str(e)
        except Exception as e:
            current_app.logger.error(f"Authentication error: {str(e)}")
            return None, "An error occurred during authentication"
    
    @staticmethod
    def create_session(user: User, ip_address: str, user_agent: str, session_duration: int = 3600) -> UserSession:
        """
        Create a new user session
        
        Args:
            user: User object
            ip_address: Client IP address
            user_agent: Client user agent
            session_duration: Session duration in seconds (default 1 hour)
            
        Returns:
            UserSession object
        """
        # Generate secure session token
        session_token = secrets.token_urlsafe(32)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(seconds=session_duration)
        )
        
        db.session.add(user_session)
        db.session.commit()
        
        return user_session
    
    @staticmethod
    def validate_session(session_token: str, ip_address: str) -> User:
        """
        Validate session token
        
        Args:
            session_token: Session token
            ip_address: Client IP address
            
        Returns:
            User object if session is valid, None otherwise
        """
        user_session = UserSession.query.filter_by(
            session_token=session_token,
            is_active=True
        ).first()
        
        if not user_session:
            return None
        
        # Check if session is expired
        if not user_session.is_valid():
            user_session.is_active = False
            db.session.commit()
            return None
        
        # Check IP address (optional - can be strict or lenient)
        # For now, just refresh activity
        user_session.refresh_activity()
        db.session.commit()
        
        return user_session.user
    
    @staticmethod
    def logout(session_token: str) -> None:
        """
        Logout user by invalidating session
        
        Args:
            session_token: Session token to invalidate
        """
        user_session = UserSession.query.filter_by(session_token=session_token).first()
        
        if user_session:
            user_session.is_active = False
            db.session.commit()
    
    @staticmethod
    def cleanup_expired_sessions() -> None:
        """Remove expired sessions from database"""
        UserSession.query.filter(
            UserSession.expires_at < datetime.utcnow()
        ).delete()
        db.session.commit()
    
    @staticmethod
    def change_password(user: User, old_password: str, new_password: str, new_password_confirm: str) -> None:
        """
        Change user password
        
        Args:
            user: User object
            old_password: Current password
            new_password: New password
            new_password_confirm: New password confirmation
            
        Raises:
            ValidationError: If validation fails
        """
        # Verify old password
        if not user.verify_password(old_password):
            raise ValidationError("Current password is incorrect")
        
        # Validate new password
        InputValidator.validate_password(new_password)
        InputValidator.validate_password_confirmation(new_password, new_password_confirm)
        
        # Check new password strength
        PasswordValidator.check_common_password(new_password)
        PasswordValidator.check_sequential_characters(new_password)
        PasswordValidator.check_repeated_characters(new_password)
        
        # Ensure new password is different from old
        if old_password == new_password:
            raise ValidationError("New password must be different from current password")
        
        # Set new password
        user.set_password(new_password)
        
        # Invalidate all existing sessions for security
        UserSession.query.filter_by(user_id=user.id).update({'is_active': False})
        
        db.session.commit()


class TwoFactorService:
    """Handle Two-Factor Authentication operations"""
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        """
        Generate backup codes for account recovery
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(code)
        return codes
    
    @staticmethod
    def setup_2fa(user: User) -> tuple:
        """
        Setup 2FA for user
        
        Args:
            user: User object
            
        Returns:
            Tuple of (secret, qr_code_base64, backup_codes)
        """
        secret, qr_code = user.setup_totp()
        backup_codes = TwoFactorService.generate_backup_codes()
        
        db.session.commit()
        
        return secret, qr_code, backup_codes
    
    @staticmethod
    def enable_2fa(user: User, token: str) -> None:
        """
        Enable 2FA after verifying initial token
        
        Args:
            user: User object
            token: TOTP token to verify
            
        Raises:
            ValidationError: If token is invalid
        """
        InputValidator.validate_totp_token(token)
        
        if not user.verify_totp(token):
            raise ValidationError("Invalid TOTP token")
        
        backup_codes = TwoFactorService.generate_backup_codes()
        user.enable_totp(backup_codes)
        
        db.session.commit()
    
    @staticmethod
    def disable_2fa(user: User, password: str) -> None:
        """
        Disable 2FA (requires password verification)
        
        Args:
            user: User object
            password: User's password
            
        Raises:
            ValidationError: If password is incorrect
        """
        if not user.verify_password(password):
            raise ValidationError("Invalid password")
        
        user.disable_totp()
        db.session.commit()
    
    @staticmethod
    def verify_2fa_token(user: User, token: str) -> bool:
        """
        Verify 2FA token or backup code
        
        Args:
            user: User object
            token: TOTP token or backup code
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            InputValidator.validate_totp_token(token)
            
            # Try TOTP token first
            if user.verify_totp(token):
                return True
            
            # Try backup code
            if user.use_backup_code(token):
                db.session.commit()
                return True
            
            return False
        except ValidationError:
            # Token is 8 characters, might be backup code
            if len(token) == 8 and user.use_backup_code(token):
                db.session.commit()
                return True
            return False
