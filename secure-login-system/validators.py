import re
from email_validator import validate_email, EmailNotValidError
from config import Config


class ValidationError(Exception):
    """Custom validation error"""
    pass


class InputValidator:
    """Validate user input to prevent injection attacks and ensure data quality"""
    
    @staticmethod
    def validate_username(username: str) -> None:
        """
        Validate username
        - 3-20 characters
        - Only alphanumeric, underscore, and hyphen
        """
        if not username:
            raise ValidationError("Username is required")
        
        if len(username) < 3 or len(username) > 20:
            raise ValidationError("Username must be between 3 and 20 characters")
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise ValidationError("Username can only contain letters, numbers, underscores, and hyphens")
    
    @staticmethod
    def validate_email(email: str) -> None:
        """Validate email format"""
        if not email:
            raise ValidationError("Email is required")
        
        try:
            validate_email(email)
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email format: {str(e)}")
    
    @staticmethod
    def validate_password(password: str) -> None:
        """
        Validate password strength
        - Minimum length
        - Uppercase and lowercase letters
        - Numbers
        - Special characters
        """
        if not password:
            raise ValidationError("Password is required")
        
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            raise ValidationError(
                f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long"
            )
        
        if Config.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter")
        
        if Config.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter")
        
        if Config.REQUIRE_DIGITS and not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one digit")
        
        if Config.REQUIRE_SPECIAL_CHARS and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'\"',.<>?/\\|`~]', password):
            raise ValidationError("Password must contain at least one special character (!@#$%^&*)")
    
    @staticmethod
    def validate_totp_token(token: str) -> None:
        """Validate TOTP token format"""
        if not token:
            raise ValidationError("TOTP token is required")
        
        if not re.match(r'^\d{6}$', token):
            raise ValidationError("TOTP token must be 6 digits")
    
    @staticmethod
    def sanitize_sql_input(value: str, max_length: int = 255) -> str:
        """
        Sanitize input to prevent SQL injection
        Note: Using parameterized queries (ORM) is the primary defense
        This is an additional layer of protection
        """
        if not isinstance(value, str):
            raise ValidationError("Input must be a string")
        
        if len(value) > max_length:
            raise ValidationError(f"Input exceeds maximum length of {max_length}")
        
        # Remove potential SQL injection characters
        # SQLAlchemy ORM handles this, but we add extra validation
        dangerous_patterns = [
            r'(\bDROP\b)',
            r'(\bINSERT\b)',
            r'(\bUPDATE\b)',
            r'(\bDELETE\b)',
            r'(\bEXEC\b)',
            r'(\bSELECT.*FROM)',
            r'(;.*)',
            r"(\'\ s*OR\s*\'1\'=\'1)",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError("Input contains potentially dangerous characters")
        
        return value.strip()
    
    @staticmethod
    def validate_password_confirmation(password: str, confirmation: str) -> None:
        """Ensure passwords match"""
        if password != confirmation:
            raise ValidationError("Passwords do not match")


class PasswordValidator:
    """Advanced password validation"""
    
    # Common weak passwords to check against
    WEAK_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', '111111', 'letmein', 'welcome', 'monkey'
    }
    
    @staticmethod
    def check_common_password(password: str) -> None:
        """Check if password is in common weak passwords list"""
        if password.lower() in PasswordValidator.WEAK_PASSWORDS:
            raise ValidationError("This password is too common. Please choose a stronger password")
    
    @staticmethod
    def check_sequential_characters(password: str) -> None:
        """Check for sequential characters (e.g., abc, 123)"""
        for i in range(len(password) - 2):
            if ord(password[i+1]) == ord(password[i]) + 1 and \
               ord(password[i+2]) == ord(password[i]) + 2:
                raise ValidationError("Password should not contain sequential characters")
    
    @staticmethod
    def check_repeated_characters(password: str) -> None:
        """Check for repeated characters (e.g., aaa, 111)"""
        if re.search(r'(.)\1{2,}', password):
            raise ValidationError("Password should not contain repeated characters")
