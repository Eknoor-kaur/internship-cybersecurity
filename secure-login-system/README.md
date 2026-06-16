# 🔐 Secure Login System

A comprehensive web-based secure login system with password hashing, input validation, session management, and optional Two-Factor Authentication (2FA).

## Features

### Core Security Features
✅ **Bcrypt Password Hashing** - Industry-standard password hashing with 12 rounds
✅ **Input Validation** - Comprehensive validation against SQL injection and other attacks
✅ **Session Management** - Secure session tokens with expiration and activity tracking
✅ **Account Lockout** - Automatic account lockout after failed login attempts
✅ **Password Requirements** - Strong password policy enforcement
✅ **HTTPS Ready** - Secure cookie configuration for production

### Advanced Features
✅ **Two-Factor Authentication (2FA)** - TOTP (Time-based One-Time Password) support
✅ **Backup Codes** - Recovery codes for account access
✅ **QR Code Generation** - Easy authenticator app setup
✅ **Login History** - Track all login attempts
✅ **Session Monitoring** - View and manage active sessions
✅ **Password Change** - Securely update passwords with session invalidation

## Technology Stack

- **Backend**: Python Flask with SQLAlchemy ORM
- **Database**: SQLite (configurable)
- **Password Hashing**: Bcrypt
- **2FA**: TOTP (PyOTP)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Security**: Input validation, parameterized queries, secure cookies

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup Steps

1. **Navigate to project directory**
   ```bash
   cd secure-login-system
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create environment file**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and update `SECRET_KEY`:
   ```
   SECRET_KEY=your-random-secret-key-here
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

   The application will be available at `http://localhost:5000`

## Security Measures

### Password Security
1. **Bcrypt Hashing** - 12 rounds with random salt
2. **Strong Password Policy** - Enforces complexity requirements
3. **Password History** - Tracks last password change
4. **Session Invalidation** - All sessions invalidated on password change

### Input Protection
1. **SQL Injection Prevention** - Parameterized queries via SQLAlchemy ORM
2. **Input Sanitization** - Validation of username, email, and password
3. **XSS Protection** - Secure cookie flags and input escaping
4. **CSRF Protection** - Built-in Flask session management

### Account Protection
1. **Account Lockout** - After 5 failed login attempts (15-minute lockout)
2. **Session Timeout** - Automatic session expiration (default: 1 hour)
3. **IP Tracking** - Records client IP for login history
4. **Activity Monitoring** - Tracks last activity timestamp

### 2FA Security
1. **TOTP Standard** - RFC 6238 compliant
2. **Backup Codes** - 10 one-time recovery codes
3. **QR Code** - Easy authenticator app setup
4. **Token Validation** - 30-second window for clock skew

## Project Structure

```
secure-login-system/
├── app.py              # Main Flask application
├── config.py           # Configuration management
├── models.py           # Database models
├── validators.py       # Input validation
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template
└── templates/          # HTML templates (to be added)
```

## Configuration

Edit `.env` file to customize:

```bash
# Database
DATABASE_URL=sqlite:///secure_login.db

# Flask
FLASK_ENV=development
SECRET_KEY=your-secret-key

# Security
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900  # 15 minutes
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
```

## Security Best Practices

1. **Change SECRET_KEY** - Use a strong, random key in production
2. **Enable HTTPS** - Always use HTTPS in production
3. **Database Backup** - Regular backups of user data
4. **Monitor Logs** - Check login history for suspicious activity
5. **Update Dependencies** - Keep libraries updated for security patches
6. **Rate Limiting** - Consider adding rate limiting for login attempts
7. **CAPTCHA** - Consider adding CAPTCHA for registration/login

## Contributing

Contributions are welcome! Please ensure:
- Code follows PEP 8 style guide
- Security best practices are maintained
- Tests are included for new features
- Documentation is updated

---

**Made with ❤️ for secure authentication**
