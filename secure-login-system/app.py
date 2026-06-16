from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

from config import config
from models import db, User, UserSession
from auth import AuthService, TwoFactorService
from validators import ValidationError


def create_app(config_name: str = None) -> Flask:
    """Create and configure Flask app"""
    
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize database
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
    
    # Helper functions
    def get_client_ip():
        """Get client IP address"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        return request.remote_addr
    
    def get_user_agent():
        """Get client user agent"""
        return request.headers.get('User-Agent', '')
    
    def login_required(f):
        """Decorator to require login"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'session_token' not in session:
                return redirect(url_for('login'))
            
            # Validate session
            user = AuthService.validate_session(session['session_token'], get_client_ip())
            if not user:
                session.clear()
                return redirect(url_for('login'))
            
            return f(*args, **kwargs)
        return decorated_function
    
    def require_no_auth(f):
        """Decorator to require no authentication (for login/register pages)"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'session_token' in session:
                user = AuthService.validate_session(session['session_token'], get_client_ip())
                if user:
                    return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    
    # Routes
    @app.route('/')
    def index():
        """Home page"""
        if 'session_token' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    
    @app.route('/register', methods=['GET', 'POST'])
    @require_no_auth
    def register():
        """User registration"""
        if request.method == 'POST':
            try:
                data = request.get_json() if request.is_json else request.form
                
                username = data.get('username', '').strip()
                email = data.get('email', '').strip()
                password = data.get('password', '')
                password_confirm = data.get('password_confirm', '')
                
                # Register user
                user = AuthService.register_user(username, email, password, password_confirm)
                
                return jsonify({
                    'success': True,
                    'message': 'Registration successful! Please log in.',
                    'redirect': url_for('login')
                })
            
            except ValidationError as e:
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 400
            
            except Exception as e:
                app.logger.error(f"Registration error: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': 'An error occurred during registration'
                }), 500
        
        return render_template('register.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    @require_no_auth
    def login():
        """User login"""
        if request.method == 'POST':
            try:
                data = request.get_json() if request.is_json else request.form
                
                username = data.get('username', '').strip()
                password = data.get('password', '')
                
                ip_address = get_client_ip()
                user_agent = get_user_agent()
                
                # Authenticate user
                user, message = AuthService.authenticate_user(username, password, ip_address, user_agent)
                
                if user:
                    # Check if 2FA is enabled
                    if user.totp_enabled:
                        # Store temporary session for 2FA verification
                        session['temp_user_id'] = user.id
                        session['temp_timestamp'] = datetime.utcnow().isoformat()
                        return jsonify({
                            'success': True,
                            'message': 'Please verify with 2FA',
                            'requires_2fa': True,
                            'redirect': url_for('verify_2fa')
                        })
                    else:
                        # Create session
                        user_session = AuthService.create_session(
                            user, ip_address, user_agent,
                            session_duration=app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
                        )
                        
                        session.permanent = True
                        session['session_token'] = user_session.session_token
                        session['user_id'] = user.id
                        
                        return jsonify({
                            'success': True,
                            'message': 'Login successful',
                            'redirect': url_for('dashboard')
                        })
                else:
                    return jsonify({
                        'success': False,
                        'error': message
                    }), 401
            
            except Exception as e:
                app.logger.error(f"Login error: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': 'An error occurred during login'
                }), 500
        
        return render_template('login.html')
    
    @app.route('/verify-2fa', methods=['GET', 'POST'])
    def verify_2fa():
        """2FA verification"""
        if 'temp_user_id' not in session:
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            try:
                data = request.get_json() if request.is_json else request.form
                token = data.get('token', '').strip()
                use_backup = data.get('use_backup', False)
                
                user = User.query.get(session['temp_user_id'])
                if not user:
                    return jsonify({
                        'success': False,
                        'error': 'User session expired'
                    }), 401
                
                # Verify 2FA token
                if TwoFactorService.verify_2fa_token(user, token):
                    ip_address = get_client_ip()
                    user_agent = get_user_agent()
                    
                    # Create session
                    user_session = AuthService.create_session(
                        user, ip_address, user_agent,
                        session_duration=app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
                    )
                    
                    session.clear()
                    session.permanent = True
                    session['session_token'] = user_session.session_token
                    session['user_id'] = user.id
                    
                    return jsonify({
                        'success': True,
                        'message': 'Login successful',
                        'redirect': url_for('dashboard')
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid 2FA token'
                    }), 401
            
            except Exception as e:
                app.logger.error(f"2FA verification error: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': 'An error occurred during verification'
                }), 500
        
        return render_template('verify_2fa.html')
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """User dashboard"""
        user = User.query.get(session.get('user_id'))
        if not user:
            return redirect(url_for('login'))
        
        return render_template('dashboard.html', user=user)
    
    @app.route('/api/profile')
    @login_required
    def get_profile():
        """Get user profile"""
        user = User.query.get(session.get('user_id'))
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict())
    
    @app.route('/api/settings/password', methods=['POST'])
    @login_required
    def change_password():
        """Change password"""
        try:
            user = User.query.get(session.get('user_id'))
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            data = request.get_json() if request.is_json else request.form
            
            old_password = data.get('old_password', '')
            new_password = data.get('new_password', '')
            new_password_confirm = data.get('new_password_confirm', '')
            
            AuthService.change_password(user, old_password, new_password, new_password_confirm)
            
            # Clear sessions
            session.clear()
            
            return jsonify({
                'success': True,
                'message': 'Password changed successfully. Please log in again.',
                'redirect': url_for('login')
            })
        
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        except Exception as e:
            app.logger.error(f"Password change error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'An error occurred'
            }), 500
    
    @app.route('/api/2fa/setup', methods=['POST'])
    @login_required
    def setup_2fa():
        """Setup 2FA"""
        try:
            user = User.query.get(session.get('user_id'))
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if user.totp_enabled:
                return jsonify({
                    'success': False,
                    'error': '2FA is already enabled'
                }), 400
            
            secret, qr_code, backup_codes = TwoFactorService.setup_2fa(user)
            
            return jsonify({
                'success': True,
                'secret': secret,
                'qr_code': f'data:image/png;base64,{qr_code}',
                'backup_codes': backup_codes
            })
        
        except Exception as e:
            app.logger.error(f"2FA setup error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'An error occurred'
            }), 500
    
    @app.route('/api/2fa/enable', methods=['POST'])
    @login_required
    def enable_2fa():
        """Enable 2FA"""
        try:
            user = User.query.get(session.get('user_id'))
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            data = request.get_json() if request.is_json else request.form
            token = data.get('token', '').strip()
            
            TwoFactorService.enable_2fa(user, token)
            
            return jsonify({
                'success': True,
                'message': '2FA enabled successfully'
            })
        
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        except Exception as e:
            app.logger.error(f"2FA enable error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'An error occurred'
            }), 500
    
    @app.route('/api/2fa/disable', methods=['POST'])
    @login_required
    def disable_2fa():
        """Disable 2FA"""
        try:
            user = User.query.get(session.get('user_id'))
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if not user.totp_enabled:
                return jsonify({
                    'success': False,
                    'error': '2FA is not enabled'
                }), 400
            
            data = request.get_json() if request.is_json else request.form
            password = data.get('password', '')
            
            TwoFactorService.disable_2fa(user, password)
            
            return jsonify({
                'success': True,
                'message': '2FA disabled successfully'
            })
        
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        except Exception as e:
            app.logger.error(f"2FA disable error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'An error occurred'
            }), 500
    
    @app.route('/api/sessions')
    @login_required
    def get_sessions():
        """Get all active sessions"""
        user = User.query.get(session.get('user_id'))
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        sessions = UserSession.query.filter_by(user_id=user.id, is_active=True).all()
        
        sessions_data = []
        for s in sessions:
            sessions_data.append({
                'id': s.id,
                'ip_address': s.ip_address,
                'created_at': s.created_at.isoformat(),
                'last_activity': s.last_activity.isoformat(),
                'current': s.session_token == session.get('session_token')
            })
        
        return jsonify(sessions_data)
    
    @app.route('/logout', methods=['POST'])
    @login_required
    def logout():
        """Logout user"""
        try:
            if 'session_token' in session:
                AuthService.logout(session['session_token'])
            
            session.clear()
            
            return jsonify({
                'success': True,
                'message': 'Logged out successfully',
                'redirect': url_for('login')
            })
        
        except Exception as e:
            app.logger.error(f"Logout error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'An error occurred'
            }), 500
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')
