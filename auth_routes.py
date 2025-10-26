"""
Authentication routes for SMVEC College System
Handles registration, OTP verification, and login
"""

from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash
from utils.college_auth import CollegeAuthSystem
from utils.firebase_config import initialize_firebase
import logging
import re

# Initialize Firebase
initialize_firebase()

# Create blueprint
auth_bp = Blueprint('auth', __name__)
auth_system = CollegeAuthSystem()

logger = logging.getLogger(__name__)

@auth_bp.route('/register')
def register_page():
    """Registration page"""
    return render_template('auth/register.html')

@auth_bp.route('/login')
def login_page():
    """Login page"""
    return render_template('auth/login.html')

@auth_bp.route('/verify-otp')
def verify_otp_page():
    """OTP verification page"""
    email = request.args.get('email')
    if not email:
        flash('Invalid access. Please start registration again.', 'error')
        return redirect(url_for('auth.register_page'))
    return render_template('auth/verify_otp.html', email=email)

@auth_bp.route('/set-password')
def set_password_page():
    """Password setup page"""
    email = request.args.get('email')
    if not email:
        flash('Invalid access. Please complete OTP verification first.', 'error')
        return redirect(url_for('auth.register_page'))
    return render_template('auth/set_password.html', email=email)

@auth_bp.route('/remove-account')
def remove_account_page():
    """Account removal page"""
    return render_template('auth/remove_account.html')

# Hidden Admin Routes
@auth_bp.route('/loginadmin')
def admin_login_page():
    """Hidden admin login page"""
    return render_template('auth/admin_login.html')

@auth_bp.route('/registeradmin')
def admin_register_page():
    """Hidden admin registration page"""
    return render_template('auth/admin_register.html')

# Forgot Password Routes
@auth_bp.route('/forgot-password')
def forgot_password_page():
    """Forgot password page"""
    return render_template('auth/forgot_password.html')

@auth_bp.route('/verify-reset-otp')
def verify_reset_otp_page():
    """Verify reset OTP page"""
    email = request.args.get('email', '')
    return render_template('auth/verify_reset_otp.html', email=email)

@auth_bp.route('/reset-password')
def reset_password_page():
    """Reset password page"""
    email = request.args.get('email', '')
    reset_id = request.args.get('reset_id', '')
    return render_template('auth/reset_password.html', email=email, reset_id=reset_id)

@auth_bp.route('/api/register', methods=['POST'])
def register_user():
    """Handle user registration and send OTP"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['full_name', 'register_number', 'department', 'user_type', 'email']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400
        
        # Add section validation for students
        if data['user_type'].lower() == 'student' and not data.get('section'):
            return jsonify({'success': False, 'error': 'Section is required for students'}), 400
        
        # Validate email format and college domain
        email_validation = auth_system.validate_college_email(data['email'], data['user_type'])
        if not email_validation['valid']:
            return jsonify({'success': False, 'error': email_validation['error']}), 400
        
        # Check if email already exists
        if auth_system.check_email_exists(data['email']):
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Validate register number format
        register_number = data['register_number'].strip()
        if len(register_number) < 5:
            return jsonify({'success': False, 'error': 'Invalid register number format'}), 400
        
        # Validate full name
        full_name = data['full_name'].strip()
        if len(full_name) < 2:
            return jsonify({'success': False, 'error': 'Full name must be at least 2 characters'}), 400
        
        # Generate and send OTP
        otp = auth_system.generate_otp()
        
        # Send OTP email
        email_result = auth_system.send_otp_email(data['email'], otp, full_name)
        if not email_result['success']:
            return jsonify({'success': False, 'error': email_result['error']}), 500
        
        # Store pending registration
        store_result = auth_system.store_pending_registration(data, otp)
        if not store_result['success']:
            return jsonify({'success': False, 'error': store_result['error']}), 500
        
        logger.info(f"Registration initiated for {data['email']}")
        return jsonify({
            'success': True, 
            'message': 'OTP sent to your college email. Please check your inbox.',
            'email': data['email']
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'error': 'Registration failed. Please try again.'}), 500

@auth_bp.route('/api/admin/register', methods=['POST'])
def register_admin():
    """Handle admin registration with admin code verification"""
    try:
        data = request.get_json()

        # Validate required fields for admin
        required_fields = ['full_name', 'employee_id', 'department', 'email', 'admin_code']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        # Validate admin code first
        admin_code_validation = auth_system.validate_admin_code(data['admin_code'])
        if not admin_code_validation['valid']:
            return jsonify({'success': False, 'error': admin_code_validation['error']}), 400

        # Validate email format and college domain for admin
        email_validation = auth_system.validate_college_email(data['email'], 'admin')
        if not email_validation['valid']:
            return jsonify({'success': False, 'error': email_validation['error']}), 400

        # Check if email already exists
        if auth_system.check_email_exists(data['email']):
            return jsonify({'success': False, 'error': 'Email already registered'}), 400

        # Validate employee ID format
        employee_id = data['employee_id'].strip()
        if len(employee_id) < 3:
            return jsonify({'success': False, 'error': 'Invalid employee ID format'}), 400

        # Validate full name
        full_name = data['full_name'].strip()
        if len(full_name) < 2:
            return jsonify({'success': False, 'error': 'Full name must be at least 2 characters'}), 400

        # Set user type as admin
        data['user_type'] = 'admin'
        data['register_number'] = employee_id  # Use employee_id as register_number for consistency

        # Generate and send OTP
        otp = auth_system.generate_otp()

        # Send OTP email
        email_result = auth_system.send_otp_email(data['email'], otp, full_name)
        if not email_result['success']:
            return jsonify({'success': False, 'error': email_result['error']}), 500

        # Store pending admin registration
        store_result = auth_system.store_pending_registration(data, otp)
        if not store_result['success']:
            return jsonify({'success': False, 'error': store_result['error']}), 500

        logger.info(f"Admin registration initiated for {data['email']}")
        return jsonify({
            'success': True,
            'message': 'Admin registration initiated. Please check your email for OTP.',
            'email': data['email']
        })

    except Exception as e:
        logger.error(f"Admin registration error: {str(e)}")
        return jsonify({'success': False, 'error': 'Admin registration failed. Please try again.'}), 500

@auth_bp.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Handle forgot password request"""
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('email'):
            return jsonify({'success': False, 'error': 'Email is required'}), 400

        email = data['email'].lower().strip()

        # Validate email format
        if not email.endswith('@smvec.ac.in'):
            return jsonify({'success': False, 'error': 'Please use your college email address'}), 400

        # Check if user exists
        if not auth_system.check_email_exists(email):
            return jsonify({'success': False, 'error': 'No account found with this email address'}), 404

        # Check rate limit
        rate_limit_check = auth_system.check_reset_rate_limit(email)
        if not rate_limit_check['allowed']:
            return jsonify({'success': False, 'error': rate_limit_check['error']}), 429

        # Generate OTP
        otp = auth_system.generate_otp()

        # Store reset request
        store_result = auth_system.store_password_reset_request(email, otp)
        if not store_result['success']:
            return jsonify({'success': False, 'error': store_result['error']}), 500

        # Send OTP email
        email_result = auth_system.send_otp_email(email, otp, "User", is_password_reset=True)
        if not email_result['success']:
            return jsonify({'success': False, 'error': email_result['error']}), 500

        logger.info(f"Password reset OTP sent to {email}")
        return jsonify({
            'success': True,
            'message': 'Password reset OTP sent to your email',
            'email': email
        })

    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to process request. Please try again.'}), 500

@auth_bp.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    """Verify OTP for password reset"""
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('email') or not data.get('otp'):
            return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400

        email = data['email'].lower().strip()
        otp = data['otp'].strip()

        # Validate OTP format
        if not otp.isdigit() or len(otp) != 6:
            return jsonify({'success': False, 'error': 'OTP must be 6 digits'}), 400

        # Verify OTP
        verification_result = auth_system.verify_reset_otp(email, otp)

        if verification_result['valid']:
            logger.info(f"Password reset OTP verified for {email}")
            return jsonify({
                'success': True,
                'message': 'OTP verified successfully',
                'reset_id': verification_result['reset_id']
            })
        else:
            return jsonify({'success': False, 'error': verification_result['error']}), 400

    except Exception as e:
        logger.error(f"Verify reset OTP error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to verify OTP. Please try again.'}), 500

@auth_bp.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset user password"""
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['email', 'password', 'confirm_password', 'reset_id']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        email = data['email'].lower().strip()
        password = data['password']
        confirm_password = data['confirm_password']
        reset_id = data['reset_id']

        # Validate password match
        if password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'}), 400

        # Validate password strength
        password_validation = auth_system.validate_password_strength(password)
        if not password_validation['valid']:
            return jsonify({'success': False, 'error': password_validation['error']}), 400

        # Complete password reset
        reset_result = auth_system.complete_password_reset(email, password, reset_id)

        if reset_result['success']:
            logger.info(f"Password reset completed for {email}")
            return jsonify({
                'success': True,
                'message': 'Password reset successfully. You can now login with your new password.'
            })
        else:
            return jsonify({'success': False, 'error': reset_result['error']}), 400

    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to reset password. Please try again.'}), 500

@auth_bp.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP entered by user"""
    try:
        data = request.get_json()
        
        email = data.get('email')
        otp = data.get('otp')
        
        if not email or not otp:
            return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400
        
        # Verify OTP
        verification_result = auth_system.verify_otp(email, otp)
        
        if verification_result['success']:
            logger.info(f"OTP verified successfully for {email}")
            return jsonify({
                'success': True,
                'message': 'OTP verified successfully. You can now set your password.',
                'email': email
            })
        else:
            return jsonify({'success': False, 'error': verification_result['error']}), 400
            
    except Exception as e:
        logger.error(f"OTP verification error: {str(e)}")
        return jsonify({'success': False, 'error': 'OTP verification failed. Please try again.'}), 500

@auth_bp.route('/api/set-password', methods=['POST'])
def set_password():
    """Set password and create user account"""
    try:
        data = request.get_json()
        
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not email or not password or not confirm_password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        # Validate password match
        if password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
        
        # Validate password strength
        password_validation = validate_password_strength(password)
        if not password_validation['valid']:
            return jsonify({'success': False, 'error': password_validation['error']}), 400
        
        # Create user account
        account_result = auth_system.create_user_account(email, password)
        
        if account_result['success']:
            logger.info(f"Account created successfully for {email}")
            return jsonify({
                'success': True,
                'message': 'Account created successfully! You can now login.',
                'user_id': account_result['user_id']
            })
        else:
            return jsonify({'success': False, 'error': account_result['error']}), 400
            
    except Exception as e:
        logger.error(f"Password setup error: {str(e)}")
        return jsonify({'success': False, 'error': 'Account creation failed. Please try again.'}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login_user():
    """Handle user login"""
    try:
        logger.info("Login attempt started")
        data = request.get_json()

        email = data.get('email')
        password = data.get('password')

        logger.info(f"Login attempt for email: {email}")

        if not email or not password:
            logger.warning("Login failed: Missing email or password")
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # Validate email format
        email = email.lower().strip()
        logger.info(f"Normalized email: {email}")

        # Get user from database
        logger.info("Querying users collection...")
        users_query = auth_system.db.collection('users').where('email', '==', email).limit(1).get()
        
        if not users_query:
            logger.warning(f"No user found for email: {email}")
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        logger.info(f"Found {len(users_query)} user(s) for email: {email}")
        user_doc = users_query[0]
        user_data = user_doc.to_dict()
        user_id = user_doc.id
        logger.info(f"User ID: {user_id}, User Type: {user_data.get('user_type')}")
        
        # Check if account is locked
        if user_data.get('account_locked_until'):
            from datetime import datetime
            if datetime.now() < user_data['account_locked_until']:
                return jsonify({'success': False, 'error': 'Account is temporarily locked. Please try again later.'}), 401
        
        # Verify password
        logger.info("Verifying password...")
        password_valid = auth_system.verify_password(password, user_data['password_hash'])
        logger.info(f"Password verification result: {password_valid}")

        if not password_valid:
            # Increment login attempts
            login_attempts = user_data.get('login_attempts', 0) + 1
            update_data = {'login_attempts': login_attempts}
            
            # Lock account if max attempts exceeded
            if login_attempts >= auth_system.max_login_attempts:
                from datetime import datetime, timedelta
                lockout_until = datetime.now() + timedelta(minutes=auth_system.account_lockout_minutes)
                update_data['account_locked_until'] = lockout_until
                
            auth_system.db.collection('users').document(user_id).update(update_data)
            
            remaining_attempts = auth_system.max_login_attempts - login_attempts
            if remaining_attempts > 0:
                return jsonify({'success': False, 'error': f'Invalid password. {remaining_attempts} attempts remaining.'}), 401
            else:
                return jsonify({'success': False, 'error': 'Account locked due to too many failed attempts.'}), 401
        
        # Successful login - reset attempts and update last login
        logger.info("Password verification successful, updating user login data...")
        try:
            from google.cloud import firestore
            auth_system.db.collection('users').document(user_id).update({
                'login_attempts': 0,
                'account_locked_until': None,
                'last_login': firestore.SERVER_TIMESTAMP
            })
            logger.info("User login data updated successfully")
        except Exception as db_error:
            logger.error(f"Database update error: {str(db_error)}")
            raise

        # Generate JWT token
        logger.info("Generating JWT token...")
        try:
            token = auth_system.generate_jwt_token(user_id, email, user_data['user_type'])
            logger.info(f"JWT token generated successfully: {token[:20] if token else 'None'}...")
            if not token:
                raise ValueError("JWT token generation returned None")
        except Exception as jwt_error:
            logger.error(f"JWT generation error: {str(jwt_error)}")
            raise

        # Set session
        logger.info("Setting session data...")
        try:
            session['user_id'] = user_id
            session['email'] = email
            session['user_type'] = user_data['user_type']
            session['full_name'] = user_data['full_name']
            session['jwt_token'] = token
            logger.info("Session data set successfully")
        except Exception as session_error:
            logger.error(f"Session setting error: {str(session_error)}")
            raise

        # Get dashboard URL
        logger.info("Getting dashboard URL...")
        try:
            dashboard_url = get_dashboard_url(user_data['user_type'])
            logger.info(f"Dashboard URL: {dashboard_url}")
        except Exception as url_error:
            logger.error(f"Dashboard URL error: {str(url_error)}")
            raise

        logger.info(f"User logged in successfully: {email}")

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'user_id': user_id,
                'email': email,
                'full_name': user_data['full_name'],
                'user_type': user_data['user_type'],
                'department': user_data['department']
            },
            'redirect_url': dashboard_url
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        import traceback
        logger.error(f"Login traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': f'Login failed: {str(e)}'}), 500

@auth_bp.route('/api/logout', methods=['POST'])
def logout_user():
    """Handle user logout"""
    try:
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'success': False, 'error': 'Logout failed'}), 500

@auth_bp.route('/api/remove-account', methods=['POST'])
def remove_account():
    """Remove account and all related data (for development/testing)"""
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400

        # Validate email format
        if not email.endswith('@smvec.ac.in'):
            return jsonify({'success': False, 'error': 'Only SMVEC emails can be removed'}), 400

        removed_items = []

        # Remove from pending registrations
        try:
            pending_doc = auth_system.db.collection('pending_registrations').document(email)
            if pending_doc.get().exists:
                pending_doc.delete()
                removed_items.append('pending_registration')
        except Exception as e:
            logger.warning(f"Error removing pending registration: {e}")

        # Remove from OTP requests
        try:
            otp_docs = auth_system.db.collection('otp_requests').where('email', '==', email).stream()
            otp_count = 0
            for doc in otp_docs:
                doc.reference.delete()
                otp_count += 1
            if otp_count > 0:
                removed_items.append(f'{otp_count}_otp_requests')
        except Exception as e:
            logger.warning(f"Error removing OTP requests: {e}")

        # Remove from users
        try:
            user_docs = auth_system.db.collection('users').where('email', '==', email).stream()
            user_count = 0
            for doc in user_docs:
                doc.reference.delete()
                user_count += 1
            if user_count > 0:
                removed_items.append(f'{user_count}_user_accounts')
        except Exception as e:
            logger.warning(f"Error removing users: {e}")

        logger.info(f"Account removed: {email}, items: {removed_items}")
        return jsonify({
            'success': True,
            'message': f'Account {email} has been removed successfully',
            'removed_items': removed_items
        })

    except Exception as e:
        logger.error(f"Account removal error: {str(e)}")
        return jsonify({'success': False, 'error': 'Account removal failed'}), 500

@auth_bp.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP to user email"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # Check rate limiting (but don't fail completely if rate limit check fails)
        try:
            if not auth_system.check_rate_limit(email):
                return jsonify({'success': False, 'error': 'Too many OTP requests. Please try again later.'}), 429
        except Exception as rate_limit_error:
            logger.warning(f"Rate limit check failed for resend OTP, proceeding: {str(rate_limit_error)}")
            # Continue with OTP resend even if rate limit check fails
        
        # Get pending registration
        pending_doc = auth_system.db.collection('pending_registrations').document(email).get()
        
        if not pending_doc.exists:
            return jsonify({'success': False, 'error': 'No pending registration found'}), 404
        
        pending_data = pending_doc.to_dict()
        
        # Generate new OTP
        new_otp = auth_system.generate_otp()
        
        # Send OTP email
        email_result = auth_system.send_otp_email(email, new_otp, pending_data['full_name'])
        if not email_result['success']:
            return jsonify({'success': False, 'error': email_result['error']}), 500
        
        # Update pending registration with new OTP
        from datetime import datetime, timedelta
        auth_system.db.collection('pending_registrations').document(email).update({
            'otp_hash': auth_system.hash_otp(new_otp),
            'otp_attempts': 0,
            'expires_at': datetime.now() + timedelta(minutes=auth_system.otp_expiry_minutes),
            'is_verified': False
        })
        
        logger.info(f"OTP resent to {email}")
        return jsonify({'success': True, 'message': 'New OTP sent to your email'})
        
    except Exception as e:
        logger.error(f"Resend OTP error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to resend OTP'}), 500

def validate_password_strength(password: str) -> dict:
    """Validate password strength"""
    if len(password) < 8:
        return {'valid': False, 'error': 'Password must be at least 8 characters long'}
    
    if not re.search(r'[A-Z]', password):
        return {'valid': False, 'error': 'Password must contain at least one uppercase letter'}
    
    if not re.search(r'[a-z]', password):
        return {'valid': False, 'error': 'Password must contain at least one lowercase letter'}
    
    if not re.search(r'\d', password):
        return {'valid': False, 'error': 'Password must contain at least one number'}
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return {'valid': False, 'error': 'Password must contain at least one special character'}
    
    return {'valid': True}

def get_dashboard_url(user_type: str) -> str:
    """Get dashboard URL based on user type"""
    if user_type.lower() == 'student':
        return '/student-dashboard'
    elif user_type.lower() == 'faculty':
        return '/faculty-dashboard'
    elif user_type.lower() == 'admin':
        return '/admin-dashboard'
    else:
        return '/dashboard'
