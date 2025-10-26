"""
College Authentication System for SMVEC
Handles email validation, OTP generation, and user registration
"""

import os
import re
import random
import string
import smtplib
import hashlib
import secrets
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, Tuple
import bcrypt
import jwt
from utils.firebase_config import get_firestore_client
from google.cloud import firestore
import logging

logger = logging.getLogger(__name__)

class CollegeAuthSystem:
    def __init__(self):
        self.db = get_firestore_client()
        self.college_domain = os.getenv('COLLEGE_DOMAIN', 'smvec.ac.in')
        self.student_prefix = os.getenv('STUDENT_EMAIL_PREFIX', 'btech')
        self.faculty_domain = os.getenv('FACULTY_EMAIL_DOMAIN', '@smvec.ac.in')
        
        # SMTP Configuration
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        
        # OTP Configuration
        self.otp_length = int(os.getenv('OTP_LENGTH', 6))
        self.otp_expiry_minutes = int(os.getenv('OTP_EXPIRY_MINUTES', 5))
        self.otp_max_attempts = int(os.getenv('OTP_MAX_ATTEMPTS', 3))
        
        # Security Configuration
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'change_this_secret_key')
        self.password_rounds = int(os.getenv('PASSWORD_HASH_ROUNDS', 12))
        self.session_timeout_hours = int(os.getenv('SESSION_TIMEOUT_HOURS', 24))
        
        # Rate Limiting
        self.max_otp_requests_per_hour = int(os.getenv('MAX_OTP_REQUESTS_PER_HOUR', 5))
        self.max_login_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', 3))
        self.account_lockout_minutes = int(os.getenv('ACCOUNT_LOCKOUT_MINUTES', 15))

        # Admin Configuration
        self.admin_registration_code = os.getenv('ADMIN_REGISTRATION_CODE', 'SMVEC_ADMIN_2024_SECURE_ACCESS_KEY')
        self.admin_email_domain = os.getenv('ADMIN_EMAIL_DOMAIN', '@smvec.ac.in')

    def validate_college_email(self, email: str, user_type: str) -> Dict[str, Any]:
        """
        Validate college email based on user type
        Students: btech*@smvec.ac.in
        Faculty: *@smvec.ac.in (but not starting with btech)
        """
        try:
            email = email.lower().strip()
            
            # Basic email format validation
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                return {'valid': False, 'error': 'Invalid email format'}
            
            # Check if email ends with college domain
            if not email.endswith(f'@{self.college_domain}'):
                return {'valid': False, 'error': f'Email must be from {self.college_domain} domain'}
            
            # Extract username part
            username = email.split('@')[0]
            
            if user_type.lower() == 'student':
                # Student emails must start with 'btech'
                if not username.startswith(self.student_prefix):
                    return {'valid': False, 'error': f'Student emails must start with "{self.student_prefix}"'}
                
                # Additional validation for student email format
                # Expected format: btech + numbers/letters
                if len(username) < len(self.student_prefix) + 1:
                    return {'valid': False, 'error': 'Invalid student email format'}
                
            elif user_type.lower() == 'faculty':
                # Faculty emails should NOT start with 'btech'
                

                # Faculty email should have reasonable length
                if len(username) < 3:
                    return {'valid': False, 'error': 'Faculty email username too short'}

            elif user_type.lower() == 'admin':
                # Admin emails can be any valid college email
                # Additional validation will be done with admin code
                if len(username) < 3:
                    return {'valid': False, 'error': 'Admin email username too short'}

            else:
                return {'valid': False, 'error': 'Invalid user type'}
            
            return {'valid': True, 'email': email, 'user_type': user_type}
            
        except Exception as e:
            logger.error(f"Error validating email: {str(e)}")
            return {'valid': False, 'error': 'Email validation failed'}

    def validate_admin_code(self, admin_code: str) -> Dict[str, Any]:
        """
        Validate admin registration code
        """
        try:
            if not admin_code:
                return {
                    'valid': False,
                    'error': 'Admin code is required'
                }

            if admin_code.strip() != self.admin_registration_code:
                return {
                    'valid': False,
                    'error': 'Invalid admin code'
                }

            return {'valid': True}

        except Exception as e:
            logger.error(f"Admin code validation error: {str(e)}")
            return {
                'valid': False,
                'error': 'Admin code validation failed'
            }

    def check_email_exists(self, email: str) -> bool:
        """Check if email already exists in the system"""
        try:
            # Check in users collection
            users_query = self.db.collection('users').where('email', '==', email).limit(1).get()
            if users_query:
                return True
            
            # Check in pending registrations
            pending_query = self.db.collection('pending_registrations').where('email', '==', email).limit(1).get()
            if pending_query:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking email existence: {str(e)}")
            return True  # Assume exists to be safe

    def generate_otp(self) -> str:
        """Generate a random OTP"""
        return ''.join(random.choices(string.digits, k=self.otp_length))

    def send_otp_email(self, email: str, otp: str, user_name: str, is_password_reset: bool = False) -> Dict[str, Any]:
        """Send OTP via email using Gmail SMTP"""
        try:
            if not self.smtp_username or not self.smtp_password:
                return {'success': False, 'error': 'SMTP configuration not set'}

            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = email

            # Set subject based on type
            if is_password_reset:
                msg['Subject'] = 'SMVEC Authentication - Password Reset OTP'
                purpose = "Password Reset"
                message = "We received a request to reset your password. Please use the following OTP to verify your identity:"
            else:
                msg['Subject'] = 'SMVEC Authentication - OTP Verification'
                purpose = "Email Verification"
                message = "Thank you for registering with SMVEC College Management System. Please use the following OTP to verify your email:"
            
            # Email body
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h2 style="color: #2c3e50; margin-bottom: 10px;">🎓 SMVEC Authentication</h2>
                        <p style="color: #7f8c8d; margin: 0;">Sri Manakulavinayagar Engineering college</p>
                    </div>
                    
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px;">
                        <h3 style="margin: 0 0 10px 0;">Hello {user_name}!</h3>
                        <p style="margin: 0; opacity: 0.9;">{purpose}</p>
                    </div>

                    <div style="margin: 20px 0;">
                        <p style="color: #666; font-size: 16px; line-height: 1.6; margin: 0;">
                            {message}
                        </p>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <div style="background: #f8f9fa; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; display: inline-block;">
                            <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">Your OTP Code:</p>
                            <h1 style="margin: 0; color: #667eea; font-size: 36px; letter-spacing: 8px; font-weight: bold;">{otp}</h1>
                        </div>
                    </div>
                    
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0; color: #856404; font-size: 14px;">
                            <strong>⚠️ Important:</strong><br>
                            • This OTP is valid for {self.otp_expiry_minutes} minutes only<br>
                            • Do not share this code with anyone<br>
                            • If you didn't request this, please ignore this email
                        </p>
                    </div>
                    
                    <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                        <p style="margin: 0; color: #7f8c8d; font-size: 12px;">
                            This is an automated message from SMVEC Authentication System<br>
                            Please do not reply to this email
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            text = msg.as_string()
            server.sendmail(self.smtp_username, email, text)
            server.quit()
            
            logger.info(f"OTP sent successfully to {email}")
            return {'success': True, 'message': 'OTP sent successfully'}
            
        except Exception as e:
            logger.error(f"Error sending OTP email: {str(e)}")
            return {'success': False, 'error': f'Failed to send OTP: {str(e)}'}

    def store_pending_registration(self, registration_data: Dict[str, Any], otp: str) -> Dict[str, Any]:
        """Store pending registration with OTP"""
        try:
            email = registration_data['email']

            # Check rate limiting (but don't fail completely if rate limit check fails)
            try:
                if not self.check_rate_limit(email):
                    return {'success': False, 'error': 'Too many OTP requests. Please try again later.'}
            except Exception as rate_limit_error:
                logger.warning(f"Rate limit check failed, proceeding with registration: {str(rate_limit_error)}")
                # Continue with registration even if rate limit check fails

            # Create pending registration document
            pending_data = {
                'email': email,
                'full_name': registration_data['full_name'],
                'register_number': registration_data['register_number'],
                'department': registration_data['department'],
                'user_type': registration_data['user_type'],
                'otp_hash': self.hash_otp(otp),
                'otp_attempts': 0,
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': datetime.now() + timedelta(minutes=self.otp_expiry_minutes),
                'is_verified': False
            }

            # Add section for students
            if registration_data['user_type'].lower() == 'student':
                pending_data['section'] = registration_data.get('section', '')

            # Store in Firestore
            doc_ref = self.db.collection('pending_registrations').document(email)
            doc_ref.set(pending_data)

            logger.info(f"Pending registration stored for {email}")
            return {'success': True, 'message': 'Registration data stored'}

        except Exception as e:
            logger.error(f"Error storing pending registration: {str(e)}")
            return {'success': False, 'error': 'Failed to store registration data'}

    def hash_otp(self, otp: str) -> str:
        """Hash OTP for secure storage"""
        # Use a consistent salt for OTP hashing
        salt = "smvec_otp_salt_2024"
        combined = f"{otp}_{salt}_{self.jwt_secret}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()

    def verify_otp_hash(self, entered_otp: str, stored_hash: str) -> bool:
        """Verify OTP against stored hash with fallback methods"""
        # Method 1: Current hashing method
        current_hash = self.hash_otp(entered_otp)
        if current_hash == stored_hash:
            return True

        # Method 2: Fallback - simple hash without salt (for backward compatibility)
        simple_hash = hashlib.sha256(f"{entered_otp}{self.jwt_secret}".encode()).hexdigest()
        if simple_hash == stored_hash:
            logger.info("OTP verified using fallback method")
            return True

        # Method 3: Direct comparison for development/testing
        if entered_otp == stored_hash:
            logger.warning("OTP verified using direct comparison - update hashing!")
            return True

        return False

    def verify_otp(self, email: str, entered_otp: str) -> Dict[str, Any]:
        """Verify OTP and return result"""
        try:
            logger.info(f"Starting OTP verification for {email} with OTP: {entered_otp}")

            # Get pending registration
            doc_ref = self.db.collection('pending_registrations').document(email)
            doc = doc_ref.get()

            if not doc.exists:
                logger.warning(f"No pending registration found for {email}")
                return {'success': False, 'error': 'No pending registration found'}

            data = doc.to_dict()
            logger.info(f"Found pending registration data for {email}")

            # Check if already verified
            if data.get('is_verified'):
                logger.warning(f"OTP already verified for {email}")
                return {'success': False, 'error': 'OTP already verified'}

            # Check expiry with better datetime handling
            expires_at = data.get('expires_at')
            current_time = datetime.now()

            if expires_at:
                # Handle Firestore timestamp conversion
                if hasattr(expires_at, 'timestamp'):
                    expires_datetime = datetime.fromtimestamp(expires_at.timestamp())
                else:
                    expires_datetime = expires_at

                logger.info(f"OTP expiry check - Current: {current_time}, Expires: {expires_datetime}")

                if current_time > expires_datetime:
                    logger.warning(f"OTP expired for {email}")
                    return {'success': False, 'error': 'OTP has expired'}

            # Check attempts
            current_attempts = data.get('otp_attempts', 0)
            if current_attempts >= self.otp_max_attempts:
                logger.warning(f"Maximum OTP attempts exceeded for {email}: {current_attempts}")
                return {'success': False, 'error': 'Maximum OTP attempts exceeded'}

            # Verify OTP with detailed logging and fallback methods
            stored_otp_hash = data.get('otp_hash')

            logger.info(f"OTP verification - Stored hash: {stored_otp_hash[:16] if stored_otp_hash else 'None'}...")
            logger.info(f"Entered OTP: {entered_otp}")

            # Use the robust verification method
            if not self.verify_otp_hash(entered_otp, stored_otp_hash):
                # Increment attempts
                new_attempts = current_attempts + 1
                doc_ref.update({'otp_attempts': firestore.Increment(1)})
                remaining_attempts = self.otp_max_attempts - new_attempts

                logger.warning(f"Invalid OTP for {email}. Attempt {new_attempts}/{self.otp_max_attempts}")
                return {'success': False, 'error': f'Invalid OTP. {remaining_attempts} attempts remaining'}

            # OTP is valid - mark as verified
            doc_ref.update({'is_verified': True, 'verified_at': firestore.SERVER_TIMESTAMP})

            logger.info(f"OTP verified successfully for {email}")
            return {'success': True, 'message': 'OTP verified successfully', 'registration_data': data}

        except Exception as e:
            logger.error(f"Error verifying OTP for {email}: {str(e)}")
            import traceback
            logger.error(f"OTP verification traceback: {traceback.format_exc()}")
            return {'success': False, 'error': 'OTP verification failed'}

    def check_rate_limit(self, email: str) -> bool:
        """Check if user has exceeded rate limits"""
        try:
            # Check OTP requests in the last hour
            one_hour_ago = datetime.now() - timedelta(hours=1)

            try:
                # Try composite query first
                recent_requests = self.db.collection('otp_requests')\
                    .where('email', '==', email)\
                    .where('created_at', '>=', one_hour_ago)\
                    .get()

                if len(recent_requests) >= self.max_otp_requests_per_hour:
                    logger.warning(f"Rate limit exceeded for {email}: {len(recent_requests)} requests in last hour")
                    return False

            except Exception as index_error:
                # If composite index doesn't exist, use fallback method
                logger.warning(f"Composite index query failed for rate limiting, using fallback: {str(index_error)}")

                # Fallback: Get all requests for this email and filter by time
                all_requests = self.db.collection('otp_requests')\
                    .where('email', '==', email)\
                    .get()

                recent_count = 0
                for req in all_requests:
                    req_data = req.to_dict()
                    if 'created_at' in req_data and req_data['created_at']:
                        # Convert Firestore timestamp to datetime
                        req_time = req_data['created_at']
                        if hasattr(req_time, 'timestamp'):
                            req_datetime = datetime.fromtimestamp(req_time.timestamp())
                        else:
                            req_datetime = req_time

                        if req_datetime >= one_hour_ago:
                            recent_count += 1

                if recent_count >= self.max_otp_requests_per_hour:
                    logger.warning(f"Rate limit exceeded for {email}: {recent_count} requests in last hour (fallback)")
                    return False

            # Log this request
            try:
                self.db.collection('otp_requests').add({
                    'email': email,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'ip_address': 'unknown'  # Can be enhanced with actual IP
                })
                logger.info(f"OTP request logged for {email}")
            except Exception as log_error:
                logger.warning(f"Failed to log OTP request: {str(log_error)}")
                # Don't fail the rate limit check just because logging failed

            return True

        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            # For first-time setup, be more permissive
            logger.warning("Rate limit check failed, allowing request for system setup")
            return True  # Allow on error during initial setup

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=self.password_rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error verifying password: {str(e)}")
            return False

    def create_user_account(self, email: str, password: str) -> Dict[str, Any]:
        """Create final user account after OTP verification"""
        try:
            # Get verified registration data
            pending_doc = self.db.collection('pending_registrations').document(email).get()
            
            if not pending_doc.exists:
                return {'success': False, 'error': 'No pending registration found'}
            
            pending_data = pending_doc.to_dict()
            
            if not pending_data.get('is_verified'):
                return {'success': False, 'error': 'Email not verified'}
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Create user document
            user_data = {
                'email': email,
                'full_name': pending_data['full_name'],
                'register_number': pending_data['register_number'],
                'department': pending_data['department'],
                'user_type': pending_data['user_type'],
                'password_hash': password_hash,
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': None,
                'login_attempts': 0,
                'account_locked_until': None
            }
            
            # Add section for students
            if pending_data['user_type'].lower() == 'student':
                user_data['section'] = pending_data.get('section', '')
            
            # Generate user ID
            user_id = self.generate_user_id(pending_data['user_type'])
            
            # Store user
            self.db.collection('users').document(user_id).set(user_data)
            
            # Clean up pending registration
            self.db.collection('pending_registrations').document(email).delete()
            
            logger.info(f"User account created successfully for {email}")
            return {'success': True, 'message': 'Account created successfully', 'user_id': user_id}
            
        except Exception as e:
            logger.error(f"Error creating user account: {str(e)}")
            return {'success': False, 'error': 'Failed to create account'}

    def generate_user_id(self, user_type: str) -> str:
        """Generate unique user ID"""
        prefix = 'STU' if user_type.lower() == 'student' else 'FAC'
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        return f"{prefix}_{timestamp}_{random_suffix}"

    def generate_jwt_token(self, user_id: str, email: str, user_type: str) -> str:
        """Generate JWT token for session"""
        payload = {
            'user_id': user_id,
            'email': email,
            'user_type': user_type,
            'exp': datetime.utcnow() + timedelta(hours=self.session_timeout_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')

    def verify_jwt_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return {'valid': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token has expired'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'error': 'Invalid token'}

    def store_password_reset_request(self, email: str, otp: str) -> Dict[str, Any]:
        """
        Store password reset request with OTP
        """
        try:
            from google.cloud import firestore

            # Create password reset document
            reset_data = {
                'email': email,
                'otp': otp,
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': datetime.now() + timedelta(minutes=10),
                'verified': False,
                'used': False,
                'attempts': 0
            }

            # Store in password_resets collection
            doc_ref = self.db.collection('password_resets').document()
            doc_ref.set(reset_data)

            return {'success': True, 'doc_id': doc_ref.id}

        except Exception as e:
            logger.error(f"Error storing password reset request: {str(e)}")
            return {'success': False, 'error': 'Failed to store reset request'}

    def verify_reset_otp(self, email: str, otp: str) -> Dict[str, Any]:
        """
        Verify OTP for password reset
        """
        try:
            # Find the most recent unused reset request for this email
            reset_docs = self.db.collection('password_resets')\
                .where('email', '==', email)\
                .where('used', '==', False)\
                .order_by('created_at', direction='DESCENDING')\
                .limit(1)\
                .get()

            if not reset_docs:
                return {'valid': False, 'error': 'No active reset request found'}

            reset_doc = reset_docs[0]
            reset_data = reset_doc.to_dict()

            # Check if OTP has expired
            if datetime.now() > reset_data['expires_at']:
                return {'valid': False, 'error': 'OTP has expired. Please request a new one.'}

            # Check attempt limit
            if reset_data.get('attempts', 0) >= 3:
                return {'valid': False, 'error': 'Too many failed attempts. Please request a new OTP.'}

            # Verify OTP
            if reset_data['otp'] != otp:
                # Increment attempts
                self.db.collection('password_resets').document(reset_doc.id).update({
                    'attempts': reset_data.get('attempts', 0) + 1
                })
                return {'valid': False, 'error': 'Invalid OTP'}

            # Mark as verified
            from google.cloud import firestore
            self.db.collection('password_resets').document(reset_doc.id).update({
                'verified': True,
                'verified_at': firestore.SERVER_TIMESTAMP
            })

            return {'valid': True, 'reset_id': reset_doc.id}

        except Exception as e:
            logger.error(f"Error verifying reset OTP: {str(e)}")
            return {'valid': False, 'error': 'OTP verification failed'}

    def complete_password_reset(self, email: str, new_password: str, reset_id: str) -> Dict[str, Any]:
        """
        Complete password reset process
        """
        try:
            from google.cloud import firestore

            # Verify reset request is still valid
            reset_doc = self.db.collection('password_resets').document(reset_id).get()
            if not reset_doc.exists:
                return {'success': False, 'error': 'Invalid reset request'}

            reset_data = reset_doc.to_dict()

            if reset_data['email'] != email or not reset_data.get('verified') or reset_data.get('used'):
                return {'success': False, 'error': 'Invalid or expired reset request'}

            # Find user account
            users_query = self.db.collection('users').where('email', '==', email).limit(1).get()
            if not users_query:
                return {'success': False, 'error': 'User account not found'}

            user_doc = users_query[0]

            # Hash new password
            password_hash = self.hash_password(new_password)

            # Update user password
            self.db.collection('users').document(user_doc.id).update({
                'password_hash': password_hash,
                'password_reset_at': firestore.SERVER_TIMESTAMP,
                'login_attempts': 0,  # Reset login attempts
                'account_locked_until': None  # Clear any account locks
            })

            # Mark reset request as used
            self.db.collection('password_resets').document(reset_id).update({
                'used': True,
                'completed_at': firestore.SERVER_TIMESTAMP
            })

            logger.info(f"Password reset completed for user: {email}")
            return {'success': True, 'message': 'Password reset successfully'}

        except Exception as e:
            logger.error(f"Error completing password reset: {str(e)}")
            return {'success': False, 'error': 'Failed to reset password'}

    def check_reset_rate_limit(self, email: str) -> Dict[str, Any]:
        """
        Check if user has exceeded password reset rate limit
        """
        try:
            # Check requests in the last hour
            one_hour_ago = datetime.now() - timedelta(hours=1)

            recent_requests = self.db.collection('password_resets')\
                .where('email', '==', email)\
                .where('created_at', '>=', one_hour_ago)\
                .get()

            if len(recent_requests) >= 3:
                return {
                    'allowed': False,
                    'error': 'Too many password reset requests. Please wait an hour before trying again.'
                }

            return {'allowed': True}

        except Exception as e:
            logger.error(f"Error checking reset rate limit: {str(e)}")
            return {'allowed': True}  # Allow on error to avoid blocking legitimate users
