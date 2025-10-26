from firebase_admin import auth, firestore
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import requests
import json
import os
from datetime import datetime
from .firebase_config import get_firestore_client, get_auth_client

logger = logging.getLogger(__name__)

# Get Firebase Web API Key from environment variables
FIREBASE_WEB_API_KEY = os.getenv('FIREBASE_WEB_API_KEY')

def create_user(user_data):
    """Create a new user in Firebase Auth and Firestore"""
    try:
        db = get_firestore_client()
        auth_client = get_auth_client()
        
        # Create user in Firebase Auth
        user_record = auth_client.create_user(
            email=user_data['email'],
            password=user_data['password'],
            display_name=user_data['full_name']
        )
        
        # Prepare user document for Firestore
        user_doc = {
            'uid': user_record.uid,
            'email': user_data['email'],
            'full_name': user_data['full_name'],
            'user_type': user_data['user_type'],
            'created_at': datetime.now(),
            'is_active': True
        }
        
        # Add role-specific fields
        if user_data['user_type'] == 'student':
            user_doc.update({
                'student_id': user_data['student_id'],
                'section': user_data['section']
            })
        elif user_data['user_type'] == 'faculty':
            user_doc.update({
                'employee_id': user_data['employee_id'],
                'department': user_data['department']
            })

            # Also add to faculty_routing collection for complaint system
            faculty_routing_data = {
                'faculty_name': user_data['full_name'],
                'department': user_data['department'],
                'email': user_data['email'],
                'employee_id': user_data['employee_id'],
                'specialization': user_data.get('specialization', ''),
                'total_complaints': 0,
                'pending_complaints': 0,
                'resolved_complaints': 0,
                'is_active': True,
                'created_at': datetime.now(),
                'auto_created': True
            }
            db.collection('faculty_routing').document(user_record.uid).set(faculty_routing_data)
        elif user_data['user_type'] == 'admin':
            # Validate admin code (you should implement proper validation)
            if user_data.get('admin_code') != 'ADMIN2024':
                raise ValueError("Invalid admin code")
            user_doc.update({
                'admin_level': 'system'
            })
        
        # Save user document to Firestore
        db.collection('users').document(user_record.uid).set(user_doc)
        
        logger.info(f"User created successfully: {user_data['email']}")
        return {'uid': user_record.uid, **user_doc}
        
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return None

def verify_password_with_firebase_auth(email, password):
    """Verify email and password using Firebase Auth REST API"""
    try:
        if not FIREBASE_WEB_API_KEY:
            logger.error("FIREBASE_WEB_API_KEY not found in environment variables")
            return None
            
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
        
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        response = requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            result = response.json()
            return result.get('localId')  # This is the user's UID
        else:
            logger.warning(f"Password verification failed for {email}: {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error verifying password: {str(e)}")
        return None

def authenticate_user(email, password, user_type):
    """Authenticate user with email and password"""
    try:
        db = get_firestore_client()
        
        # First verify email and password with Firebase Auth
        user_uid = verify_password_with_firebase_auth(email, password)
        
        if not user_uid:
            logger.warning(f"Invalid credentials for: {email}")
            return None
        
        # Get user document from Firestore
        user_doc = db.collection('users').document(user_uid).get()
        
        if not user_doc.exists:
            logger.warning(f"User document not found for: {email}")
            return None
        
        user_data = user_doc.to_dict()
        
        # Verify user type matches
        if user_data.get('user_type') != user_type:
            logger.warning(f"User type mismatch for: {email}")
            return None
        
        # Check if user is active
        if not user_data.get('is_active', True):
            logger.warning(f"Inactive user attempted login: {email}")
            return None
        
        # Update last login
        db.collection('users').document(user_uid).update({
            'last_login': datetime.now()
        })
        
        logger.info(f"User authenticated successfully: {email}")
        return {'uid': user_uid, **user_data}
        
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return None

def get_user_role(user_id):
    """Get user role by user ID"""
    try:
        db = get_firestore_client()
        user_doc = db.collection('users').document(user_id).get()
        
        if user_doc.exists:
            return user_doc.to_dict().get('user_type')
        return None
        
    except Exception as e:
        logger.error(f"Error getting user role: {str(e)}")
        return None

def get_user_data(user_id):
    """Get complete user data by user ID"""
    try:
        db = get_firestore_client()
        user_doc = db.collection('users').document(user_id).get()
        
        if user_doc.exists:
            return user_doc.to_dict()
        return None
        
    except Exception as e:
        logger.error(f"Error getting user data: {str(e)}")
        return None

def update_user_profile(user_id, update_data):
    """Update user profile data"""
    try:
        db = get_firestore_client()
        
        # Add updated timestamp
        update_data['updated_at'] = datetime.now()
        
        # Update user document
        db.collection('users').document(user_id).update(update_data)
        
        logger.info(f"User profile updated: {user_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error updating user profile: {str(e)}")
        return False

def deactivate_user(user_id):
    """Deactivate user account"""
    try:
        db = get_firestore_client()
        auth_client = get_auth_client()
        
        # Disable user in Firebase Auth
        auth_client.update_user(user_id, disabled=True)
        
        # Update user document
        db.collection('users').document(user_id).update({
            'is_active': False,
            'deactivated_at': datetime.now()
        })
        
        logger.info(f"User deactivated: {user_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error deactivating user: {str(e)}")
        return False
