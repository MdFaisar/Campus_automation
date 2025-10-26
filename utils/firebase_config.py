import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import json
import logging

logger = logging.getLogger(__name__)

def initialize_firebase():
    """Initialize Firebase with proper error handling"""
    try:
        # Check if Firebase is already initialized
        if firebase_admin._apps:
            logger.info("Firebase already initialized")
            return firebase_admin.get_app()
        
        # Get config path from environment variable or use default
        config_path = os.environ.get('FIREBASE_CONFIG_PATH', 'config/firebase_config.json')
        
        # Check if config file exists
        if not os.path.exists(config_path):
            logger.error(f"Firebase config file not found at: {config_path}")
            raise FileNotFoundError(f"Firebase config file not found at: {config_path}")
        
        # Check if config file is not empty
        if os.path.getsize(config_path) == 0:
            logger.error(f"Firebase config file is empty: {config_path}")
            raise ValueError(f"Firebase config file is empty: {config_path}")
        
        # Try to load and validate JSON
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                
            # Validate required fields
            required_fields = ['type', 'project_id', 'private_key', 'client_email']
            missing_fields = [field for field in required_fields if field not in config_data]
            
            if missing_fields:
                logger.error(f"Missing required fields in Firebase config: {missing_fields}")
                raise ValueError(f"Missing required fields in Firebase config: {missing_fields}")
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in Firebase config file: {e}")
            raise ValueError(f"Invalid JSON in Firebase config file: {e}")
        
        # Initialize Firebase with credentials
        cred = credentials.Certificate(config_path)
        firebase_app = firebase_admin.initialize_app(cred)
        
        logger.info("Firebase initialized successfully")
        return firebase_app
        
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {str(e)}")
        raise

def get_firestore_client():
    """Get Firestore client with error handling"""
    try:
        return firestore.client()
    except Exception as e:
        logger.error(f"Failed to get Firestore client: {str(e)}")
        raise

def get_auth_client():
    """Get Firebase Auth client with error handling"""
    try:
        return auth
    except Exception as e:
        logger.error(f"Failed to get Auth client: {str(e)}")
        raise