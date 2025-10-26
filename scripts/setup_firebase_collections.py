"""
Setup Firebase collections for the complaint system
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.firebase_config import initialize_firebase, get_firestore_client
from firebase_admin import firestore
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_faculty_routing():
    """Setup faculty routing collection with sample data"""
    try:
        db = get_firestore_client()
        
        # Sample faculty data
        faculty_data = [
            {
                'faculty_id': 'FAC001',
                'faculty_name': 'Dr. John Smith',
                'department': 'Computer Science',
                'email': 'john.smith@university.edu',
                'specialization': 'Software Engineering',
                'total_complaints': 0,
                'pending_complaints': 0,
                'resolved_complaints': 0,
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP
            },
            {
                'faculty_id': 'FAC002',
                'faculty_name': 'Dr. Sarah Johnson',
                'department': 'Mathematics',
                'email': 'sarah.johnson@university.edu',
                'specialization': 'Applied Mathematics',
                'total_complaints': 0,
                'pending_complaints': 0,
                'resolved_complaints': 0,
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP
            },
            {
                'faculty_id': 'FAC003',
                'faculty_name': 'Prof. Michael Brown',
                'department': 'Physics',
                'email': 'michael.brown@university.edu',
                'specialization': 'Quantum Physics',
                'total_complaints': 0,
                'pending_complaints': 0,
                'resolved_complaints': 0,
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP
            },
            {
                'faculty_id': 'FAC004',
                'faculty_name': 'Dr. Emily Davis',
                'department': 'Chemistry',
                'email': 'emily.davis@university.edu',
                'specialization': 'Organic Chemistry',
                'total_complaints': 0,
                'pending_complaints': 0,
                'resolved_complaints': 0,
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP
            },
            {
                'faculty_id': 'FAC005',
                'faculty_name': 'Dr. Robert Wilson',
                'department': 'English Literature',
                'email': 'robert.wilson@university.edu',
                'specialization': 'Modern Literature',
                'total_complaints': 0,
                'pending_complaints': 0,
                'resolved_complaints': 0,
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP
            }
        ]
        
        # Add faculty to collection
        batch = db.batch()
        for faculty in faculty_data:
            faculty_id = faculty.pop('faculty_id')
            doc_ref = db.collection('faculty_routing').document(faculty_id)
            batch.set(doc_ref, faculty)
        
        batch.commit()
        logger.info(f"Added {len(faculty_data)} faculty members to faculty_routing collection")
        
    except Exception as e:
        logger.error(f"Error setting up faculty routing: {str(e)}")

def setup_complaint_categories():
    """Setup complaint categories collection"""
    try:
        db = get_firestore_client()
        
        categories = [
            {
                'category_id': 'academic',
                'name': 'Academic Issues',
                'description': 'Issues related to coursework, grading, or academic policies',
                'is_active': True
            },
            {
                'category_id': 'infrastructure',
                'name': 'Infrastructure',
                'description': 'Issues with facilities, equipment, or campus infrastructure',
                'is_active': True
            },
            {
                'category_id': 'harassment',
                'name': 'Harassment',
                'description': 'Reports of harassment or inappropriate behavior',
                'is_active': True,
                'priority': 'high'
            },
            {
                'category_id': 'discrimination',
                'name': 'Discrimination',
                'description': 'Reports of discrimination based on any grounds',
                'is_active': True,
                'priority': 'high'
            },
            {
                'category_id': 'administrative',
                'name': 'Administrative',
                'description': 'Issues with administrative processes or services',
                'is_active': True
            },
            {
                'category_id': 'general',
                'name': 'General',
                'description': 'General complaints or suggestions',
                'is_active': True
            }
        ]
        
        batch = db.batch()
        for category in categories:
            category_id = category.pop('category_id')
            doc_ref = db.collection('complaint_categories').document(category_id)
            batch.set(doc_ref, category)
        
        batch.commit()
        logger.info(f"Added {len(categories)} categories to complaint_categories collection")
        
    except Exception as e:
        logger.error(f"Error setting up complaint categories: {str(e)}")

def setup_system_config():
    """Setup system configuration"""
    try:
        db = get_firestore_client()
        
        config = {
            'daily_complaint_limit': 1,
            'max_complaint_length': 2000,
            'auto_assign_complaints': True,
            'email_notifications': True,
            'blockchain_enabled': True,
            'encryption_enabled': True,
            'system_version': '1.0.0',
            'last_updated': firestore.SERVER_TIMESTAMP
        }
        
        db.collection('system_config').document('complaint_system').set(config)
        logger.info("System configuration created")
        
    except Exception as e:
        logger.error(f"Error setting up system config: {str(e)}")

def create_indexes():
    """Create necessary indexes (Note: These need to be created in Firebase Console)"""
    logger.info("Creating indexes...")
    
    indexes_info = """
    Please create the following indexes in Firebase Console:
    
    Collection: complaints
    - faculty_id (Ascending), is_active (Ascending), created_at (Descending)
    - status (Ascending), created_at (Descending)
    - hashed_student_id (Ascending), created_at (Descending)
    
    Collection: complaint_users
    - last_complaint_date (Ascending)
    
    Collection: faculty_routing
    - department (Ascending), is_active (Ascending)
    """
    
    logger.info(indexes_info)

def setup_security_rules():
    """Display security rules that should be applied"""
    security_rules = """
    Please apply the following security rules in Firebase Console:
    
    rules_version = '2';
    service cloud.firestore {
      match /databases/{database}/documents {
        // Complaints collection - read/write for authenticated users only
        match /complaints/{complaintId} {
          allow read, write: if request.auth != null;
        }
        
        // Faculty routing - read for authenticated users
        match /faculty_routing/{facultyId} {
          allow read: if request.auth != null;
          allow write: if request.auth != null && 
                      request.auth.token.user_type == 'admin';
        }
        
        // Complaint users - read/write for authenticated users only
        match /complaint_users/{userId} {
          allow read, write: if request.auth != null;
        }
        
        // Complaint categories - read for all authenticated users
        match /complaint_categories/{categoryId} {
          allow read: if request.auth != null;
          allow write: if request.auth != null && 
                      request.auth.token.user_type == 'admin';
        }
        
        // System config - read for authenticated users, write for admin only
        match /system_config/{configId} {
          allow read: if request.auth != null;
          allow write: if request.auth != null && 
                      request.auth.token.user_type == 'admin';
        }
      }
    }
    """
    
    logger.info("Security Rules:")
    logger.info(security_rules)

def main():
    """Main setup function"""
    try:
        logger.info("Starting Firebase collections setup...")
        
        # Initialize Firebase
        firebase_app = initialize_firebase()
        logger.info("Firebase initialized")
        
        # Setup collections
        setup_faculty_routing()
        setup_complaint_categories()
        setup_system_config()
        
        # Display additional setup instructions
        create_indexes()
        setup_security_rules()
        
        logger.info("Firebase collections setup completed!")
        logger.info("Don't forget to:")
        logger.info("1. Create the indexes mentioned above in Firebase Console")
        logger.info("2. Apply the security rules in Firebase Console")
        logger.info("3. Test the complaint system functionality")
        
    except Exception as e:
        logger.error(f"Setup error: {str(e)}")

if __name__ == "__main__":
    main()
