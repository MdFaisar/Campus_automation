"""
Complaint management system with Firebase integration
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from firebase_admin import firestore
from .firebase_config import get_firestore_client
from .blockchain_config import get_blockchain_config
import secrets
import base64

logger = logging.getLogger(__name__)

class ComplaintManager:
    """Manages complaint submission and retrieval with Firebase and blockchain integration"""
    
    def __init__(self):
        """Initialize complaint manager"""
        self.db = get_firestore_client()
        self.blockchain = get_blockchain_config()
        self._initialize_collections()
    
    def _initialize_collections(self):
        """Initialize Firebase collections with proper structure"""
        try:
            # Create indexes and initial data if needed
            logger.info("Complaint manager initialized")
        except Exception as e:
            logger.error(f"Error initializing complaint manager: {str(e)}")
    
    def hash_student_id(self, student_id: str) -> str:
        """Create anonymous hash of student ID for daily tracking"""
        salt = os.getenv('STUDENT_ID_SALT', 'default_salt_change_in_production')
        today = datetime.now().strftime('%Y-%m-%d')
        combined = f"{student_id}:{salt}:{today}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def encrypt_complaint_content(self, content: str) -> Dict[str, str]:
        """Encrypt complaint content for storage"""
        try:
            # Generate a random key for this complaint
            key = secrets.token_bytes(32)
            
            # Simple XOR encryption (in production, use proper encryption like AES)
            content_bytes = content.encode('utf-8')
            encrypted_bytes = bytes(a ^ b for a, b in zip(content_bytes, (key * (len(content_bytes) // len(key) + 1))[:len(content_bytes)]))
            
            return {
                'encrypted_content': base64.b64encode(encrypted_bytes).decode('utf-8'),
                'encryption_key': base64.b64encode(key).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Error encrypting content: {str(e)}")
            return {'encrypted_content': content, 'encryption_key': ''}
    
    def decrypt_complaint_content(self, encrypted_data: Dict[str, str]) -> str:
        """Decrypt complaint content"""
        try:
            if not encrypted_data.get('encryption_key'):
                return encrypted_data.get('encrypted_content', '')
            
            encrypted_bytes = base64.b64decode(encrypted_data['encrypted_content'])
            key = base64.b64decode(encrypted_data['encryption_key'])
            
            # Decrypt using XOR
            decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, (key * (len(encrypted_bytes) // len(key) + 1))[:len(encrypted_bytes)]))
            
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting content: {str(e)}")
            return encrypted_data.get('encrypted_content', '')
    
    def check_daily_limit(self, student_id: str) -> Dict[str, Any]:
        """Check if student can submit complaint today"""
        try:
            hashed_student_id = self.hash_student_id(student_id)
            today = datetime.now().strftime('%Y-%m-%d')
            
            # Check Firebase for daily submission
            user_doc = self.db.collection('complaint_users').document(hashed_student_id).get()
            
            if user_doc.exists:
                user_data = user_doc.to_dict()
                last_complaint_date = user_data.get('last_complaint_date')
                
                if last_complaint_date == today:
                    return {
                        'can_submit': False,
                        'reason': 'Daily limit exceeded. You can only submit one complaint per day.',
                        'next_allowed': (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
                    }
            
            # Check blockchain for additional verification
            if self.blockchain.is_ready():
                blockchain_check = self.blockchain.check_daily_limit(hashed_student_id)
                if not blockchain_check:
                    return {
                        'can_submit': False,
                        'reason': 'Daily limit exceeded according to blockchain records.',
                        'next_allowed': (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
                    }
            
            return {'can_submit': True, 'reason': 'Can submit complaint'}
            
        except Exception as e:
            logger.error(f"Error checking daily limit: {str(e)}")
            return {'can_submit': False, 'reason': 'Error checking daily limit'}
    
    def submit_complaint(self, student_id: str, complaint_text: str, faculty_id: str, 
                        category: str = 'general', priority: str = 'medium') -> Dict[str, Any]:
        """Submit a new complaint"""
        try:
            # Check daily limit
            limit_check = self.check_daily_limit(student_id)
            if not limit_check['can_submit']:
                return {'success': False, 'error': limit_check['reason']}
            
            # Validate inputs
            if not complaint_text.strip():
                return {'success': False, 'error': 'Complaint text cannot be empty'}
            
            if not faculty_id.strip():
                return {'success': False, 'error': 'Faculty ID is required'}
            
            # Verify faculty exists
            faculty_doc = self.db.collection('faculty_routing').document(faculty_id).get()
            if not faculty_doc.exists:
                return {'success': False, 'error': 'Invalid faculty ID'}
            
            # Generate IDs and hashes
            hashed_student_id = self.hash_student_id(student_id)
            complaint_id = self.db.collection('complaints').document().id
            
            # Encrypt complaint content
            encrypted_data = self.encrypt_complaint_content(complaint_text)
            
            # Create complaint hash for blockchain
            complaint_hash = hashlib.sha256(complaint_text.encode()).hexdigest()
            
            # Prepare complaint data
            complaint_data = {
                'complaint_id': complaint_id,
                'hashed_student_id': hashed_student_id,
                'faculty_id': faculty_id,
                'category': category,
                'priority': priority,
                'encrypted_content': encrypted_data['encrypted_content'],
                'encryption_key': encrypted_data['encryption_key'],
                'complaint_hash': complaint_hash,
                'status': 'submitted',
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP,
                'is_active': True,
                'blockchain_tx_hash': None
            }
            
            # Submit to blockchain first
            tx_hash = None
            if self.blockchain.is_ready():
                tx_hash = self.blockchain.submit_complaint_to_blockchain(
                    hashed_student_id, complaint_hash, faculty_id
                )
                if tx_hash:
                    complaint_data['blockchain_tx_hash'] = tx_hash
                    complaint_data['blockchain_status'] = 'confirmed'
                else:
                    complaint_data['blockchain_status'] = 'failed'
                    logger.warning("Blockchain submission failed, proceeding with Firebase only")
            
            # Save to Firebase
            batch = self.db.batch()
            
            # Save complaint
            complaint_ref = self.db.collection('complaints').document(complaint_id)
            batch.set(complaint_ref, complaint_data)
            
            # Update user's last complaint date
            user_ref = self.db.collection('complaint_users').document(hashed_student_id)
            user_data = {
                'hashed_student_id': hashed_student_id,
                'last_complaint_date': datetime.now().strftime('%Y-%m-%d'),
                'total_complaints': firestore.Increment(1),
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            batch.set(user_ref, user_data, merge=True)
            
            # Update faculty complaint count
            faculty_ref = self.db.collection('faculty_routing').document(faculty_id)
            batch.update(faculty_ref, {
                'total_complaints': firestore.Increment(1),
                'pending_complaints': firestore.Increment(1),
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Commit batch
            batch.commit()
            
            logger.info(f"Complaint submitted successfully. ID: {complaint_id}")
            
            return {
                'success': True,
                'complaint_id': complaint_id,
                'blockchain_tx_hash': tx_hash,
                'message': 'Complaint submitted successfully'
            }
            
        except Exception as e:
            logger.error(f"Error submitting complaint: {str(e)}")
            return {'success': False, 'error': 'Failed to submit complaint'}
    
    def get_faculty_complaints(self, faculty_id: str, status: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get complaints for a specific faculty member"""
        try:
            # Try the optimized query first (requires composite index)
            try:
                # Build query
                query = self.db.collection('complaints').where('faculty_id', '==', faculty_id)

                if status:
                    query = query.where('status', '==', status)

                query = query.where('is_active', '==', True)
                query = query.order_by('created_at', direction=firestore.Query.DESCENDING)
                query = query.limit(limit)

                # Execute query
                docs = query.get()

            except Exception as index_error:
                logger.warning(f"Composite index query failed, using fallback: {str(index_error)}")

                # Fallback: Use simpler query and filter in Python
                query = self.db.collection('complaints').where('faculty_id', '==', faculty_id)
                docs = query.get()

                # Filter and sort in Python
                filtered_docs = []
                for doc in docs:
                    data = doc.to_dict()
                    # Apply filters
                    if status and data.get('status') != status:
                        continue
                    if not data.get('is_active', True):
                        continue
                    filtered_docs.append(doc)

                # Sort by created_at (newest first)
                filtered_docs.sort(key=lambda x: x.to_dict().get('created_at', 0), reverse=True)

                # Apply limit
                docs = filtered_docs[:limit]

            complaints = []
            for doc in docs:
                complaint_data = doc.to_dict()
                complaint_data['complaint_id'] = doc.id  # Ensure complaint_id is set

                # Decrypt content for faculty view
                if complaint_data.get('encrypted_content'):
                    try:
                        decrypted_content = self.decrypt_complaint_content({
                            'encrypted_content': complaint_data['encrypted_content'],
                            'encryption_key': complaint_data['encryption_key']
                        })
                        complaint_data['complaint_text'] = decrypted_content
                    except Exception as decrypt_error:
                        logger.warning(f"Failed to decrypt complaint content: {str(decrypt_error)}")
                        complaint_data['complaint_text'] = "[Content could not be decrypted]"

                # Remove sensitive data
                complaint_data.pop('encryption_key', None)
                complaint_data.pop('encrypted_content', None)
                complaint_data.pop('hashed_student_id', None)

                complaints.append(complaint_data)

            logger.info(f"Retrieved {len(complaints)} complaints for faculty {faculty_id}")
            return complaints

        except Exception as e:
            logger.error(f"Error getting faculty complaints: {str(e)}")
            return []

    def get_student_complaints(self, student_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get complaints for a specific student"""
        try:
            # Hash the student ID to match the stored format
            hashed_student_id = self.hash_student_id(student_id)

            # Try the optimized query first (requires composite index)
            try:
                query = self.db.collection('complaints').where('hashed_student_id', '==', hashed_student_id)
                query = query.where('is_active', '==', True)
                query = query.order_by('created_at', direction=firestore.Query.DESCENDING)
                query = query.limit(limit)

                docs = query.get()

            except Exception as index_error:
                logger.warning(f"Composite index query failed for student complaints, using fallback: {str(index_error)}")

                # Fallback: Use simpler query and filter in Python
                query = self.db.collection('complaints').where('hashed_student_id', '==', hashed_student_id)
                docs = query.get()

                # Filter and sort in Python
                filtered_docs = []
                for doc in docs:
                    data = doc.to_dict()
                    if not data.get('is_active', True):
                        continue
                    filtered_docs.append(doc)

                # Sort by created_at (newest first)
                filtered_docs.sort(key=lambda x: x.to_dict().get('created_at', 0), reverse=True)

                # Apply limit
                docs = filtered_docs[:limit]

            complaints = []
            for doc in docs:
                complaint_data = doc.to_dict()
                complaint_data['complaint_id'] = doc.id  # Ensure complaint_id is set

                # Decrypt content for student view
                if complaint_data.get('encrypted_content'):
                    try:
                        decrypted_content = self.decrypt_complaint_content({
                            'encrypted_content': complaint_data['encrypted_content'],
                            'encryption_key': complaint_data['encryption_key']
                        })
                        complaint_data['complaint_text'] = decrypted_content
                    except Exception as decrypt_error:
                        logger.warning(f"Failed to decrypt complaint content: {str(decrypt_error)}")
                        complaint_data['complaint_text'] = "[Content could not be decrypted]"

                # Remove sensitive data but keep some for student view
                complaint_data.pop('encryption_key', None)
                complaint_data.pop('encrypted_content', None)
                complaint_data.pop('hashed_student_id', None)

                complaints.append(complaint_data)

            logger.info(f"Retrieved {len(complaints)} complaints for student {student_id}")
            return complaints

        except Exception as e:
            logger.error(f"Error getting student complaints: {str(e)}")
            return []
    
    def update_complaint_status(self, complaint_id: str, new_status: str, faculty_response: str = None) -> Dict[str, Any]:
        """Update complaint status"""
        try:
            # Verify complaint exists
            complaint_ref = self.db.collection('complaints').document(complaint_id)
            complaint_doc = complaint_ref.get()

            if not complaint_doc.exists:
                return {'success': False, 'error': 'Complaint not found'}

            complaint_data = complaint_doc.to_dict()
            faculty_id = complaint_data.get('faculty_id')

            # Prepare update data
            update_data = {
                'status': new_status,
                'updated_at': firestore.SERVER_TIMESTAMP
            }

            if faculty_response:
                # Store response as plain text (already encrypted at storage level if needed)
                update_data['faculty_response'] = faculty_response
                update_data['response_date'] = firestore.SERVER_TIMESTAMP

            # Update complaint
            complaint_ref.update(update_data)

            # Update faculty stats if status changed to resolved
            if new_status == 'resolved' and faculty_id:
                faculty_ref = self.db.collection('faculty_routing').document(faculty_id)
                faculty_ref.update({
                    'pending_complaints': firestore.Increment(-1),
                    'resolved_complaints': firestore.Increment(1),
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
            
            return {'success': True, 'message': 'Complaint status updated successfully'}
            
        except Exception as e:
            logger.error(f"Error updating complaint status: {str(e)}")
            return {'success': False, 'error': 'Failed to update complaint status'}
    
    def sync_faculty_from_users(self):
        """Sync faculty from users collection to faculty_routing collection"""
        try:
            # Get all faculty users
            faculty_users = self.db.collection('users').where('user_type', '==', 'faculty').get()

            batch = self.db.batch()
            synced_count = 0

            for user_doc in faculty_users:
                user_data = user_doc.to_dict()
                faculty_id = user_doc.id

                # Check if faculty already exists in faculty_routing
                faculty_routing_doc = self.db.collection('faculty_routing').document(faculty_id).get()

                if not faculty_routing_doc.exists:
                    # Create faculty routing entry
                    faculty_routing_data = {
                        'faculty_name': user_data.get('full_name', 'Unknown Faculty'),
                        'department': user_data.get('department', 'Unknown Department'),
                        'email': user_data.get('email', ''),
                        'employee_id': user_data.get('employee_id', ''),
                        'specialization': user_data.get('specialization', ''),
                        'total_complaints': 0,
                        'pending_complaints': 0,
                        'resolved_complaints': 0,
                        'is_active': user_data.get('is_active', True),
                        'created_at': user_data.get('created_at'),
                        'synced_from_users': True
                    }

                    doc_ref = self.db.collection('faculty_routing').document(faculty_id)
                    batch.set(doc_ref, faculty_routing_data)
                    synced_count += 1

            if synced_count > 0:
                batch.commit()
                logger.info(f"Synced {synced_count} faculty members to faculty_routing collection")

            return synced_count

        except Exception as e:
            logger.error(f"Error syncing faculty from users: {str(e)}")
            return 0

    def get_faculty_list(self) -> List[Dict[str, Any]]:
        """Get list of available faculty for complaint routing"""
        try:
            # First, sync faculty from users collection
            self.sync_faculty_from_users()

            # Get faculty from faculty_routing collection
            docs = self.db.collection('faculty_routing').where('is_active', '==', True).get()

            faculty_list = []
            for doc in docs:
                faculty_data = doc.to_dict()
                faculty_data['faculty_id'] = doc.id

                # Ensure required fields exist
                if not faculty_data.get('faculty_name'):
                    faculty_data['faculty_name'] = 'Unknown Faculty'
                if not faculty_data.get('department'):
                    faculty_data['department'] = 'Unknown Department'

                faculty_list.append(faculty_data)

            # Sort by faculty name
            faculty_list.sort(key=lambda x: x.get('faculty_name', ''))

            logger.info(f"Retrieved {len(faculty_list)} active faculty members")
            return faculty_list

        except Exception as e:
            logger.error(f"Error getting faculty list: {str(e)}")
            return []

# Global instance
_complaint_manager = None

def get_complaint_manager():
    """Get the global complaint manager instance"""
    global _complaint_manager
    if _complaint_manager is None:
        _complaint_manager = ComplaintManager()
    return _complaint_manager
