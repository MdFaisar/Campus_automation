import requests
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class N8NEmailAutomation:
    def __init__(self):
        """Initialize n8n email automation"""
        self.webhook_url = os.environ.get('N8N_WEBHOOK_URL')
        self._db = None  # Initialize as None, will be set lazily
        
        if not self.webhook_url:
            logger.warning("N8N_WEBHOOK_URL not configured")
    
    @property
    def db(self):
        """Lazy initialization of Firestore client"""
        if self._db is None:
            try:
                from .firebase_config import get_firestore_client
                self._db = get_firestore_client()
            except Exception as e:
                logger.error(f"Failed to initialize Firestore client: {str(e)}")
                self._db = None
        return self._db
    
    def send_notification(self, recipient: str, subject: str, message: str, 
                         notification_type: str = "general", **kwargs) -> bool:
        """Send email notification via n8n webhook"""
        try:
            if not self.webhook_url:
                logger.error("N8N webhook URL not configured")
                return False
            
            # Prepare payload
            payload = {
                "recipient": recipient,
                "subject": subject,
                "message": message,
                "notification_type": notification_type,
                "timestamp": datetime.now().isoformat(),
                "metadata": kwargs
            }
            
            # Send to n8n webhook
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Email notification sent successfully to {recipient}")
                
                # Log notification
                self._log_notification(payload)
                return True
            else:
                logger.error(f"Failed to send email notification: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
            return False
    
    def _log_notification(self, payload: Dict):
        """Log notification to Firestore"""
        try:
            if self.db is None:
                logger.warning("Firestore client not available, skipping notification logging")
                return
                
            notification_log = {
                'recipient': payload['recipient'],
                'subject': payload['subject'],
                'notification_type': payload['notification_type'],
                'timestamp': datetime.now(),
                'status': 'sent'
            }
            self.db.collection('notification_logs').add(notification_log)
        except Exception as e:
            logger.error(f"Error logging notification: {str(e)}")
    
    def send_welcome_email(self, user_data: Dict) -> bool:
        """Send welcome email to new user"""
        subject = "Welcome to College Management System"
        message = f"""
        Dear {user_data['full_name']},

        Welcome to the College Management System! Your account has been created successfully.

        Account Details:
        - Email: {user_data['email']}
        - User Type: {user_data['user_type'].title()}
        - Registration Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

        You can now access the system and explore the following features:
        """
        
        # Add role-specific features
        if user_data['user_type'] == 'student':
            message += """
        - AI Notes Bot for studying
        - View your class schedule
        - Check exam seating arrangements
        - Submit complaints anonymously
        """
        elif user_data['user_type'] == 'faculty':
            message += """
        - Upload notes for students
        - Manage room allocations
        - View student information
        - Schedule classes
        """
        elif user_data['user_type'] == 'admin':
            message += """
        - Manage users and roles
        - Room management
        - Handle complaints
        - Generate system reports
        """
        
        message += """
        If you have any questions or need assistance, please don't hesitate to contact our support team.

        Best regards,
        College Management System Team
        """
        
        return self.send_notification(
            recipient=user_data['email'],
            subject=subject,
            message=message,
            notification_type="welcome",
            user_type=user_data['user_type']
        )
    
    def send_schedule_update(self, recipients: List[str], schedule_data: Dict) -> bool:
        """Send schedule update notification"""
        subject = "Schedule Update Notification"
        message = f"""
        Dear Student/Faculty,

        There has been an update to the class schedule:

        Course: {schedule_data.get('course', 'N/A')}
        Date: {schedule_data.get('date', 'N/A')}
        Time: {schedule_data.get('time', 'N/A')}
        Room: {schedule_data.get('room', 'N/A')}
        Type: {schedule_data.get('type', 'Class')}

        Please check your dashboard for complete details.

        Best regards,
        College Management System
        """
        
        success_count = 0
        for recipient in recipients:
            if self.send_notification(
                recipient=recipient,
                subject=subject,
                message=message,
                notification_type="schedule_update",
                schedule_data=schedule_data
            ):
                success_count += 1
        
        return success_count == len(recipients)
    
    def send_exam_notification(self, recipient: str, exam_data: Dict) -> bool:
        """Send exam seating notification"""
        subject = "Exam Seating Arrangement"
        message = f"""
        Dear {exam_data.get('student_name', 'Student')},

        Your exam seating arrangement has been confirmed:

        Exam: {exam_data.get('exam_name', 'N/A')}
        Date: {exam_data.get('exam_date', 'N/A')}
        Time: {exam_data.get('exam_time', 'N/A')}
        Room: {exam_data.get('room', 'N/A')}
        Seat Number: {exam_data.get('seat_number', 'N/A')}

        Please arrive 30 minutes before the exam starts and bring your ID card.

        Best regards,
        Examination Department
        """
        
        return self.send_notification(
            recipient=recipient,
            subject=subject,
            message=message,
            notification_type="exam_notification",
            exam_data=exam_data
        )
    
    def send_complaint_acknowledgment(self, complaint_data: Dict) -> bool:
        """Send complaint acknowledgment"""
        subject = "Complaint Acknowledgment"
        message = f"""
        Dear Student,

        Your complaint has been received and registered in our system.

        Complaint ID: {complaint_data.get('complaint_id', 'N/A')}
        Category: {complaint_data.get('category', 'N/A')}
        Submitted On: {complaint_data.get('submitted_date', 'N/A')}
        Status: Under Review

        We will investigate your complaint and provide a response within 48 hours.

        Best regards,
        Student Affairs Department
        """
        
        return self.send_notification(
            recipient=complaint_data.get('email', ''),
            subject=subject,
            message=message,
            notification_type="complaint_acknowledgment",
            complaint_id=complaint_data.get('complaint_id')
        )
    
    def send_room_allocation_notification(self, recipients: List[str], allocation_data: Dict) -> bool:
        """Send room allocation notification"""
        subject = "Room Allocation Update"
        message = f"""
        Dear Faculty,

        Room allocation has been updated:

        Course: {allocation_data.get('course', 'N/A')}
        Faculty: {allocation_data.get('faculty_name', 'N/A')}
        Room: {allocation_data.get('room', 'N/A')}
        Date: {allocation_data.get('date', 'N/A')}
        Time: {allocation_data.get('time', 'N/A')}
        Duration: {allocation_data.get('duration', 'N/A')}

        Please confirm your availability for this allocation.

        Best regards,
        Room Management System
        """
        
        success_count = 0
        for recipient in recipients:
            if self.send_notification(
                recipient=recipient,
                subject=subject,
                message=message,
                notification_type="room_allocation",
                allocation_data=allocation_data
            ):
                success_count += 1
        
        return success_count == len(recipients)
    
    def send_bulk_notification(self, recipients: List[str], subject: str, 
                             message: str, notification_type: str = "bulk") -> Dict:
        """Send bulk notification to multiple recipients"""
        results = {
            'successful': 0,
            'failed': 0,
            'total': len(recipients)
        }
        
        for recipient in recipients:
            if self.send_notification(
                recipient=recipient,
                subject=subject,
                message=message,
                notification_type=notification_type
            ):
                results['successful'] += 1
            else:
                results['failed'] += 1
        
        return results

# Global instance - will be initialized lazily
_email_automation = None

def get_email_automation():
    """Get the global email automation instance"""
    global _email_automation
    if _email_automation is None:
        _email_automation = N8NEmailAutomation()
    return _email_automation

# Convenience functions
def send_notification(recipient: str, subject: str, message: str, **kwargs) -> bool:
    """Send notification using global email automation instance"""
    return get_email_automation().send_notification(recipient, subject, message, **kwargs)

def send_welcome_email(user_data: Dict) -> bool:
    """Send welcome email using global instance"""
    return get_email_automation().send_welcome_email(user_data)

def send_schedule_update(recipients: List[str], schedule_data: Dict) -> bool:
    """Send schedule update using global instance"""
    return get_email_automation().send_schedule_update(recipients, schedule_data)

def send_exam_notification(recipient: str, exam_data: Dict) -> bool:
    """Send exam notification using global instance"""
    return get_email_automation().send_exam_notification(recipient, exam_data)

def send_complaint_acknowledgment(complaint_data: Dict) -> bool:
    """Send complaint acknowledgment using global instance"""
    return get_email_automation().send_complaint_acknowledgment(complaint_data)

def send_room_allocation_notification(recipients: List[str], allocation_data: Dict) -> bool:
    """Send room allocation notification using global instance"""
    return get_email_automation().send_room_allocation_notification(recipients, allocation_data)

def send_bulk_notification(recipients: List[str], subject: str, message: str, notification_type: str = "bulk") -> Dict:
    """Send bulk notification using global instance"""
    return get_email_automation().send_bulk_notification(recipients, subject, message, notification_type)