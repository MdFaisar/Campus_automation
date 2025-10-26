"""
Room Management System for College Management System
Handles room allocation, booking, waiting lists, and admin operations
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from firebase_admin import firestore
from google.cloud.firestore import FieldFilter
#import smpt_sender

logger = logging.getLogger(__name__)

class RoomManager:
    def __init__(self):
        self.db = firestore.client()
        
    def add_room(self, room_data: Dict) -> bool:
        """Add a new room (Admin only)"""
        try:
            room_doc = {
                'room_number': room_data['room_number'],
                'room_name': room_data.get('room_name', ''),
                'capacity': int(room_data['capacity']),
                'room_type': room_data.get('room_type', 'classroom'),  # classroom, lab, auditorium
                'building': room_data.get('building', ''),
                'floor': room_data.get('floor', ''),
                'facilities': room_data.get('facilities', []),  # projector, whiteboard, computers, etc.
                'status': 'active',  # active, maintenance, inactive
                'created_at': datetime.now(),
                'created_by': room_data.get('created_by', '')
            }
            
            # Check if room already exists
            existing_rooms = self.db.collection('rooms').where(filter=FieldFilter('room_number', '==', room_data['room_number'])).get()
            if len(existing_rooms) > 0:
                logger.error(f"Room {room_data['room_number']} already exists")
                return False
            
            # Add room to database
            self.db.collection('rooms').add(room_doc)
            logger.info(f"Room {room_data['room_number']} added successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error adding room: {str(e)}")
            return False
    
    def delete_room(self, room_id: str, admin_id: str) -> bool:
        """Delete a room (Admin only)"""
        try:
            # Check if room has active bookings
            active_bookings = self.db.collection('room_bookings')\
                .where(filter=FieldFilter('room_id', '==', room_id))\
                .where(filter=FieldFilter('status', 'in', ['confirmed', 'pending']))\
                .get()
            
            if active_bookings:
                logger.error(f"Cannot delete room {room_id}: has active bookings")
                return False
            
            # Delete the room
            self.db.collection('rooms').document(room_id).delete()
            
            # Log the deletion
            self.db.collection('room_audit_log').add({
                'action': 'room_deleted',
                'room_id': room_id,
                'admin_id': admin_id,
                'timestamp': datetime.now()
            })
            
            logger.info(f"Room {room_id} deleted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting room: {str(e)}")
            return False
    
    def get_available_rooms(self, date: str, start_time: str, end_time: str, 
                           room_type: str = None) -> List[Dict]:
        """Get list of available rooms for a specific time slot"""
        try:
            # Parse datetime
            booking_date = datetime.strptime(date, '%Y-%m-%d').date()
            start_datetime = datetime.strptime(f"{date} {start_time}", '%Y-%m-%d %H:%M')
            end_datetime = datetime.strptime(f"{date} {end_time}", '%Y-%m-%d %H:%M')
            
            # Get all active rooms
            rooms_query = self.db.collection('rooms').where(filter=FieldFilter('status', '==', 'active'))
            if room_type:
                rooms_query = rooms_query.where(filter=FieldFilter('room_type', '==', room_type))
            
            all_rooms = rooms_query.get()
            available_rooms = []
            
            for room_doc in all_rooms:
                room_data = room_doc.to_dict()
                room_data['id'] = room_doc.id
                
                # Check if room is available during the requested time
                if self._is_room_available(room_doc.id, start_datetime, end_datetime):
                    available_rooms.append(room_data)
            
            return available_rooms
            
        except Exception as e:
            logger.error(f"Error getting available rooms: {str(e)}")
            return []
    
    def _is_room_available(self, room_id: str, start_time: datetime, end_time: datetime) -> bool:
        """Check if a room is available during a specific time period"""
        try:
            # Simplified approach - get all confirmed bookings for this room
            # and filter by date in Python to avoid complex Firestore queries
            bookings = self.db.collection('room_bookings')\
                .where(filter=FieldFilter('room_id', '==', room_id))\
                .where(filter=FieldFilter('status', '==', 'confirmed'))\
                .get()

            target_date = start_time.date()

            for booking_doc in bookings:
                booking = booking_doc.to_dict()

                # Get booking date
                booking_date = booking['booking_date']
                if hasattr(booking_date, 'date'):
                    booking_date = booking_date.date()
                elif hasattr(booking_date, 'strftime'):
                    # It's already a date object
                    pass
                else:
                    # Skip if we can't determine the date
                    continue

                # Only check bookings on the same date
                if booking_date != target_date:
                    continue

                # Check for time overlap
                # Handle both string and time object formats
                start_time_obj = booking['start_time']
                end_time_obj = booking['end_time']

                if isinstance(start_time_obj, str):
                    start_time_obj = datetime.strptime(start_time_obj, '%H:%M').time()
                if isinstance(end_time_obj, str):
                    end_time_obj = datetime.strptime(end_time_obj, '%H:%M').time()

                booking_start = datetime.combine(booking_date, start_time_obj)
                booking_end = datetime.combine(booking_date, end_time_obj)

                if (start_time < booking_end and end_time > booking_start):
                    return False

            return True

        except Exception as e:
            logger.error(f"Error checking room availability: {str(e)}")
            return False
    
    def book_room(self, booking_data: Dict) -> Dict:
        """Book a room for faculty"""
        try:
            logger.info(f"Starting booking process for faculty {booking_data.get('faculty_id')}")
            logger.info(f"Booking data: {booking_data}")

            # Parse datetime - store as datetime object for Firestore compatibility
            booking_date_str = booking_data['date']
            booking_date = datetime.strptime(booking_date_str, '%Y-%m-%d')
            start_time = datetime.strptime(booking_data['start_time'], '%H:%M').time()
            end_time = datetime.strptime(booking_data['end_time'], '%H:%M').time()

            logger.info(f"Parsed date: {booking_date}, start: {start_time}, end: {end_time}")

            # Check if room is available
            start_datetime = datetime.combine(booking_date.date(), start_time)
            end_datetime = datetime.combine(booking_date.date(), end_time)

            logger.info(f"Checking availability for room {booking_data['room_id']}")

            is_available = self._is_room_available(booking_data['room_id'], start_datetime, end_datetime)
            logger.info(f"Room availability check result: {is_available}")

            if is_available:
                # Room is available - create confirmed booking
                booking_doc = {
                    'room_id': booking_data['room_id'],
                    'faculty_id': booking_data['faculty_id'],
                    'faculty_name': booking_data['faculty_name'],
                    'faculty_email': booking_data['faculty_email'],
                    'booking_date': booking_date,  # Store as datetime object
                    'start_time': start_time.strftime('%H:%M'),  # Convert to string
                    'end_time': end_time.strftime('%H:%M'),      # Convert to string
                    'purpose': booking_data.get('purpose', ''),
                    'course_name': booking_data.get('course_name', ''),
                    'expected_students': booking_data.get('expected_students', 0),
                    'status': 'confirmed',
                    'created_at': datetime.now(),
                    'booking_type': 'regular'
                }

                logger.info(f"Creating booking document: {booking_doc}")
                booking_ref = self.db.collection('room_bookings').add(booking_doc)
                logger.info(f"Booking created with ID: {booking_ref[1].id}")

                # Send confirmation email (skip for now to avoid errors)
                try:
                    self._send_booking_confirmation(booking_data, 'confirmed')
                except Exception as email_error:
                    logger.warning(f"Email notification failed: {str(email_error)}")

                logger.info(f"Room booking confirmed for faculty {booking_data['faculty_id']}")
                return {
                    'success': True,
                    'status': 'confirmed',
                    'booking_id': booking_ref[1].id,
                    'message': 'Room booked successfully!'
                }
            else:
                # Room is not available - add to waiting list
                waiting_list_doc = {
                    'room_id': booking_data['room_id'],
                    'faculty_id': booking_data['faculty_id'],
                    'faculty_name': booking_data['faculty_name'],
                    'faculty_email': booking_data['faculty_email'],
                    'booking_date': booking_date,  # Store as datetime object
                    'start_time': start_time.strftime('%H:%M'),  # Convert to string
                    'end_time': end_time.strftime('%H:%M'),      # Convert to string
                    'purpose': booking_data.get('purpose', ''),
                    'course_name': booking_data.get('course_name', ''),
                    'expected_students': booking_data.get('expected_students', 0),
                    'status': 'waiting',
                    'created_at': datetime.now(),
                    'priority': self._calculate_waiting_priority(booking_data)
                }
                
                waiting_ref = self.db.collection('room_waiting_list').add(waiting_list_doc)
                
                # Send waiting list notification
                self._send_waiting_list_notification(booking_data)
                
                logger.info(f"Faculty {booking_data['faculty_id']} added to waiting list")
                return {
                    'success': True,
                    'status': 'waiting',
                    'waiting_id': waiting_ref[1].id,
                    'message': 'Room is not available. You have been added to the waiting list.'
                }
                
        except Exception as e:
            logger.error(f"Error booking room: {str(e)}")
            return {
                'success': False,
                'status': 'error',
                'message': 'An error occurred while booking the room.'
            }
    
    def _calculate_waiting_priority(self, booking_data: Dict) -> int:
        """Calculate priority for waiting list (lower number = higher priority)"""
        # Priority factors:
        # 1. Faculty seniority (if available)
        # 2. Course importance
        # 3. Number of students
        # 4. Time of request (FIFO)
        
        priority = 100  # Base priority
        
        # Adjust based on expected students (more students = higher priority)
        expected_students = booking_data.get('expected_students', 0)
        if expected_students > 50:
            priority -= 20
        elif expected_students > 30:
            priority -= 10
        elif expected_students > 15:
            priority -= 5
        
        return priority
    
    def cancel_booking(self, booking_id: str, faculty_id: str, is_admin: bool = False) -> Dict:
        """Cancel a room booking"""
        try:
            # Get the booking
            booking_doc = self.db.collection('room_bookings').document(booking_id).get()
            
            if not booking_doc.exists:
                return {'success': False, 'message': 'Booking not found'}
            
            booking_data = booking_doc.to_dict()
            
            # Check if faculty owns this booking or if admin is canceling
            if not is_admin and booking_data['faculty_id'] != faculty_id:
                return {'success': False, 'message': 'Unauthorized to cancel this booking'}
            
            # Update booking status to cancelled
            self.db.collection('room_bookings').document(booking_id).update({
                'status': 'cancelled',
                'cancelled_at': datetime.now(),
                'cancelled_by': faculty_id if not is_admin else 'admin'
            })
            
            # Process waiting list for this time slot
            self._process_waiting_list(
                booking_data['room_id'],
                booking_data['booking_date'],
                booking_data['start_time'],
                booking_data['end_time']
            )
            
            logger.info(f"Booking {booking_id} cancelled successfully")
            return {'success': True, 'message': 'Booking cancelled successfully'}
            
        except Exception as e:
            logger.error(f"Error cancelling booking: {str(e)}")
            return {'success': False, 'message': 'Error cancelling booking'}

    def _process_waiting_list(self, room_id: str, booking_date, start_time, end_time):
        """Process waiting list when a booking is cancelled"""
        try:
            # Convert booking_date to datetime if it's a date object
            if hasattr(booking_date, 'date'):
                search_date = booking_date
            else:
                search_date = datetime.combine(booking_date, datetime.min.time())

            # Simplified approach - get all waiting entries for this room and filter in Python
            all_waiting_entries = self.db.collection('room_waiting_list')\
                .where(filter=FieldFilter('room_id', '==', room_id))\
                .where(filter=FieldFilter('status', '==', 'waiting'))\
                .get()

            # Filter and sort in Python to avoid complex Firestore queries
            matching_entries = []
            for entry_doc in all_waiting_entries:
                entry_data = entry_doc.to_dict()

                # Check if this entry matches our criteria
                entry_booking_date = entry_data.get('booking_date')
                if hasattr(entry_booking_date, 'date'):
                    entry_booking_date = entry_booking_date.date()

                search_date_obj = search_date.date() if hasattr(search_date, 'date') else search_date

                if (entry_booking_date == search_date_obj and
                    entry_data.get('start_time') == start_time and
                    entry_data.get('end_time') == end_time):

                    matching_entries.append((entry_doc, entry_data))

            # Sort by priority and creation time
            matching_entries.sort(key=lambda x: (x[1].get('priority', 100), x[1].get('created_at')))

            waiting_entries = [entry[0] for entry in matching_entries[:1]]  # Take only the first one

            if waiting_entries:
                # Get the highest priority waiting entry
                waiting_doc = waiting_entries[0]
                waiting_data = waiting_doc.to_dict()

                # Create confirmed booking from waiting list entry
                booking_doc = {
                    'room_id': waiting_data['room_id'],
                    'faculty_id': waiting_data['faculty_id'],
                    'faculty_name': waiting_data['faculty_name'],
                    'faculty_email': waiting_data['faculty_email'],
                    'booking_date': waiting_data['booking_date'],
                    'start_time': waiting_data['start_time'],
                    'end_time': waiting_data['end_time'],
                    'purpose': waiting_data['purpose'],
                    'course_name': waiting_data['course_name'],
                    'expected_students': waiting_data['expected_students'],
                    'status': 'confirmed',
                    'created_at': datetime.now(),
                    'booking_type': 'from_waiting_list',
                    'original_waiting_id': waiting_doc.id
                }

                # Add confirmed booking
                self.db.collection('room_bookings').add(booking_doc)

                # Update waiting list entry status
                self.db.collection('room_waiting_list').document(waiting_doc.id).update({
                    'status': 'confirmed',
                    'confirmed_at': datetime.now()
                })

                # Send confirmation email
                self._send_booking_confirmation(waiting_data, 'confirmed_from_waiting')

                logger.info(f"Waiting list entry promoted to confirmed booking for faculty {waiting_data['faculty_id']}")

        except Exception as e:
            logger.error(f"Error processing waiting list: {str(e)}")

    def get_faculty_bookings(self, faculty_id: str) -> List[Dict]:
        """Get all bookings for a faculty member"""
        try:
            logger.info(f"Getting bookings for faculty: {faculty_id}")
            bookings = []

            # Get confirmed bookings - simplified query to avoid index requirements
            logger.info("Querying confirmed bookings...")
            confirmed_bookings = self.db.collection('room_bookings')\
                .where(filter=FieldFilter('faculty_id', '==', faculty_id))\
                .get()

            # Filter by status in Python to avoid complex Firestore index
            filtered_bookings = []
            for booking_doc in confirmed_bookings:
                booking_data = booking_doc.to_dict()
                if booking_data.get('status') in ['confirmed', 'cancelled']:
                    filtered_bookings.append(booking_doc)

            logger.info(f"Found {len(filtered_bookings)} confirmed/cancelled bookings")

            for booking_doc in filtered_bookings:
                booking_data = booking_doc.to_dict()
                booking_data['id'] = booking_doc.id
                booking_data['type'] = 'booking'

                # Convert datetime to date string for frontend
                if 'booking_date' in booking_data and hasattr(booking_data['booking_date'], 'date'):
                    booking_data['booking_date'] = booking_data['booking_date'].date().strftime('%Y-%m-%d')

                # Get room details
                room_doc = self.db.collection('rooms').document(booking_data['room_id']).get()
                if room_doc.exists:
                    booking_data['room_details'] = room_doc.to_dict()

                bookings.append(booking_data)

            # Get waiting list entries - simplified query
            waiting_entries = self.db.collection('room_waiting_list')\
                .where(filter=FieldFilter('faculty_id', '==', faculty_id))\
                .get()

            # Filter by status in Python
            filtered_waiting = []
            for waiting_doc in waiting_entries:
                waiting_data = waiting_doc.to_dict()
                if waiting_data.get('status') == 'waiting':
                    filtered_waiting.append(waiting_doc)

            for waiting_doc in filtered_waiting:
                waiting_data = waiting_doc.to_dict()
                waiting_data['id'] = waiting_doc.id
                waiting_data['type'] = 'waiting'

                # Convert datetime to date string for frontend
                if 'booking_date' in waiting_data and hasattr(waiting_data['booking_date'], 'date'):
                    waiting_data['booking_date'] = waiting_data['booking_date'].date().strftime('%Y-%m-%d')

                # Get room details
                room_doc = self.db.collection('rooms').document(waiting_data['room_id']).get()
                if room_doc.exists:
                    waiting_data['room_details'] = room_doc.to_dict()

                bookings.append(waiting_data)

            return bookings

        except Exception as e:
            logger.error(f"Error getting faculty bookings: {str(e)}")
            return []

    def get_all_rooms(self) -> List[Dict]:
        """Get all rooms"""
        try:
            logger.info("Starting get_all_rooms operation")
            rooms = []

            # Get all rooms - simple query without complex filters
            room_docs = self.db.collection('rooms').get()
            logger.info(f"Retrieved {len(room_docs)} room documents from Firestore")

            for room_doc in room_docs:
                try:
                    room_data = room_doc.to_dict()
                    room_data['id'] = room_doc.id

                    # Set default values for missing fields
                    room_data['room_number'] = room_data.get('room_number', 'Unknown')
                    room_data['room_name'] = room_data.get('room_name', '')
                    room_data['capacity'] = room_data.get('capacity', 0)
                    room_data['room_type'] = room_data.get('room_type', 'classroom')
                    room_data['building'] = room_data.get('building', 'Main Building')
                    room_data['floor'] = room_data.get('floor', '1st Floor')
                    room_data['facilities'] = room_data.get('facilities', [])
                    room_data['status'] = room_data.get('status', 'active')

                    # For now, set current_bookings to 0 to avoid complex queries
                    # This can be enhanced later once basic functionality is working
                    room_data['current_bookings'] = 0

                    rooms.append(room_data)
                    logger.debug(f"Added room: {room_data['room_number']}")

                except Exception as room_error:
                    logger.warning(f"Error processing room document {room_doc.id}: {str(room_error)}")
                    continue

            # Sort rooms by room_number in Python instead of Firestore
            rooms.sort(key=lambda x: x.get('room_number', ''))

            logger.info(f"Successfully retrieved and processed {len(rooms)} rooms")
            return rooms

        except Exception as e:
            logger.error(f"Error getting all rooms: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return []

    def force_cancel_booking(self, booking_id: str, admin_id: str, reason: str = '') -> Dict:
        """Force cancel a booking (Admin only)"""
        try:
            # Get the booking
            booking_doc = self.db.collection('room_bookings').document(booking_id).get()

            if not booking_doc.exists:
                return {'success': False, 'message': 'Booking not found'}

            booking_data = booking_doc.to_dict()

            # Update booking status to force cancelled
            self.db.collection('room_bookings').document(booking_id).update({
                'status': 'force_cancelled',
                'cancelled_at': datetime.now(),
                'cancelled_by': admin_id,
                'cancellation_reason': reason
            })

            # Log the force cancellation
            self.db.collection('room_audit_log').add({
                'action': 'force_cancel_booking',
                'booking_id': booking_id,
                'admin_id': admin_id,
                'reason': reason,
                'timestamp': datetime.now(),
                'original_faculty': booking_data['faculty_id']
            })

            # Send notification to faculty
            self._send_force_cancellation_notification(booking_data, reason)

            # Process waiting list
            self._process_waiting_list(
                booking_data['room_id'],
                booking_data['booking_date'],
                booking_data['start_time'],
                booking_data['end_time']
            )

            logger.info(f"Booking {booking_id} force cancelled by admin {admin_id}")
            return {'success': True, 'message': 'Booking force cancelled successfully'}

        except Exception as e:
            logger.error(f"Error force cancelling booking: {str(e)}")
            return {'success': False, 'message': 'Error force cancelling booking'}

    def _send_booking_confirmation(self, booking_data: Dict, status: str):
        """Send booking confirmation email"""
        try:
            if status == 'confirmed':
                subject = "Room Booking Confirmed"
                message = f"""
                Dear {booking_data['faculty_name']},

                Your room booking has been confirmed:

                Room: {booking_data.get('room_number', 'N/A')}
                Date: {booking_data['date']}
                Time: {booking_data['start_time']} - {booking_data['end_time']}
                Purpose: {booking_data.get('purpose', 'N/A')}
                Course: {booking_data.get('course_name', 'N/A')}

                Please arrive on time and ensure the room is left clean.

                Best regards,
                Room Management System
                """
            elif status == 'confirmed_from_waiting':
                subject = "Room Booking Confirmed - From Waiting List"
                message = f"""
                Dear {booking_data['faculty_name']},

                Great news! A room has become available and your booking has been confirmed:

                Room: {booking_data.get('room_number', 'N/A')}
                Date: {booking_data['booking_date']}
                Time: {booking_data['start_time']} - {booking_data['end_time']}
                Purpose: {booking_data.get('purpose', 'N/A')}
                Course: {booking_data.get('course_name', 'N/A')}

                Please confirm your availability as soon as possible.

                Best regards,
                Room Management System
                """

            send_smtp_email(
                recipient=booking_data['faculty_email'],
                subject=subject,
                message=message.strip()  # Remove extra whitespace
            )

        except Exception as e:
            logger.error(f"Error sending booking confirmation: {str(e)}")

    def _send_waiting_list_notification(self, booking_data: Dict):
        """Send waiting list notification email"""
        try:
            subject = "Added to Room Booking Waiting List"
            message = f"""
            Dear {booking_data['faculty_name']},

            Your room booking request has been added to the waiting list:

            Room: {booking_data.get('room_number', 'N/A')}
            Date: {booking_data['date']}
            Time: {booking_data['start_time']} - {booking_data['end_time']}
            Purpose: {booking_data.get('purpose', 'N/A')}
            Course: {booking_data.get('course_name', 'N/A')}

            You will be notified if the room becomes available.

            Best regards,
            Room Management System
            """

            send_notification(
                recipient=booking_data['faculty_email'],
                subject=subject,
                message=message
            )

        except Exception as e:
            logger.error(f"Error sending waiting list notification: {str(e)}")

    def _send_force_cancellation_notification(self, booking_data: Dict, reason: str):
        """Send force cancellation notification email"""
        try:
            subject = "Room Booking Cancelled by Administration"
            message = f"""
            Dear {booking_data['faculty_name']},

            Your room booking has been cancelled by the administration:

            Room: {booking_data.get('room_number', 'N/A')}
            Date: {booking_data['booking_date']}
            Time: {booking_data['start_time']} - {booking_data['end_time']}
            Reason: {reason}

            Please contact the administration for more information or to reschedule.

            Best regards,
            Room Management System
            """

            send_notification(
                recipient=booking_data['faculty_email'],
                subject=subject,
                message=message
            )

        except Exception as e:
            logger.error(f"Error sending force cancellation notification: {str(e)}")

# Global instance
_room_manager = None

def get_room_manager():
    """Get global room manager instance"""
    global _room_manager
    if _room_manager is None:
        _room_manager = RoomManager()
    return _room_manager
