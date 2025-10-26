from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import json
import logging
from pathlib import Path
import traceback
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Firebase FIRST before importing other modules
from utils.firebase_config import initialize_firebase, get_firestore_client
firebase_app = initialize_firebase()

# Now import other modules that depend on Firebase
from utils.auth import authenticate_user, create_user, get_user_role
from utils.rag_system import RAGSystem
from utils.email_automation import send_notification
from utils.room_management import RoomManager, get_room_manager
from utils.complaint_manager import get_complaint_manager
from auth_routes import auth_bp

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Register authentication blueprint
app.register_blueprint(auth_bp)
app.config['NOTES_FOLDER'] = 'uploads/notes'
app.config['DOCUMENTS_FOLDER'] = 'uploads/documents'
app.config['TEMP_FOLDER'] = 'uploads/temp'

# Create upload directories if they don't exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['NOTES_FOLDER'], 
               app.config['DOCUMENTS_FOLDER'], app.config['TEMP_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'ppt', 'pptx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize RAG system with error handling
try:
    rag_system = RAGSystem()
    #logger.info("RAG system initialized successfully")
except Exception as e:
    #logger.error(f"Failed to initialize RAG system: {str(e)}")
    rag_system = None

# Initialize Room Manager
room_manager = None
try:
    room_manager = get_room_manager()
    if room_manager:
        # Initialize test rooms if needed
        room_manager.initialize_test_rooms()
        logger.info("Room manager initialized successfully with test rooms")
    else:
        logger.warning("Room manager was initialized as None")
except Exception as e:
    logger.error(f"Failed to initialize room manager: {str(e)}")
    room_manager = None

# Initialize Complaint Manager
try:
    complaint_manager = get_complaint_manager()
    #logger.info("Complaint manager initialized successfully")
except Exception as e:
    #logger.error(f"Failed to initialize complaint manager: {str(e)}")
    complaint_manager = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Landing page - redirect to login if not authenticated"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for all user types"""
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email')
            password = data.get('password')
            user_type = data.get('user_type', 'student')
            
            if not email or not password:
                return jsonify({'error': 'Email and password are required'}), 400
            
            # Authenticate user
            user = authenticate_user(email, password, user_type)
            if user:
                session['user_id'] = user['uid']
                session['user_type'] = user_type
                session['user_email'] = email
                
                logger.info(f"User {email} logged in successfully as {user_type}")
                
                if request.is_json:
                    return jsonify({'success': True, 'redirect': url_for('dashboard')})
                else:
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
            else:
                error_msg = 'Invalid email or password'
                if request.is_json:
                    return jsonify({'error': error_msg}), 401
                else:
                    flash(error_msg, 'error')
                    
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            error_msg = 'An error occurred during login'
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page for all user types"""
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            
            required_fields = ['email', 'password', 'confirm_password', 'user_type', 'full_name']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400
            
            # Validate password match
            if data['password'] != data['confirm_password']:
                return jsonify({'error': 'Passwords do not match'}), 400
            
            # Additional validation based on user type
            if data['user_type'] == 'student':
                if not data.get('student_id') or not data.get('section'):
                    return jsonify({'error': 'Student ID and Section are required for students'}), 400
            elif data['user_type'] == 'faculty':
                if not data.get('employee_id') or not data.get('department'):
                    return jsonify({'error': 'Employee ID and Department are required for faculty'}), 400
            elif data['user_type'] == 'admin':
                if not data.get('admin_code'):
                    return jsonify({'error': 'Admin code is required for admin registration'}), 400
            
            # Create user
            user = create_user(data)
            if user:
                logger.info(f"User {data['email']} registered successfully as {data['user_type']}")
                
                # Send welcome email
                try:
                    send_notification(
                        recipient=data['email'],
                        subject='Welcome to College Management System',
                        message=f"Welcome {data['full_name']}! Your account has been created successfully."
                    )
                except Exception as e:
                    logger.error(f"Failed to send welcome email: {str(e)}")
                
                if request.is_json:
                    return jsonify({'success': True, 'message': 'Registration successful! Please login.'})
                else:
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('auth.login_page'))
            else:
                error_msg = 'Registration failed. Email might already exist.'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                else:
                    flash(error_msg, 'error')
                    
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            error_msg = 'An error occurred during registration'
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'error')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page - role-based content"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    user_type = session.get('user_type', 'student')

    # Redirect to specific dashboards based on user type
    if user_type == 'student':
        return redirect(url_for('student_dashboard'))
    elif user_type == 'faculty':
        return redirect(url_for('faculty_dashboard'))
    else:
        # For admin or other types, show general dashboard
        user_email = session.get('user_email', '')
        user_data = {
            'user_type': user_type,
            'email': user_email,
            'features': get_user_features(user_type)
        }
        return render_template('dashboard.html', user_data=user_data)

@app.route('/student-dashboard')
def student_dashboard():
    """Student dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'student':
        flash('Access denied. Student access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('student_dashboard.html', user_data=session)

@app.route('/faculty-dashboard')
def faculty_dashboard():
    """Faculty dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'faculty':
        flash('Access denied. Faculty access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', user_data=session)

@app.route('/admin-dashboard')
def admin_dashboard():
    """Admin dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('auth.admin_login_page'))

    if session.get('user_type') != 'admin':
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('admin_dashboard.html', user_data=session)

@app.route('/user-management')
def user_management():
    """User management page (Admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('auth.admin_login_page'))

    if session.get('user_type') != 'admin':
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('admin/user_management.html', user_data=session)

@app.route('/notes')
def notes():
    """AI Notes Bot page"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
    
    return render_template('notes.html')

@app.route('/api/notes/upload', methods=['POST'])
def upload_notes():
    """Upload notes - Faculty only with improved error handling"""
    logger.info("Upload request received")
    
    # Check authentication
    if 'user_id' not in session:
        logger.error("Unauthorized access attempt")
        return jsonify({'error': 'Unauthorized - Please login'}), 403
    
    # Check user type
    if session.get('user_type') != 'faculty':
        logger.error(f"Non-faculty user attempted upload: {session.get('user_type')}")
        return jsonify({'error': 'Unauthorized - Faculty access required'}), 403
    
    # Check if RAG system is initialized
    if rag_system is None:
        logger.error("RAG system not initialized")
        return jsonify({'error': 'System not ready - RAG system initialization failed'}), 500
    
    try:
        logger.info("Checking for uploaded files")
        
        # Check if file is in request
        if 'file' not in request.files:
            logger.error("No file in request")
            return jsonify({'error': 'No file provided'}), 400
        
        files = request.files.getlist('file')
        if not files or (len(files) == 1 and files[0].filename == ''):
            logger.error("No file selected")
            return jsonify({'error': 'No file selected'}), 400
        
        uploaded_files = []
        failed_files = []
        
        for file in files:
            try:
                logger.info(f"Processing file: {file.filename}")
                
                # Validate file
                if not file.filename:
                    failed_files.append({'filename': 'Unknown', 'error': 'No filename'})
                    continue
                
                if not allowed_file(file.filename):
                    failed_files.append({'filename': file.filename, 'error': 'File type not allowed'})
                    continue
                
                # Get additional metadata from form
                department = request.form.get('department', 'General')
                subject = request.form.get('subject', 'General')
                
                logger.info(f"File validation passed for: {file.filename}")
                logger.info(f"Department: {department}, Subject: {subject}")
                
                # Save and process file using RAG system
                success = rag_system.add_document(file, department=department, subject=subject)
                
                if success:
                    uploaded_files.append({
                        'filename': file.filename,
                        'department': department,
                        'subject': subject
                    })
                    logger.info(f"Successfully processed: {file.filename}")
                else:
                    failed_files.append({'filename': file.filename, 'error': 'Failed to process document'})
                    logger.error(f"Failed to process: {file.filename}")
                
            except Exception as e:
                logger.error(f"Error processing file {file.filename}: {str(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                failed_files.append({'filename': file.filename, 'error': str(e)})
        
        # Prepare response
        response_data = {
            'success': len(uploaded_files) > 0,
            'uploaded_files': uploaded_files,
            'failed_files': failed_files
        }
        
        if len(uploaded_files) > 0:
            response_data['message'] = f'Successfully uploaded {len(uploaded_files)} file(s)'
            if len(failed_files) > 0:
                response_data['message'] += f', {len(failed_files)} file(s) failed'
        else:
            response_data['error'] = 'No files were uploaded successfully'
            return jsonify(response_data), 400
        
        logger.info(f"Upload completed: {len(uploaded_files)} success, {len(failed_files)} failed")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/notes/query', methods=['POST'])
def query_notes():
    """Query the AI notes bot"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if rag_system is None:
        return jsonify({'error': 'System not ready'}), 500
    
    try:
        data = request.get_json()
        query = data.get('query')
        
        if not query:
            return jsonify({'error': 'Query is required'}), 400
        
        # Get response from RAG system
        response = rag_system.query(query)
        
        logger.info(f"Query processed: {query[:50]}...")
        return jsonify({'response': response})
        
    except Exception as e:
        logger.error(f"Query error: {str(e)}")
        return jsonify({'error': 'Query processing failed'}), 500

@app.route('/api/notes/list')
def list_notes():
    """List available notes"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if rag_system is None:
        return jsonify({'error': 'System not ready'}), 500
    
    try:
        notes = rag_system.get_document_list()
        return jsonify({'notes': notes})
    except Exception as e:
        logger.error(f"List notes error: {str(e)}")
        return jsonify({'error': 'Failed to get notes list'}), 500

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login_page'))

@app.route('/test-faculty-login')
def test_faculty_login():
    """Test faculty login for development (remove in production)"""
    session['user_id'] = 'test_faculty_123'
    session['user_type'] = 'faculty'
    session['user_email'] = 'test.faculty@example.com'

    flash('Logged in as test faculty for development', 'success')
    return redirect(url_for('room_allocation'))

# Room Allocation Routes

@app.route('/room-allocation')
def room_allocation():
    """Room allocation page for faculty"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'faculty':
        flash('Access denied. Faculty access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('room_allocation.html', user_data=session)

@app.route('/room-management')
def room_management():
    """Room management page for admin"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'admin':
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('room_management.html', user_data=session)

@app.route('/api/rooms/available', methods=['POST'])
def get_available_rooms():
    """Get available rooms for a specific time slot"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        data = request.get_json()
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        room_type = data.get('room_type')

        if not all([date, start_time, end_time]):
            return jsonify({'error': 'Date, start time, and end time are required'}), 400

        room_manager = get_room_manager()
        available_rooms = room_manager.get_available_rooms(date, start_time, end_time, room_type)

        return jsonify({'rooms': available_rooms})

    except Exception as e:
        logger.error(f"Error getting available rooms: {str(e)}")
        return jsonify({'error': 'Failed to get available rooms'}), 500

@app.route('/api/rooms/book', methods=['POST'])
def book_room():
    """Book a room"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        data = request.get_json()

        # Add faculty information from session
        data['faculty_id'] = session['user_id']
        data['faculty_name'] = session.get('user_email', 'Faculty')  # Use email as name for now
        data['faculty_email'] = session['user_email']

        room_manager = get_room_manager()
        result = room_manager.book_room(data)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error booking room: {str(e)}")
        return jsonify({'error': 'Failed to book room'}), 500

@app.route('/api/rooms/my-bookings')
def get_my_bookings():
    """Get current user's bookings"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        room_manager = get_room_manager()
        bookings = room_manager.get_faculty_bookings(session['user_id'])

        return jsonify({'bookings': bookings})

    except Exception as e:
        logger.error(f"Error getting bookings: {str(e)}")
        return jsonify({'error': 'Failed to get bookings'}), 500

@app.route('/api/rooms/cancel/<booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    """Cancel a booking"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        room_manager = get_room_manager()
        result = room_manager.cancel_booking(booking_id, session['user_id'])

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error cancelling booking: {str(e)}")
        return jsonify({'error': 'Failed to cancel booking'}), 500

@app.route('/api/rooms/all', methods=['GET'])
def get_all_rooms_for_faculty():
    """Get all rooms for faculty view"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        room_manager = get_room_manager()
        rooms = room_manager.get_all_rooms()

        return jsonify({'rooms': rooms})

    except Exception as e:
        logger.error(f"Error getting all rooms for faculty: {str(e)}")
        return jsonify({'error': 'Failed to get rooms'}), 500

# API endpoints as per specification
@app.route('/api/faculty/rooms', methods=['GET'])
def get_faculty_rooms():
    """Get all rooms for faculty (as per specification)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        room_manager = get_room_manager()
        rooms = room_manager.get_all_rooms()

        return jsonify({'rooms': rooms})

    except Exception as e:
        logger.error(f"Error getting faculty rooms: {str(e)}")
        return jsonify({'error': 'Failed to get rooms'}), 500

@app.route('/api/faculty/book', methods=['POST'])
def faculty_book_room():
    """Book a room for faculty (as per specification)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        data = request.get_json()
        logger.info(f"Faculty booking request data: {data}")
        logger.info(f"Session data - user_id: {session.get('user_id')}, user_type: {session.get('user_type')}, user_email: {session.get('user_email')}, email: {session.get('email')}, full_name: {session.get('full_name')}")

        # Add faculty information from session
        data['faculty_id'] = session['user_id']
        
        # Handle missing email gracefully - check both possible session keys
        user_email = session.get('user_email') or session.get('email')
        
        if not user_email:
            # If no email found, use a fallback
            user_email = f"{session['user_id']}@faculty.edu"
            logger.warning(f"No email found in session (checked 'user_email' and 'email'), using fallback: {user_email}")
        else:
            logger.info(f"Using email for faculty: {user_email}")
        
        # Use full_name if available, otherwise use email as name
        faculty_name = session.get('full_name') or user_email
        data['faculty_name'] = faculty_name
        data['faculty_email'] = user_email

        logger.info(f"Booking data with faculty info: {data}")

        room_manager = get_room_manager()
        result = room_manager.book_room(data)
        
        logger.info(f"Room booking result: {result}")
        logger.info(f"Result type: {type(result)}")
        
        # Ensure result has the correct format
        if not isinstance(result, dict):
            logger.error(f"Unexpected result type: {type(result)}")
            return jsonify({'success': False, 'error': 'Invalid response format', 'message': 'Invalid response format'}), 500
        
        # Ensure success field is boolean
        if 'success' in result:
            result['success'] = bool(result['success'])
        
        logger.info(f"Final JSON response: {result}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error booking room for faculty: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': f'Failed to book room: {str(e)}', 'message': f'Failed to book room: {str(e)}'}), 500

@app.route('/api/faculty/cancel', methods=['POST'])
def faculty_cancel_booking():
    """Cancel a booking for faculty (as per specification)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        data = request.get_json()
        booking_id = data.get('booking_id')

        room_manager = get_room_manager()
        result = room_manager.cancel_booking(booking_id, session['user_id'])

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error cancelling booking for faculty: {str(e)}")
        return jsonify({'error': 'Failed to cancel booking'}), 500

@app.route('/api/faculty/my_bookings', methods=['GET'])
def get_faculty_my_bookings():
    """Get faculty's bookings (as per specification)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    try:
        room_manager = get_room_manager()
        bookings = room_manager.get_faculty_bookings(session['user_id'])

        return jsonify({'bookings': bookings})

    except Exception as e:
        logger.error(f"Error getting faculty bookings: {str(e)}")
        return jsonify({'error': 'Failed to get bookings'}), 500

# Admin Room Management Routes

@app.route('/api/admin/rooms', methods=['GET'])
def get_all_rooms():
    """Get all rooms (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        room_manager = get_room_manager()
        rooms = room_manager.get_all_rooms()

        return jsonify({'rooms': rooms})

    except Exception as e:
        logger.error(f"Error getting all rooms: {str(e)}")
        return jsonify({'error': 'Failed to get rooms'}), 500

@app.route('/api/admin/rooms/add', methods=['POST'])
def add_room():
    """Add a new room (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        data = request.get_json()
        data['created_by'] = session['user_id']

        room_manager = get_room_manager()
        success = room_manager.add_room(data)

        if success:
            return jsonify({'success': True, 'message': 'Room added successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to add room'}), 400

    except Exception as e:
        logger.error(f"Error adding room: {str(e)}")
        return jsonify({'error': 'Failed to add room'}), 500

@app.route('/api/admin/rooms/delete/<room_id>', methods=['DELETE'])
def delete_room(room_id):
    """Delete a room (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        room_manager = get_room_manager()
        success = room_manager.delete_room(room_id, session['user_id'])

        if success:
            return jsonify({'success': True, 'message': 'Room deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete room'}), 400

    except Exception as e:
        logger.error(f"Error deleting room: {str(e)}")
        return jsonify({'error': 'Failed to delete room'}), 500

# Admin Statistics API
@app.route('/api/admin/stats/users', methods=['GET'])
def get_user_stats():
    """Get user statistics (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        db = get_firestore_client()

        # Count total users
        users = db.collection('users').get()
        total_count = len(users)

        # Count by user type
        student_count = sum(1 for user in users if user.to_dict().get('user_type') == 'student')
        faculty_count = sum(1 for user in users if user.to_dict().get('user_type') == 'faculty')
        admin_count = sum(1 for user in users if user.to_dict().get('user_type') == 'admin')

        return jsonify({
            'success': True,
            'count': total_count,
            'breakdown': {
                'students': student_count,
                'faculty': faculty_count,
                'admins': admin_count
            }
        })

    except Exception as e:
        logger.error(f"Error getting user stats: {str(e)}")
        return jsonify({'error': 'Failed to get user statistics'}), 500

@app.route('/api/admin/stats/complaints', methods=['GET'])
def get_complaint_stats():
    """Get complaint statistics (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        if complaint_manager is None:
            return jsonify({'error': 'Complaint system not ready'}), 500

        # Get complaint statistics
        stats = complaint_manager.get_admin_statistics()

        return jsonify({
            'success': True,
            'pending': stats.get('pending', 0),
            'resolved': stats.get('resolved', 0),
            'total': stats.get('total', 0)
        })

    except Exception as e:
        logger.error(f"Error getting complaint stats: {str(e)}")
        return jsonify({'error': 'Failed to get complaint statistics'}), 500

# User Management API Endpoints
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    """Get all users with filtering and sorting (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        from datetime import datetime, timedelta
        db = get_firestore_client()

        # Get query parameters for filtering
        search_name = request.args.get('name', '').strip().lower()
        search_id = request.args.get('id', '').strip().lower()
        filter_department = request.args.get('department', '').strip()
        filter_section = request.args.get('section', '').strip()
        search_email = request.args.get('email', '').strip().lower()
        filter_user_type = request.args.get('user_type', '').strip().lower()
        filter_status = request.args.get('status', '').strip().lower()

        # Pagination parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))

        # Get all users
        users_ref = db.collection('users')
        users = users_ref.get()

        user_list = []
        for user_doc in users:
            user_data = user_doc.to_dict()
            user_data['user_id'] = user_doc.id

            # Apply filters
            if search_name and search_name not in user_data.get('full_name', '').lower():
                continue

            if search_id:
                register_number = user_data.get('register_number', '').lower()
                employee_id = user_data.get('employee_id', '').lower()
                if search_id not in register_number and search_id not in employee_id:
                    continue

            if filter_department and user_data.get('department', '') != filter_department:
                continue

            if filter_section and user_data.get('section', '') != filter_section:
                continue

            if search_email and search_email not in user_data.get('email', '').lower():
                continue

            if filter_user_type and user_data.get('user_type', '') != filter_user_type:
                continue

            # Calculate last active status
            last_login = user_data.get('last_login')
            if last_login:
                if hasattr(last_login, 'timestamp'):
                    last_login_dt = datetime.fromtimestamp(last_login.timestamp())
                else:
                    last_login_dt = last_login

                time_diff = datetime.now() - last_login_dt

                if time_diff.total_seconds() < 300:  # 5 minutes
                    status = "Online"
                elif time_diff.total_seconds() < 3600:  # 1 hour
                    minutes = int(time_diff.total_seconds() / 60)
                    status = f"Last seen {minutes} minutes ago"
                elif time_diff.total_seconds() < 86400:  # 1 day
                    hours = int(time_diff.total_seconds() / 3600)
                    status = f"Last seen {hours} hours ago"
                else:
                    days = int(time_diff.total_seconds() / 86400)
                    status = f"Last seen {days} days ago"
            else:
                status = "Never logged in"

            user_data['last_active_status'] = status

            # Apply status filter
            if filter_status:
                if filter_status == 'online' and status != 'Online':
                    continue
                elif filter_status == 'recent' and 'minutes ago' not in status and 'hours ago' not in status:
                    continue
                elif filter_status == 'inactive' and status not in ['Never logged in'] and 'days ago' not in status:
                    continue

            # Check if account is suspended
            suspended_until = user_data.get('suspended_until')
            if suspended_until and datetime.now() < suspended_until:
                user_data['is_suspended'] = True
                user_data['suspended_until'] = suspended_until.isoformat()
            else:
                user_data['is_suspended'] = False

            user_list.append(user_data)

        # Sort users (default by full_name)
        sort_by = request.args.get('sort_by', 'full_name')
        sort_order = request.args.get('sort_order', 'asc')

        if sort_by in ['full_name', 'email', 'department', 'user_type']:
            user_list.sort(key=lambda x: x.get(sort_by, '').lower(),
                          reverse=(sort_order == 'desc'))

        # Pagination
        total_users = len(user_list)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_users = user_list[start_idx:end_idx]

        return jsonify({
            'success': True,
            'users': paginated_users,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_users,
                'pages': (total_users + per_page - 1) // per_page
            }
        })

    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return jsonify({'error': 'Failed to get users'}), 500

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user account (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        db = get_firestore_client()

        # Check if user exists
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404

        user_data = user_doc.to_dict()

        # Prevent admin from deleting themselves
        if user_id == session.get('user_id'):
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Prevent deleting other admins (optional security measure)
        if user_data.get('user_type') == 'admin':
            return jsonify({'error': 'Cannot delete admin accounts'}), 400

        # Delete the user
        db.collection('users').document(user_id).delete()

        logger.info(f"Admin {session.get('email')} deleted user {user_data.get('email')}")

        return jsonify({
            'success': True,
            'message': f"User {user_data.get('full_name')} has been deleted successfully"
        })

    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/api/admin/users/<user_id>/suspend', methods=['PUT'])
def suspend_user(user_id):
    """Suspend user account for 7 days (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        from datetime import datetime, timedelta
        from google.cloud import firestore
        db = get_firestore_client()

        # Check if user exists
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404

        user_data = user_doc.to_dict()

        # Prevent admin from suspending themselves
        if user_id == session.get('user_id'):
            return jsonify({'error': 'Cannot suspend your own account'}), 400

        # Prevent suspending other admins
        if user_data.get('user_type') == 'admin':
            return jsonify({'error': 'Cannot suspend admin accounts'}), 400

        # Calculate suspension end date (7 days from now)
        suspension_end = datetime.now() + timedelta(days=7)

        # Update user with suspension
        db.collection('users').document(user_id).update({
            'suspended_until': suspension_end,
            'suspended_by': session.get('user_id'),
            'suspended_at': firestore.SERVER_TIMESTAMP,
            'suspension_reason': 'Administrative action'
        })

        logger.info(f"Admin {session.get('email')} suspended user {user_data.get('email')} until {suspension_end}")

        return jsonify({
            'success': True,
            'message': f"User {user_data.get('full_name')} has been suspended for 7 days",
            'suspended_until': suspension_end.isoformat()
        })

    except Exception as e:
        logger.error(f"Error suspending user: {str(e)}")
        return jsonify({'error': 'Failed to suspend user'}), 500

@app.route('/api/admin/users/<user_id>/activate', methods=['PUT'])
def activate_user(user_id):
    """Reactivate suspended user account (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        from google.cloud import firestore
        db = get_firestore_client()

        # Check if user exists
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404

        user_data = user_doc.to_dict()

        # Remove suspension
        db.collection('users').document(user_id).update({
            'suspended_until': None,
            'reactivated_by': session.get('user_id'),
            'reactivated_at': firestore.SERVER_TIMESTAMP
        })

        logger.info(f"Admin {session.get('email')} reactivated user {user_data.get('email')}")

        return jsonify({
            'success': True,
            'message': f"User {user_data.get('full_name')} has been reactivated"
        })

    except Exception as e:
        logger.error(f"Error reactivating user: {str(e)}")
        return jsonify({'error': 'Failed to reactivate user'}), 500

@app.route('/api/admin/users/<user_id>/details', methods=['GET'])
def get_user_details(user_id):
    """Get detailed user information (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        from datetime import datetime
        db = get_firestore_client()

        # Get user details
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404

        user_data = user_doc.to_dict()
        user_data['user_id'] = user_doc.id

        # Format timestamps
        if user_data.get('created_at'):
            if hasattr(user_data['created_at'], 'timestamp'):
                user_data['created_at'] = datetime.fromtimestamp(user_data['created_at'].timestamp()).isoformat()

        if user_data.get('last_login'):
            if hasattr(user_data['last_login'], 'timestamp'):
                user_data['last_login'] = datetime.fromtimestamp(user_data['last_login'].timestamp()).isoformat()

        # Remove sensitive information
        user_data.pop('password_hash', None)
        user_data.pop('jwt_token', None)

        return jsonify({
            'success': True,
            'user': user_data
        })

    except Exception as e:
        logger.error(f"Error getting user details: {str(e)}")
        return jsonify({'error': 'Failed to get user details'}), 500

@app.route('/api/admin/users/<user_id>/reset-password', methods=['PUT'])
def reset_user_password(user_id):
    """Reset user password (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        from utils.college_auth import CollegeAuthSystem
        from google.cloud import firestore
        import secrets
        import string

        db = get_firestore_client()
        auth_system = CollegeAuthSystem()

        data = request.get_json()
        new_password = data.get('new_password')

        # Check if user exists
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404

        user_data = user_doc.to_dict()

        # Generate random password if not provided
        if not new_password:
            # Generate secure random password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            new_password = ''.join(secrets.choice(alphabet) for _ in range(12))

        # Validate password strength
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400

        # Hash the new password
        password_hash = auth_system.hash_password(new_password)

        # Update user password
        db.collection('users').document(user_id).update({
            'password_hash': password_hash,
            'password_reset_by': session.get('user_id'),
            'password_reset_at': firestore.SERVER_TIMESTAMP,
            'force_password_change': True  # User should change password on next login
        })

        logger.info(f"Admin {session.get('email')} reset password for user {user_data.get('email')}")

        return jsonify({
            'success': True,
            'message': f"Password reset for {user_data.get('full_name')}",
            'new_password': new_password if not data.get('new_password') else None
        })

    except Exception as e:
        logger.error(f"Error resetting password: {str(e)}")
        return jsonify({'error': 'Failed to reset password'}), 500

@app.route('/api/admin/users/<user_id>/edit', methods=['PUT'])
def edit_user(user_id):
    """Edit user details (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from utils.firebase_config import get_firestore_client
        from google.cloud import firestore
        db = get_firestore_client()

        data = request.get_json()

        # Check if user exists
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404

        user_data = user_doc.to_dict()

        # Prevent editing admin accounts (except by themselves)
        if user_data.get('user_type') == 'admin' and user_id != session.get('user_id'):
            return jsonify({'error': 'Cannot edit other admin accounts'}), 400

        # Prepare update data
        update_data = {}

        # Allowed fields to update
        allowed_fields = ['full_name', 'department', 'section']

        for field in allowed_fields:
            if field in data and data[field] is not None:
                update_data[field] = data[field].strip()

        # Add audit trail
        update_data['last_modified_by'] = session.get('user_id')
        update_data['last_modified_at'] = firestore.SERVER_TIMESTAMP

        if update_data:
            db.collection('users').document(user_id).update(update_data)

            logger.info(f"Admin {session.get('email')} updated user {user_data.get('email')}")

            return jsonify({
                'success': True,
                'message': f"User {user_data.get('full_name')} updated successfully"
            })
        else:
            return jsonify({'error': 'No valid fields to update'}), 400

    except Exception as e:
        logger.error(f"Error editing user: {str(e)}")
        return jsonify({'error': 'Failed to edit user'}), 500

@app.route('/api/admin/bookings/force-cancel/<booking_id>', methods=['POST'])
def force_cancel_booking(booking_id):
    """Force cancel a booking (Admin only)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    try:
        data = request.get_json()
        reason = data.get('reason', 'Administrative cancellation')

        room_manager = get_room_manager()
        result = room_manager.force_cancel_booking(booking_id, session['user_id'], reason)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error force cancelling booking: {str(e)}")
        return jsonify({'error': 'Failed to force cancel booking'}), 500

def get_user_features(user_type):
    """Get available features based on user type"""
    features = {
        'student': [
            {'name': 'AI Notes Bot', 'url': '/notes', 'icon': 'robot'},
            {'name': 'My Schedule', 'url': '/schedule', 'icon': 'calendar'},
            {'name': 'Exam Seats', 'url': '/exam-seats', 'icon': 'chair'},
            {'name': 'Submit Complaint', 'url': '/complaint-submission', 'icon': 'message-circle'}
        ],
        'faculty': [
            {'name': 'Upload Notes', 'url': '/notes', 'icon': 'upload'},
            {'name': 'Room Allocation', 'url': '/room-allocation', 'icon': 'map'},
            {'name': 'Complaint Dashboard', 'url': '/complaint-dashboard', 'icon': 'message-square'},
            {'name': 'Student Management', 'url': '/students', 'icon': 'users'},
            {'name': 'Schedule Classes', 'url': '/schedule-classes', 'icon': 'clock'}
        ],
        'admin': [
            {'name': 'User Management', 'url': '/user-management', 'icon': 'settings'},
            {'name': 'Room Management', 'url': '/room-management', 'icon': 'building'},
            {'name': 'Complaint Management', 'url': '/complaint-management', 'icon': 'shield'},
            {'name': 'System Reports', 'url': '/reports', 'icon': 'bar-chart'}
        ]
    }
    return features.get(user_type, [])

# Complaint System Routes

@app.route('/complaint-submission')
def complaint_submission():
    """Complaint submission page for students"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'student':
        flash('Access denied. Student access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('complaint_submission.html', user_data=session)

@app.route('/student-complaint-dashboard')
def student_complaint_dashboard():
    """Student complaint dashboard to view complaint status"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'student':
        flash('Access denied. Student access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('student_complaint_dashboard.html', user_data=session)

@app.route('/complaint-dashboard')
def complaint_dashboard():
    """Complaint dashboard page for faculty"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    if session.get('user_type') != 'faculty':
        flash('Access denied. Faculty access required.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('complaint_dashboard.html', user_data=session)

@app.route('/api/complaints/check-limit', methods=['POST'])
def check_complaint_limit():
    """Check if student can submit complaint today"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'student':
        return jsonify({'error': 'Student access required'}), 403

    if complaint_manager is None:
        return jsonify({'error': 'Complaint system not ready'}), 500

    try:
        student_id = session['user_id']
        result = complaint_manager.check_daily_limit(student_id)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error checking complaint limit: {str(e)}")
        return jsonify({'error': 'Failed to check daily limit'}), 500

@app.route('/api/complaints/submit', methods=['POST'])
def submit_complaint():
    """Submit a new complaint"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'student':
        return jsonify({'error': 'Student access required'}), 403

    if complaint_manager is None:
        return jsonify({'error': 'Complaint system not ready'}), 500

    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['complaint_text', 'faculty_id', 'category']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        # Submit complaint
        result = complaint_manager.submit_complaint(
            student_id=session['user_id'],
            complaint_text=data['complaint_text'],
            faculty_id=data['faculty_id'],
            category=data.get('category', 'general'),
            priority=data.get('priority', 'medium')
        )

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error submitting complaint: {str(e)}")
        return jsonify({'error': 'Failed to submit complaint'}), 500

@app.route('/api/complaints/faculty-list')
def get_faculty_list():
    """Get list of faculty for complaint routing"""
    # Allow anonymous access for complaint submission
    # if 'user_id' not in session:
    #     return jsonify({'error': 'Unauthorized'}), 401

    # Fallback faculty list for when complaint_manager is not available
    fallback_faculty = [
        {
            'faculty_id': 'PROF001',
            'faculty_name': 'Dr. John Smith',
            'department': 'Computer Science'
        },
        {
            'faculty_id': 'PROF002',
            'faculty_name': 'Dr. Jane Doe',
            'department': 'Mathematics'
        },
        {
            'faculty_id': 'PROF003',
            'faculty_name': 'Dr. Alice Johnson',
            'department': 'Physics'
        },
        {
            'faculty_id': 'PROF004',
            'faculty_name': 'Dr. Bob Wilson',
            'department': 'Chemistry'
        },
        {
            'faculty_id': 'PROF005',
            'faculty_name': 'Dr. Carol Brown',
            'department': 'Biology'
        }
    ]

    if complaint_manager is None:
        logger.warning("Complaint manager not ready, using fallback faculty list")
        return jsonify({'faculty': fallback_faculty})

    try:
        faculty_list = complaint_manager.get_faculty_list()
        if not faculty_list:
            logger.warning("No faculty found in database, using fallback list")
            return jsonify({'faculty': fallback_faculty})
        return jsonify({'faculty': faculty_list})

    except Exception as e:
        logger.error(f"Error getting faculty list: {str(e)}")
        return jsonify({'error': 'Failed to get faculty list'}), 500

@app.route('/api/complaints/faculty/<faculty_id>')
def get_faculty_complaints(faculty_id):
    """Get complaints for a specific faculty member"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    # Verify faculty can only access their own complaints
    if session['user_id'] != faculty_id:
        return jsonify({'error': 'Access denied'}), 403

    if complaint_manager is None:
        return jsonify({'error': 'Complaint system not ready'}), 500

    try:
        status = request.args.get('status')
        limit = int(request.args.get('limit', 50))

        complaints = complaint_manager.get_faculty_complaints(faculty_id, status, limit)
        return jsonify({'complaints': complaints})

    except Exception as e:
        logger.error(f"Error getting faculty complaints: {str(e)}")
        return jsonify({'error': 'Failed to get complaints'}), 500

@app.route('/api/complaints/student/my-complaints')
def get_student_complaints():
    """Get complaints for the logged-in student"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'student':
        return jsonify({'error': 'Student access required'}), 403

    if complaint_manager is None:
        return jsonify({'error': 'Complaint system not ready'}), 500

    try:
        student_id = session['user_id']
        complaints = complaint_manager.get_student_complaints(student_id)

        # Add faculty names to complaints
        for complaint in complaints:
            faculty_id = complaint.get('faculty_id')
            if faculty_id:
                try:
                    faculty_doc = get_firestore_client().collection('faculty_routing').document(faculty_id).get()
                    if faculty_doc.exists:
                        faculty_data = faculty_doc.to_dict()
                        complaint['faculty_name'] = faculty_data.get('faculty_name', 'Unknown Faculty')
                    else:
                        complaint['faculty_name'] = 'Unknown Faculty'
                except Exception as e:
                    logger.warning(f"Error getting faculty name for {faculty_id}: {e}")
                    complaint['faculty_name'] = 'Unknown Faculty'

        return jsonify({'success': True, 'complaints': complaints})

    except Exception as e:
        logger.error(f"Error getting student complaints: {str(e)}")
        return jsonify({'error': 'Failed to get complaints'}), 500

@app.route('/api/complaints/update-status', methods=['POST'])
def update_complaint_status():
    """Update complaint status by faculty"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('user_type') != 'faculty':
        return jsonify({'error': 'Faculty access required'}), 403

    if complaint_manager is None:
        return jsonify({'error': 'Complaint system not ready'}), 500

    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        complaint_id = data.get('complaint_id')
        new_status = data.get('status')
        faculty_response = data.get('faculty_response', '')

        if not complaint_id or not new_status:
            return jsonify({'error': 'Complaint ID and status are required'}), 400

        # Verify faculty can only update their own complaints
        faculty_id = session['user_id']

        # Get the complaint to verify faculty ownership
        complaint_doc = get_firestore_client().collection('complaints').document(complaint_id).get()
        if not complaint_doc.exists:
            return jsonify({'error': 'Complaint not found'}), 404

        complaint_data = complaint_doc.to_dict()
        if complaint_data.get('faculty_id') != faculty_id:
            return jsonify({'error': 'Access denied - not your complaint'}), 403

        # Update the complaint status
        result = complaint_manager.update_complaint_status(
            complaint_id=complaint_id,
            new_status=new_status,
            faculty_response=faculty_response
        )

        if result.get('success'):
            return jsonify({'success': True, 'message': 'Status updated successfully'})
        else:
            return jsonify({'error': result.get('error', 'Failed to update status')}), 500

    except Exception as e:
        logger.error(f"Error updating complaint status: {str(e)}")
        return jsonify({'error': 'Failed to update status'}), 500



@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'File too large. Maximum size is 16MB.'}), 413

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)