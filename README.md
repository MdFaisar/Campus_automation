#README.md

# College Management System

## About
A comprehensive college management system featuring automated class/lab allocation, exam seating management, AI-powered notes bot, anonymous complaint system, and email automation.

## Features
- **Automated Class/Lab Allocation**: Real-time room availability and intelligent scheduling
- **Exam Seating Logic**: Advanced algorithm preventing same section/gender adjacency
- **AI Notes Bot**: LLaMA 3.3-70b powered RAG system for student queries
- **Anonymous Complaint System**: Blockchain-based encrypted complaint submission
- **Email Automation**: Automated notifications via n8n workflows

## Technical Stack
- **Frontend**: HTML, CSS (External)
- **Backend**: Flask (Python)
- **Database**: Firebase
- **AI Model**: LLaMA 3.3-70b via Groq
- **Automation**: n8n
- **Blockchain**: Multichain
- **Authentication**: Firebase Auth

## File Structure
```
college-management-system/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── README.md                      # Project documentation
├── static/
│   ├── css/
│   │   ├── main.css              # Main stylesheet
│   │   ├── login.css             # Login page styles
│   │   ├── dashboard.css         # Dashboard styles
│   │   └── notes.css             # Notes bot styles
│   └── js/
│       ├── main.js               # Main JavaScript
│       ├── auth.js               # Authentication logic
│       ├── dashboard.js          # Dashboard functionality
│       └── notes.js              # Notes bot functionality
├── templates/
│   ├── base.html                 # Base template
│   ├── login.html                # Login page
│   ├── register.html             # Registration page
│   ├── dashboard.html            # Dashboard page
│   └── notes.html                # AI Notes Bot page
├── utils/
│   ├── __init__.py
│   ├── auth.py                   # Authentication utilities
│   ├── firebase_config.py        # Firebase configuration
│   ├── rag_system.py             # RAG implementation
│   └── email_automation.py       # n8n integration
├── uploads/                      # Directory for uploaded files
└── config/
    ├── firebase_config.json     # Firebase credentials
    └── n8n_workflows.json       # n8n workflow definitions
```

## Installation & Setup

### Prerequisites
- Python 3.8+
- Firebase account
- Groq API key
- n8n instance
- Multichain setup

### Installation Steps

1. **Clone the repository**
```bash
git clone <repository-url>
cd college-management-system
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Firebase Setup**
- Create a Firebase project
- Enable Authentication and Firestore
- Download configuration and place in `config/firebase_config.json`

4. **Environment Variables**
Create a `.env` file:
```
GROQ_API_KEY=your_groq_api_key
FIREBASE_CONFIG_PATH=config/firebase_config.json
N8N_WEBHOOK_URL=your_n8n_webhook_url
MULTICHAIN_RPC_URL=your_multichain_rpc_url
```

5. **Run the application**
```bash
python app.py
```

## Implementation Guide

### Phase 1: Authentication System
- Set up Firebase Authentication
- Create login/registration pages
- Implement role-based access (Student, Faculty, Admin)

### Phase 2: Dashboard Development
- Create role-specific dashboards
- Implement feature navigation
- Add basic CRUD operations

### Phase 3: AI Notes Bot (RAG System)
- Set up document upload functionality
- Implement RAG with LLaMA 3.3-70b
- Create chat interface for students

### Phase 4: Advanced Features
- Room allocation system
- Exam seating algorithm
- Blockchain complaint system

### Phase 5: Automation
- n8n workflow integration
- Email notification system
- Automated scheduling

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/logout` - User logout

### Notes Bot
- `POST /api/notes/upload` - Upload notes (Faculty only)
- `POST /api/notes/query` - Query the AI bot (Students)
- `GET /api/notes/list` - List available notes

### Automation
- `POST /api/automation/schedule` - Trigger scheduling
- `POST /api/automation/notify` - Send notifications

## Security Features
- Firebase Authentication
- Role-based access control
- Encrypted file storage
- Blockchain-based anonymity
- Input validation and sanitization

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
This project is licensed under the MIT License.

## Support
For support and questions, please contact the development team.