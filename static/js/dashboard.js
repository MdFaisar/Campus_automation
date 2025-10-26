// Dashboard JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard
    initializeDashboard();
    
    // Setup feature cards
    setupFeatureCards();
    
    // Setup user menu
    setupUserMenu();
    
    // Load dashboard data
    loadDashboardData();
});

function initializeDashboard() {
    // Welcome animation
    const welcomeSection = document.querySelector('.welcome-section');
    if (welcomeSection) {
        welcomeSection.style.opacity = '0';
        welcomeSection.style.transform = 'translateY(-20px)';
        
        setTimeout(() => {
            welcomeSection.style.transition = 'all 0.5s ease';
            welcomeSection.style.opacity = '1';
            welcomeSection.style.transform = 'translateY(0)';
        }, 100);
    }
    
    // Feature cards animation
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 200 + (index * 100));
    });
}

function setupFeatureCards() {
    const featureCards = document.querySelectorAll('.feature-card');
    
    featureCards.forEach(card => {
        // Add hover effects
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.boxShadow = '0 8px 25px rgba(0,0,0,0.15)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 2px 10px rgba(0,0,0,0.1)';
        });
        
        // Add click handler
        card.addEventListener('click', function() {
            const url = this.dataset.url;
            if (url) {
                // Add click animation
                this.style.transform = 'scale(0.95)';
                
                setTimeout(() => {
                    window.location.href = url;
                }, 150);
            }
        });
    });
}

function setupUserMenu() {
    const userMenuToggle = document.getElementById('user-menu-toggle');
    const userMenuDropdown = document.getElementById('user-menu-dropdown');
    
    if (userMenuToggle && userMenuDropdown) {
        userMenuToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            userMenuDropdown.classList.toggle('show');
        });
        
        // Close menu when clicking outside
        document.addEventListener('click', function(e) {
            if (!userMenuToggle.contains(e.target)) {
                userMenuDropdown.classList.remove('show');
            }
        });
    }
    
    // Logout handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            handleLogout();
        });
    }
}

function handleLogout() {
    // Show confirmation
    if (confirm('Are you sure you want to logout?')) {
        // Show loading
        showLoading('Logging out...');
        
        // Redirect to logout
        window.location.href = '/logout';
    }
}

function loadDashboardData() {
    const userType = getUserType();
    
    // Load user-specific data
    switch (userType) {
        case 'student':
            loadStudentData();
            break;
        case 'faculty':
            loadFacultyData();
            break;
        case 'admin':
            loadAdminData();
            break;
    }
    
    // Load recent activities
    loadRecentActivities();
    
    // Load notifications
    loadNotifications();
}

function loadStudentData() {
    // Load student-specific dashboard data
    const statsContainer = document.querySelector('.stats-container');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-book"></i>
                </div>
                <div class="stat-info">
                    <h3 id="total-notes">-</h3>
                    <p>Notes Available</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-calendar"></i>
                </div>
                <div class="stat-info">
                    <h3 id="upcoming-classes">-</h3>
                    <p>Upcoming Classes</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-clipboard-check"></i>
                </div>
                <div class="stat-info">
                    <h3 id="pending-exams">-</h3>
                    <p>Pending Exams</p>
                </div>
            </div>
        `;
        
        // Load actual data
        loadNotesCount();
        loadUpcomingClasses();
        loadPendingExams();
    }
}

function loadFacultyData() {
    // Load faculty-specific dashboard data
    const statsContainer = document.querySelector('.stats-container');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-upload"></i>
                </div>
                <div class="stat-info">
                    <h3 id="uploaded-notes">-</h3>
                    <p>Uploaded Notes</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-info">
                    <h3 id="total-students">-</h3>
                    <p>Total Students</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-chalkboard-teacher"></i>
                </div>
                <div class="stat-info">
                    <h3 id="scheduled-classes">-</h3>
                    <p>Scheduled Classes</p>
                </div>
            </div>
        `;
        
        // Load actual data
        loadUploadedNotes();
        loadTotalStudents();
        loadScheduledClasses();
    }
}

function loadAdminData() {
    // Load admin-specific dashboard data
    const statsContainer = document.querySelector('.stats-container');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-users-cog"></i>
                </div>
                <div class="stat-info">
                    <h3 id="total-users">-</h3>
                    <p>Total Users</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-building"></i>
                </div>
                <div class="stat-info">
                    <h3 id="total-rooms">-</h3>
                    <p>Total Rooms</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="stat-info">
                    <h3 id="pending-complaints">-</h3>
                    <p>Pending Complaints</p>
                </div>
            </div>
        `;
        
        // Load actual data
        loadTotalUsers();
        loadTotalRooms();
        loadPendingComplaints();
    }
}

function loadNotesCount() {
    fetch('/api/notes/list')
        .then(response => response.json())
        .then(data => {
            if (data.notes) {
                document.getElementById('total-notes').textContent = data.notes.length;
            }
        })
        .catch(error => {
            console.error('Error loading notes count:', error);
            document.getElementById('total-notes').textContent = '0';
        });
}

function loadUpcomingClasses() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('upcoming-classes').textContent = '3';
    }, 500);
}

function loadPendingExams() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('pending-exams').textContent = '2';
    }, 700);
}

function loadUploadedNotes() {
    fetch('/api/notes/list')
        .then(response => response.json())
        .then(data => {
            if (data.notes) {
                document.getElementById('uploaded-notes').textContent = data.notes.length;
            }
        })
        .catch(error => {
            console.error('Error loading uploaded notes:', error);
            document.getElementById('uploaded-notes').textContent = '0';
        });
}

function loadTotalStudents() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('total-students').textContent = '150';
    }, 500);
}

function loadScheduledClasses() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('scheduled-classes').textContent = '8';
    }, 700);
}

function loadTotalUsers() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('total-users').textContent = '245';
    }, 500);
}

function loadTotalRooms() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('total-rooms').textContent = '35';
    }, 700);
}

function loadPendingComplaints() {
    // Mock data for now
    setTimeout(() => {
        document.getElementById('pending-complaints').textContent = '7';
    }, 900);
}

function loadRecentActivities() {
    const activitiesContainer = document.querySelector('.recent-activities');
    if (!activitiesContainer) return;
    
    // Mock recent activities
    const activities = [
        {
            type: 'notes',
            message: 'New notes uploaded for Data Structures',
            time: '2 hours ago',
            icon: 'fas fa-file-alt'
        },
        {
            type: 'schedule',
            message: 'Class schedule updated for tomorrow',
            time: '4 hours ago',
            icon: 'fas fa-calendar-alt'
        },
        {
            type: 'exam',
            message: 'Exam seating arrangement published',
            time: '1 day ago',
            icon: 'fas fa-clipboard-check'
        }
    ];
    
    activitiesContainer.innerHTML = `
        <h3>Recent Activities</h3>
        <div class="activity-list">
            ${activities.map(activity => `
                <div class="activity-item">
                    <div class="activity-icon">
                        <i class="${activity.icon}"></i>
                    </div>
                    <div class="activity-content">
                        <p>${activity.message}</p>
                        <small>${activity.time}</small>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function loadNotifications() {
    const notificationsContainer = document.querySelector('.notifications');
    if (!notificationsContainer) return;
    
    // Mock notifications
    const notifications = [
        {
            type: 'info',
            message: 'System maintenance scheduled for this weekend',
            time: '1 hour ago'
        },
        {
            type: 'success',
            message: 'Your complaint has been resolved',
            time: '3 hours ago'
        },
        {
            type: 'warning',
            message: 'Assignment submission deadline approaching',
            time: '6 hours ago'
        }
    ];
    
    notificationsContainer.innerHTML = `
        <h3>Notifications</h3>
        <div class="notification-list">
            ${notifications.map(notification => `
                <div class="notification-item ${notification.type}">
                    <p>${notification.message}</p>
                    <small>${notification.time}</small>
                </div>
            `).join('')}
        </div>
    `;
}

function getUserType() {
    // Extract user type from page data or session
    const userDataElement = document.querySelector('[data-user-type]');
    return userDataElement ? userDataElement.dataset.userType : 'student';
}

