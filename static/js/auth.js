// Authentication JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize authentication handlers
    initializeAuthHandlers();
    
    // Handle user type selection
    handleUserTypeSelection();
    
    // Handle form validation
    setupFormValidation();
});

function initializeAuthHandlers() {
    // Login form handler
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Registration form handler
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // Password toggle handlers
    setupPasswordToggle();
}

function handleLogin(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const loginData = {
        email: formData.get('email'),
        password: formData.get('password'),
        user_type: formData.get('user_type')
    };
    
    // Validate form
    if (!validateLoginForm(loginData)) {
        return;
    }
    
    // Show loading
    showLoading('Logging in...');
    
    // Submit login request
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(loginData)
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.success) {
            showMessage('Login successful! Redirecting...', 'success');
            setTimeout(() => {
                window.location.href = data.redirect;
            }, 1500);
        } else {
            showMessage(data.error || 'Login failed', 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Login error:', error);
        showMessage('An error occurred during login', 'error');
    });
}

function handleRegister(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const registerData = {
        email: formData.get('email'),
        password: formData.get('password'),
        confirm_password: formData.get('confirm_password'),
        user_type: formData.get('user_type'),
        full_name: formData.get('full_name')
    };
    
    // Add role-specific fields
    const userType = registerData.user_type;
    if (userType === 'student') {
        registerData.student_id = formData.get('student_id');
        registerData.section = formData.get('section');
    } else if (userType === 'faculty') {
        registerData.employee_id = formData.get('employee_id');
        registerData.department = formData.get('department');
    } else if (userType === 'admin') {
        registerData.admin_code = formData.get('admin_code');
    }
    
    // Validate form
    if (!validateRegisterForm(registerData)) {
        return;
    }
    
    // Show loading
    showLoading('Creating account...');
    
    // Submit registration request
    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(registerData)
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.success) {
            showMessage('Registration successful! Please login.', 'success');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showMessage(data.error || 'Registration failed', 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Registration error:', error);
        showMessage('An error occurred during registration', 'error');
    });
}

function handleUserTypeSelection() {
    const userTypeSelect = document.getElementById('user_type');
    if (!userTypeSelect) return;
    
    userTypeSelect.addEventListener('change', function() {
        const userType = this.value;
        const additionalFields = document.getElementById('additional-fields');
        
        if (additionalFields) {
            additionalFields.innerHTML = '';
            
            if (userType === 'student') {
                additionalFields.innerHTML = `
                    <div class="form-group">
                        <label for="student_id">Student ID</label>
                        <input type="text" id="student_id" name="student_id" required>
                    </div>
                    <div class="form-group">
                        <label for="section">Section</label>
                        <input type="text" id="section" name="section" required>
                    </div>
                `;
            } else if (userType === 'faculty') {
                additionalFields.innerHTML = `
                    <div class="form-group">
                        <label for="employee_id">Employee ID</label>
                        <input type="text" id="employee_id" name="employee_id" required>
                    </div>
                    <div class="form-group">
                        <label for="department">Department</label>
                        <select id="department" name="department" required>
                            <option value="">Select Department</option>
                            <option value="Computer Science">Computer Science</option>
                            <option value="Information Technology">Information Technology</option>
                            <option value="Electronics">Electronics</option>
                            <option value="Mechanical">Mechanical</option>
                            <option value="Civil">Civil</option>
                            <option value="Mathematics">Mathematics</option>
                            <option value="Physics">Physics</option>
                            <option value="Chemistry">Chemistry</option>
                        </select>
                    </div>
                `;
            } else if (userType === 'admin') {
                additionalFields.innerHTML = `
                    <div class="form-group">
                        <label for="admin_code">Admin Code</label>
                        <input type="password" id="admin_code" name="admin_code" required>
                        <small class="form-text">Contact IT department for admin code</small>
                    </div>
                `;
            }
        }
    });
}

function setupPasswordToggle() {
    const toggleButtons = document.querySelectorAll('.password-toggle');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
}

function setupFormValidation() {
    // Real-time validation
    const emailInputs = document.querySelectorAll('input[type="email"]');
    emailInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value && !isValidEmail(this.value)) {
                showFieldError(this, 'Please enter a valid email address');
            } else {
                clearFieldError(this);
            }
        });
    });
    
    // Password strength validation - ONLY for registration forms
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        const passwordInput = registerForm.querySelector('input[name="password"]');
        if (passwordInput) {
            passwordInput.addEventListener('input', function() {
                const strength = checkPasswordStrength(this.value);
                showPasswordStrength(this, strength);
            });
        }
    }
}

function validateLoginForm(data) {
    let isValid = true;
    
    // Email validation
    if (!data.email) {
        showMessage('Email is required', 'error');
        isValid = false;
    } else if (!isValidEmail(data.email)) {
        showMessage('Please enter a valid email address', 'error');
        isValid = false;
    }
    
    // Password validation - only check if it's provided
    if (!data.password) {
        showMessage('Password is required', 'error');
        isValid = false;
    }
    
    // User type validation
    if (!data.user_type) {
        showMessage('Please select a user type', 'error');
        isValid = false;
    }
    
    return isValid;
}

function validateRegisterForm(data) {
    let isValid = true;
    
    // Email validation
    if (!data.email) {
        showMessage('Email is required', 'error');
        isValid = false;
    } else if (!isValidEmail(data.email)) {
        showMessage('Please enter a valid email address', 'error');
        isValid = false;
    }
    
    // Password validation
    if (!data.password) {
        showMessage('Password is required', 'error');
        isValid = false;
    } else if (data.password.length < 8) {
        showMessage('Password must be at least 8 characters long', 'error');
        isValid = false;
    }
    
    // Confirm password validation
    if (data.password !== data.confirm_password) {
        showMessage('Passwords do not match', 'error');
        isValid = false;
    }
    
    // Full name validation
    if (!data.full_name) {
        showMessage('Full name is required', 'error');
        isValid = false;
    }
    
    // Role-specific validation
    if (data.user_type === 'student') {
        if (!data.student_id) {
            showMessage('Student ID is required', 'error');
            isValid = false;
        }
        if (!data.section) {
            showMessage('Section is required', 'error');
            isValid = false;
        }
    } else if (data.user_type === 'faculty') {
        if (!data.employee_id) {
            showMessage('Employee ID is required', 'error');
            isValid = false;
        }
        if (!data.department) {
            showMessage('Department is required', 'error');
            isValid = false;
        }
    } else if (data.user_type === 'admin') {
        if (!data.admin_code) {
            showMessage('Admin code is required', 'error');
            isValid = false;
        }
    }
    
    return isValid;
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function checkPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]+/)) strength++;
    if (password.match(/[A-Z]+/)) strength++;
    if (password.match(/[0-9]+/)) strength++;
    if (password.match(/[^a-zA-Z0-9]+/)) strength++;
    
    return strength;
}

function showPasswordStrength(input, strength) {
    let strengthText = '';
    let strengthClass = '';
    
    switch (strength) {
        case 0:
        case 1:
            strengthText = 'Very Weak';
            strengthClass = 'strength-very-weak';
            break;
        case 2:
            strengthText = 'Weak';
            strengthClass = 'strength-weak';
            break;
        case 3:
            strengthText = 'Medium';
            strengthClass = 'strength-medium';
            break;
        case 4:
            strengthText = 'Strong';
            strengthClass = 'strength-strong';
            break;
        case 5:
            strengthText = 'Very Strong';
            strengthClass = 'strength-very-strong';
            break;
    }
    
    // Show strength indicator
    let strengthIndicator = input.parentNode.querySelector('.password-strength');
    if (!strengthIndicator) {
        strengthIndicator = document.createElement('div');
        strengthIndicator.className = 'password-strength';
        input.parentNode.appendChild(strengthIndicator);
    }
    
    strengthIndicator.textContent = strengthText;
    strengthIndicator.className = `password-strength ${strengthClass}`;
}

function showFieldError(input, message) {
    input.classList.add('error');
    
    let errorElement = input.parentNode.querySelector('.field-error');
    if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.className = 'field-error';
        input.parentNode.appendChild(errorElement);
    }
    
    errorElement.textContent = message;
}

function clearFieldError(input) {
    input.classList.remove('error');
    
    const errorElement = input.parentNode.querySelector('.field-error');
    if (errorElement) {
        errorElement.remove();
    }
}

function showLoading(message) {
    const loadingDiv = document.getElementById('loading') || createLoadingDiv();
    loadingDiv.style.display = 'block';
    loadingDiv.querySelector('.loading-text').textContent = message;
}

function hideLoading() {
    const loadingDiv = document.getElementById('loading');
    if (loadingDiv) {
        loadingDiv.style.display = 'none';
    }
}

function createLoadingDiv() {
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loading';
    loadingDiv.className = 'loading-overlay';
    loadingDiv.innerHTML = `
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">Processing...</div>
        </div>
    `;5
    document.body.appendChild(loadingDiv);
    return loadingDiv;
}

function showMessage(message, type) {
    const messageDiv = document.getElementById('message') || createMessageDiv();
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    messageDiv.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 5000);
}

function createMessageDiv() {
    const messageDiv = document.createElement('div');
    messageDiv.id = 'message';
    messageDiv.className = 'message';
    document.body.appendChild(messageDiv);
    return messageDiv;
}
