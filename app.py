from flask import Flask, render_template, redirect, url_for, request, send_file, flash, abort, session, jsonify, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, UserFile, SiteSettings, IconSettings, BackupSettings, BackupHistory, FileShare, ShareAccessLog
from werkzeug.utils import secure_filename
from functools import wraps
import os
import secrets
import humanize
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
from pathlib import Path
import shutil
import zipfile
import time
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY_FILE = BASE_DIR / 'secret_key.txt'

app = Flask(__name__)

def str_to_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}

def load_or_create_secret_key():
    """Load secret key from environment or file, otherwise generate one."""
    env_key = os.getenv('FLASK_SECRET_KEY') or os.getenv('SECRET_KEY')
    if env_key:
        return env_key.strip()
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text(encoding='utf-8').strip()
    new_key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(new_key, encoding='utf-8')
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        # Best effort only; ignore if platform does not support chmod or permissions already strict
        pass
    return new_key

def persist_secret_key(new_key):
    """Persist a freshly generated secret key to disk and in-memory config."""
    SECRET_KEY_FILE.write_text(new_key, encoding='utf-8')
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    app.config['SECRET_KEY'] = new_key

app.config['SECRET_KEY'] = load_or_create_secret_key()

# Configure session security
is_development = str_to_bool(os.getenv('FLASK_DEBUG')) or os.getenv('FLASK_ENV') == 'development'
app.config['SESSION_COOKIE_SECURE'] = str_to_bool(os.getenv('SESSION_COOKIE_SECURE'), default=not is_development)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Strict')
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Short session lifetime
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 60 * 60 * 24  # 24 hours

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sephosting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = str((BASE_DIR / 'user_uploads').resolve())
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Ensure instance folder exists
os.makedirs(BASE_DIR / 'instance', exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# Disable the redirect for unauthorized access to prevent redirect loops
login_manager.login_message = None

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)

# Initialize SQLAlchemy
db.init_app(app)

@app.context_processor
def inject_csrf_token():
    """Expose csrf_token() helper in templates without requiring FlaskForm."""
    return {'csrf_token': lambda: generate_csrf()}

# Function to set no-cache headers
def set_no_cache_headers(response):
    """Set headers to prevent caching for sensitive pages"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Decorator to prevent caching for sensitive routes
def no_cache(view_function):
    @wraps(view_function)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view_function(*args, **kwargs))
        return set_no_cache_headers(response)
    return no_cache_impl

# Set session cookie settings for better security
@app.before_request
def enforce_session_security():
    """Maintain secure session settings and handle idle timeouts."""
    if request.endpoint in {'static'} or request.endpoint is None:
        return None

    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

    if not current_user.is_authenticated:
        return None

    last_activity = session.get('last_activity')
    now_ts = int(time.time())

    if last_activity and now_ts - int(last_activity) > 1800:
        logout_user()
        # Preserve flash messages by leaving _flashes intact
        clear_session_except_flashes()

        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'success': False, 'error': 'Session expired'}), 401

        flash('Your session has expired. Please log in again.', 'error')
        return redirect(url_for('login'))

    session['last_activity'] = now_ts

@login_manager.user_loader
def load_user(user_id):
    # Try to load the user from the database
    user = User.query.get(user_id)
    
    # If user doesn't exist anymore, return None to force logout
    if user is None:
        return None
        
    return user

# Admin requirement decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # EMERGENCY FIX: Simplify admin check to avoid redirect loops
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
            
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# File Sharing Helper Functions
# ============================================================================

def generate_share_token():
    """
    Generate a cryptographically secure share token
    
    Returns:
        str: 32-character URL-safe token
    """
    return secrets.token_urlsafe(32)

def calculate_expiration(expiration_option):
    """
    Calculate expiration datetime from option
    
    Parameters:
        expiration_option (str): One of ['1h', '24h', '7d', '30d', 'never']
    
    Returns:
        datetime or None: Expiration datetime or None for 'never'
    """
    if expiration_option == 'never':
        return None
    
    expiration_map = {
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30)
    }
    
    delta = expiration_map.get(expiration_option)
    if delta:
        return datetime.utcnow() + delta
    return None

def is_share_valid(share):
    """
    Check if a share is valid and accessible
    
    Parameters:
        share (FileShare): FileShare object
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not share.is_active:
        return False, "This share link has been revoked"
    
    if share.expires_at and datetime.utcnow() > share.expires_at:
        return False, "This share link has expired"
    
    if share.max_downloads and share.download_count >= share.max_downloads:
        return False, "Download limit reached for this file"
    
    if not share.file or not os.path.exists(share.file.filepath):
        return False, "The shared file no longer exists"
    
    return True, None

def verify_share_password(share, password):
    """
    Verify password for password-protected share
    
    Parameters:
        share (FileShare): FileShare object
        password (str): Plain text password to verify
    
    Returns:
        bool: True if password matches
    """
    if not share.password_hash:
        return True
    return check_password_hash(share.password_hash, password)

def log_share_access(share_id, action, success=True):
    """
    Log an access attempt to a shared file
    
    Parameters:
        share_id (str): FileShare ID
        action (str): 'view', 'download', 'password_fail'
        success (bool): Whether the action succeeded
    """
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')[:512]
    
    access_log = ShareAccessLog(
        share_id=share_id,
        ip_address=ip_address,
        user_agent=user_agent,
        action=action,
        success=success
    )
    db.session.add(access_log)
    db.session.commit()

def check_rate_limit(share_id, ip_address):
    """
    Check if IP has exceeded rate limit for password attempts
    
    Parameters:
        share_id (str): FileShare ID
        ip_address (str): Client IP address
    
    Returns:
        tuple: (is_allowed: bool, retry_after: int)
    """
    time_threshold = datetime.utcnow() - timedelta(minutes=15)
    
    failed_attempts = ShareAccessLog.query.filter(
        ShareAccessLog.share_id == share_id,
        ShareAccessLog.ip_address == ip_address,
        ShareAccessLog.action == 'password_fail',
        ShareAccessLog.accessed_at >= time_threshold
    ).count()
    
    if failed_attempts >= 5:
        return False, 15 * 60  # 15 minutes in seconds
    
    return True, 0

# Replace the before_first_request decorator with an initialization function
def create_default_admin():
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        
        # Check if any admin user already exists
        admin_exists = User.query.filter_by(is_admin=True).first() is not None
        
        if not admin_exists:
            print("Creating default administrator user...")
            admin = User(
                username='Admin',
                email='admin@sephosting.com',
                password_hash=generate_password_hash('Admin'),
                is_admin=True,
                storage_limit=10 * 1024 * 1024 * 1024,  # 10GB
                is_first_login=True  # Ensure this is set to True
            )
            
            # Make sure we save the user to the database
            try:
                db.session.add(admin)
                db.session.commit()
                print("Default administrator user created successfully!")
            except Exception as e:
                db.session.rollback()
                print(f"Error creating default admin: {str(e)}")
        else:
            print("Administrator user already exists, skipping default admin creation.")
        
        # Always initialize default settings, even if admin already exists
        initialize_default_settings()
        initialize_default_icons()

def initialize_default_settings():
    # Initialize default site settings if they don't exist
    default_settings = {
        'site_title': 'Sephosting',
        'site_description': 'Your private cloud storage solution that respects your digital privacy',
        'feature_1_title': 'Zero-Knowledge Encryption',
        'feature_1_description': 'Your files are encrypted before they leave your device. Not even we can access them.',
        'feature_2_title': 'Strict Privacy Policy',
        'feature_2_description': 'We never sell your data or share it with third parties. Your privacy is our priority.',
        'footer_text': 'Sephosting - Secure Cloud Storage',
        'default_storage_limit': '5'  # 5GB default for new users
    }
    
    for key, value in default_settings.items():
        if not SiteSettings.query.filter_by(setting_key=key).first():
            print(f"Initializing default setting: {key}")
            setting = SiteSettings(setting_key=key, setting_value=value)
            db.session.add(setting)
    
    db.session.commit()

def initialize_default_icons():
    # Initialize default icons if they don't exist
    default_icons = {
        'feature_1_icon': '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>',
        'feature_2_icon': '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>'
    }
    
    for key, value in default_icons.items():
        if not IconSettings.query.filter_by(icon_key=key).first():
            print(f"Initializing default icon: {key}")
            icon = IconSettings(icon_key=key, icon_svg=value)
            db.session.add(icon)
    
    db.session.commit()

@app.route('/')
def home():
    # Get site settings with defaults
    site_settings = {
        'site_title': SiteSettings.get_setting('site_title', 'Sephosting'),
        'site_description': SiteSettings.get_setting('site_description', 'Your private cloud storage solution that respects your digital privacy'),
        'feature_1_title': SiteSettings.get_setting('feature_1_title', 'Zero-Knowledge Encryption'),
        'feature_1_description': SiteSettings.get_setting('feature_1_description', 'Your files are encrypted before they leave your device. Not even we can access them.'),
        'feature_2_title': SiteSettings.get_setting('feature_2_title', 'Strict Privacy Policy'),
        'feature_2_description': SiteSettings.get_setting('feature_2_description', 'We never sell your data or share it with third parties. Your privacy is our priority.'),
        'footer_text': SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    }
    
    # Get icon settings with defaults
    icon_settings = {
        'feature_1_icon': IconSettings.get_icon('feature_1_icon', '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'),
        'feature_2_icon': IconSettings.get_icon('feature_2_icon', '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>')
    }
    
    return render_template('home.html', now=datetime.utcnow(), settings=site_settings, icons=icon_settings)

@app.route('/login', methods=['GET', 'POST'])
@no_cache
def login():
    session.pop('_flashes', None)

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        remember = 'remember' in request.form

        # Special case for default admin credentials
        if username.lower() == 'admin' and password == 'Admin':
            # Check if any admin exists
            admin_exists = User.query.filter_by(is_admin=True).first() is not None

            if not admin_exists:
                # No admin exists, create the default admin
                print("Creating default administrator user via login...")
                admin = User(
                    username='Admin',
                    email='admin@sephosting.com',
                    password_hash=generate_password_hash('Admin'),
                    is_admin=True,
                    storage_limit=10 * 1024 * 1024 * 1024,  # 10GB
                    is_first_login=True
                )

                # Make sure we save the user to the database
                try:
                    db.session.add(admin)
                    db.session.commit()
                    print("Default administrator user created successfully!")
                except Exception as e:
                    db.session.rollback()
                    print(f"Error creating default admin: {str(e)}")

                # Log in the new admin
                login_user(admin, remember=remember)

                # Set last activity time
                session['last_activity'] = int(time.time())

                flash('Default administrator account created. Please change your credentials.', 'success')
                return redirect(url_for('change_credentials'))
            elif User.query.filter(User.is_admin == True, User.is_first_login == False).first() is not None:
                # Admin exists and has changed credentials
                flash('Default administrator credentials have been changed. Please use the new credentials.', 'error')
                return render_template('login.html', now=datetime.utcnow())

        user = User.query.filter((User.username == username) | (User.email == username)).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)

            # Set last activity time
            session['last_activity'] = int(time.time())

            # If this is the admin's first login, redirect to the credentials change page
            if user.is_first_login:
                return redirect(url_for('change_credentials'))

            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', now=datetime.utcnow())

@app.route('/change_credentials', methods=['GET', 'POST'])
@login_required
@no_cache
def change_credentials():
    if not current_user.is_first_login:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_username = (request.form.get('new_username') or '').strip()
        new_email = (request.form.get('new_email') or '').strip()
        new_password = request.form.get('new_password') or ''
        confirm_password = request.form.get('confirm_password') or ''
        rotate_secret = request.form.get('rotate_secret_key') == 'on'

        if not new_username or not new_email or not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())

        if len(new_password) < 12:
            flash('Password must be at least 12 characters long.', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())

        if '@' not in new_email:
            flash('Please provide a valid email address.', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())

        if new_username != current_user.username and User.query.filter_by(username=new_username).first():
            flash('Username is already taken', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())

        if new_email != current_user.email and User.query.filter_by(email=new_email).first():
            flash('Email is already taken', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())

        current_user.username = new_username
        current_user.email = new_email
        current_user.password_hash = generate_password_hash(new_password)
        current_user.is_first_login = False

        db.session.commit()

        if rotate_secret:
            persist_secret_key(secrets.token_hex(32))
            flash('Application secret key regenerated. All users will need to re-authenticate.', 'info')

        session['last_activity'] = int(time.time())
        flash('Your credentials have been updated successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_credentials.html', now=datetime.utcnow())

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Clear old flash messages at the beginning of the function
    session.pop('_flashes', None)
    
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('register.html', now=datetime.utcnow())

        # Prevent creating users with reserved usernames (case insensitive)
        # But only if an admin already exists
        if username.lower() == 'admin':
            admin_exists = User.query.filter_by(is_admin=True).first() is not None
            if admin_exists:
                flash('This username is reserved. Please choose another one.', 'error')
                return render_template('register.html', now=datetime.utcnow())

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken', 'error')
            return render_template('register.html', now=datetime.utcnow())
        
        # Check if the email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered', 'error')
            return render_template('register.html', now=datetime.utcnow())

        if '@' not in email:
            flash('Please provide a valid email address.', 'error')
            return render_template('register.html', now=datetime.utcnow())

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html', now=datetime.utcnow())

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html', now=datetime.utcnow())
        
        # Get default storage limit (in GB)
        default_storage_gb = int(SiteSettings.get_setting('default_storage_limit', '5'))
        # Convert to bytes
        storage_limit = default_storage_gb * 1024 * 1024 * 1024
        
        # Create a new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            storage_limit=storage_limit
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', now=datetime.utcnow())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    clear_session_except_flashes()
    flash('You have been logged out securely.', 'success')
    return redirect(url_for('home'))

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Remove file type restrictions
ALLOWED_EXTENSIONS = set()  # Accept all file types

def allowed_file(filename):
    """Check if the file is allowed"""
    return True  # Accept all file types

def safe_storage_path(*segments):
    """Safely build a path inside the configured upload directory."""
    base_path = Path(app.config['UPLOAD_FOLDER']).resolve()
    target_path = base_path.joinpath(*segments).resolve()
    if not str(target_path).startswith(str(base_path)):
        raise ValueError('Unsafe storage path detected')
    return target_path

def is_safe_storage_path(path):
    """Verify that a path stays within the upload directory."""
    base_path = Path(app.config['UPLOAD_FOLDER']).resolve()
    try:
        Path(path).resolve().relative_to(base_path)
        return True
    except ValueError:
        return False

def determine_content_length(file_storage):
    """Best-effort detection of the uploaded file size in bytes."""
    if getattr(file_storage, 'content_length', None):
        return int(file_storage.content_length)
    stream = getattr(file_storage, 'stream', None)
    if stream and hasattr(stream, 'tell') and hasattr(stream, 'seek'):
        current_position = stream.tell()
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(current_position)
        return int(size)
    return 0

def clear_session_except_flashes():
    """Remove all session data except flashed messages."""
    for key in list(session.keys()):
        if key != '_flashes':
            session.pop(key, None)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        # Check user's storage limit before uploading
        user_storage = current_user.get_used_storage()
        estimated_size = request.content_length or determine_content_length(file)

        if estimated_size and user_storage + int(estimated_size) > current_user.storage_limit:
            flash('Storage limit exceeded', 'error')
            return redirect(url_for('dashboard'))

        # Save the file
        filename = secure_filename(file.filename)
        try:
            user_dir = safe_storage_path(str(current_user.id))
            os.makedirs(user_dir, exist_ok=True)
            filepath = safe_storage_path(str(current_user.id), filename)
        except ValueError:
            flash('Invalid upload path detected.', 'error')
            return redirect(url_for('dashboard'))

        file.save(str(filepath))

        # Create file record
        new_file = UserFile(
            filename=filename,
            filepath=str(filepath),
            user_id=current_user.id
        )

        # Save file size
        actual_size = new_file.save_filesize()

        if user_storage + actual_size > current_user.storage_limit:
            # Remove the file and abort the upload
            if filepath.exists():
                filepath.unlink()
            flash('Storage limit exceeded', 'error')
            return redirect(url_for('dashboard'))

        db.session.add(new_file)
        db.session.commit()

        flash('File uploaded successfully', 'success')
        return redirect(url_for('dashboard'))
    
    flash('Invalid file type', 'error')
    return redirect(url_for('dashboard'))

@app.route('/chunk-upload', methods=['POST'])
@login_required
def chunk_upload():
    """Handles file uploads (simplified version)"""
    try:
        # Check if a file was sent
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file sent'}), 400
            
        file = request.files['file']
        
        # Check if the file has a name
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
            
        # Get the filename
        filename = secure_filename(file.filename)
        
        # Check if the file is allowed
        if not allowed_file(filename):
            return jsonify({'success': False, 'error': 'File type not allowed'}), 400
            
        # Check storage limit
        filesize = request.content_length or determine_content_length(file)
        user_storage = current_user.get_used_storage()

        if filesize and user_storage + int(filesize) > current_user.storage_limit:
            return jsonify({'success': False, 'error': 'Storage limit exceeded'}), 400

        # Create user folder if it doesn't exist
        try:
            user_dir = safe_storage_path(str(current_user.id))
            os.makedirs(user_dir, exist_ok=True)
            filepath = safe_storage_path(str(current_user.id), filename)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid upload path detected'}), 400

        # Full file path
        filepath = Path(filepath)
        
        # Check if file with same name already exists in database
        existing_file = UserFile.query.filter_by(
            user_id=current_user.id,
            filename=filename
        ).first()
        
        if existing_file:
            # Delete old file from disk if it exists
            if os.path.exists(existing_file.filepath):
                try:
                    os.remove(existing_file.filepath)
                except OSError:
                    pass
            
            # Delete associated shares
            shares = FileShare.query.filter_by(file_id=existing_file.id).all()
            for share in shares:
                ShareAccessLog.query.filter_by(share_id=share.id).delete()
                db.session.delete(share)
            
            # Delete the old database entry
            db.session.delete(existing_file)
            db.session.commit()

        # Save the file
        print(f"Saving file {filename} to {filepath}")
        file.save(str(filepath))

        # Check that the file was saved correctly
        if not filepath.exists():
            return jsonify({'success': False, 'error': 'Error saving the file'}), 500

        # Create database entry
        new_file = UserFile(
            filename=filename,
            filepath=str(filepath),
            user_id=current_user.id
        )

        # Save file size
        actual_size = new_file.save_filesize()

        if user_storage + actual_size > current_user.storage_limit:
            if filepath.exists():
                filepath.unlink()
            return jsonify({'success': False, 'error': 'Storage limit exceeded'}), 400

        db.session.add(new_file)
        db.session.commit()
        print(f"File {filename} recorded in database")

        updated_storage = current_user.get_used_storage()
        storage_percentage = current_user.get_storage_percentage()

        file_payload = {
            'id': new_file.id,
            'filename': new_file.filename,
            'filesize_bytes': new_file.filesize,
            'filesize_mb': round(new_file.filesize / (1024 * 1024), 2),
            'download_url': url_for('download', file_id=new_file.id),
            'delete_url': url_for('delete_file', file_id=new_file.id),
            'uploaded_at_iso': new_file.uploaded_at.isoformat(),
            'uploaded_at_display': new_file.uploaded_at.strftime('%B %d, %Y at %H:%M'),
        }

        storage_payload = {
            'used_bytes': updated_storage,
            'limit_bytes': current_user.storage_limit,
            'used_display': humanize.naturalsize(updated_storage, binary=False),
            'limit_display': humanize.naturalsize(current_user.storage_limit, binary=False),
            'percentage': storage_percentage
        }

        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file': file_payload,
            'storage': storage_payload
        }), 200
        
    except Exception as e:
        print(f"Error during upload: {str(e)}")
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/download/<string:file_id>')
@login_required
def download(file_id):
    file = UserFile.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if not is_safe_storage_path(file.filepath):
        abort(400)

    if not os.path.exists(file.filepath):
        abort(404)

    return send_file(file.filepath, as_attachment=True)

@app.route('/delete/<string:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = UserFile.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    # Delete all associated share links and their access logs
    shares = FileShare.query.filter_by(file_id=file_id).all()
    for share in shares:
        # Delete access logs first
        ShareAccessLog.query.filter_by(share_id=share.id).delete()
        # Delete the share
        db.session.delete(share)
    
    # Delete the file from disk
    if is_safe_storage_path(file.filepath) and os.path.exists(file.filepath):
        os.remove(file.filepath)
    
    # Delete the file record from the database
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_all_files', methods=['POST'])
@login_required
def delete_all_files():
    # Get all files for the current user
    files = UserFile.query.filter_by(user_id=current_user.id).all()
    
    if not files:
        flash('No files to delete', 'error')
        return redirect(url_for('dashboard'))
    
    # Delete each file from disk and database
    for file in files:
        if is_safe_storage_path(file.filepath) and os.path.exists(file.filepath):
            os.remove(file.filepath)
        db.session.delete(file)
    
    # Commit the changes
    db.session.commit()
    
    flash('All files deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# User dashboard
@app.route('/dashboard')
@login_required
@no_cache
def dashboard():
    # Clear old flash messages at the beginning of the function
    session.pop('_flashes', None)
    
    # Get user files
    user_files = UserFile.query.filter_by(user_id=current_user.id).order_by(UserFile.uploaded_at.desc()).all()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Your Personal Cloud Storage')
    
    return render_template(
        'dashboard.html',
        files=user_files,
        used_storage=current_user.get_used_storage(),
        storage_limit=current_user.storage_limit,
        storage_percentage=current_user.get_storage_percentage(),
        footer_text=footer_text,
        now=datetime.utcnow()
    )

# Admin routes
@app.route('/admin')
@login_required
@admin_required
@no_cache
def admin_dashboard():
    # Get user stats
    total_users = User.query.count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    # Get file stats
    total_files = UserFile.query.count()
    total_storage = db.session.query(func.sum(UserFile.filesize)).scalar() or 0
    
    # Get backup stats
    backup_settings = BackupSettings.get_settings()
    last_backup = backup_settings.last_backup
    total_backups = BackupHistory.query.count()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'OpenHosting - Secure Cloud Storage')
    
    return render_template('admin/dashboard.html', 
                          total_users=total_users, 
                          admin_users=admin_users, 
                          total_files=total_files, 
                          total_storage=total_storage,
                          last_backup=last_backup,
                          total_backups=total_backups,
                          footer_text=footer_text, 
                          now=datetime.utcnow())

@app.route('/admin/users')
@login_required
@admin_required
@no_cache
def admin_users():
    users = User.query.all()
    user_stats = []
    
    for user in users:
        used_storage = user.get_used_storage()
        user_stats.append({
            'user': user,
            'used_storage': humanize.naturalsize(used_storage),
            'total_storage': humanize.naturalsize(user.storage_limit),
            'storage_percent': user.get_storage_percentage(),
            'file_count': len(user.files)
        })
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    
    return render_template('admin/users.html', user_stats=user_stats, footer_text=footer_text, now=datetime.utcnow())

@app.route('/admin/user/<string:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        storage_limit_gb = float(request.form.get('storage_limit', 5))
        storage_limit_bytes = int(storage_limit_gb * 1024 * 1024 * 1024)
        
        user.storage_limit = storage_limit_bytes
        
        # Optionally update admin status
        is_admin = 'is_admin' in request.form
        user.is_admin = is_admin
        
        db.session.commit()
        flash(f'User {user.username} updated successfully', 'success')
        return redirect(url_for('admin_users'))
    
    user_files = UserFile.query.filter_by(user_id=user.id).all()
    used_storage = user.get_used_storage()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    
    return render_template(
        'admin/edit_user.html',
        user=user,
        files=user_files,
        used_storage=humanize.naturalsize(used_storage),
        storage_limit_gb=user.storage_limit / (1024 * 1024 * 1024),
        storage_percent=user.get_storage_percentage(),
        footer_text=footer_text,
        now=datetime.utcnow()
    )

@app.route('/admin/user/<string:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting admin users
    if user.is_admin:
        flash('Cannot delete admin users', 'error')
        return redirect(url_for('admin_users'))
    
    # Delete user's files from filesystem
    for file in user.files:
        try:
            if is_safe_storage_path(file.filepath) and os.path.exists(file.filepath):
                os.remove(file.filepath)
        except Exception as e:
            flash(f'Error deleting file {file.filename}: {str(e)}', 'error')
    
    # Delete user from database (cascade will delete files)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} and all their files have been deleted', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/files')
@login_required
@admin_required
def admin_files():
    # Get all files
    files = UserFile.query.options(joinedload(UserFile.user)).all()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Your Personal Cloud Storage')
    
    return render_template('admin/files.html', files=files, footer_text=footer_text, now=datetime.utcnow())

@app.route('/admin/files/delete/<string:file_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_file(file_id):
    file = UserFile.query.get_or_404(file_id)
    
    # Delete the file from the filesystem
    try:
        if is_safe_storage_path(file.filepath) and os.path.exists(file.filepath):
            os.remove(file.filepath)
    except Exception as e:
        flash(f'Error deleting file from filesystem: {str(e)}', 'error')
    
    # Delete the file record from the database
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('admin_files'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
@no_cache
def admin_settings():
    if request.method == 'POST':
        # Update settings
        SiteSettings.set_setting('site_title', request.form.get('site_title', 'Sephosting'))
        SiteSettings.set_setting('site_description', request.form.get('site_description', ''))
        SiteSettings.set_setting('feature_1_title', request.form.get('feature_1_title', ''))
        SiteSettings.set_setting('feature_1_description', request.form.get('feature_1_description', ''))
        SiteSettings.set_setting('feature_2_title', request.form.get('feature_2_title', ''))
        SiteSettings.set_setting('feature_2_description', request.form.get('feature_2_description', ''))
        SiteSettings.set_setting('footer_text', request.form.get('footer_text', ''))
        
        # Update icons if provided
        feature_1_icon = request.form.get('feature_1_icon', '')
        feature_2_icon = request.form.get('feature_2_icon', '')
        
        if feature_1_icon:
            IconSettings.set_icon('feature_1_icon', feature_1_icon)
        if feature_2_icon:
            IconSettings.set_icon('feature_2_icon', feature_2_icon)
        
        # Process default storage limit
        default_storage_limit = request.form.get('default_storage_limit', '5')
        # Check if the value is a valid number
        try:
            default_storage_gb = float(default_storage_limit)
            if default_storage_gb < 1:
                default_storage_gb = 1  # Minimum 1GB
            SiteSettings.set_setting('default_storage_limit', str(int(default_storage_gb)))
        except ValueError:
            flash('Invalid storage limit value. Using default value of 5GB.', 'error')
            SiteSettings.set_setting('default_storage_limit', '5')
        
        flash('Site settings updated successfully', 'success')
        return redirect(url_for('admin_settings'))
    
    # Get current settings with defaults
    settings = {
        'site_title': SiteSettings.get_setting('site_title', 'Sephosting'),
        'site_description': SiteSettings.get_setting('site_description', 'Your private cloud storage solution that respects your digital privacy'),
        'feature_1_title': SiteSettings.get_setting('feature_1_title', 'Zero-Knowledge Encryption'),
        'feature_1_description': SiteSettings.get_setting('feature_1_description', 'Your files are encrypted before they leave your device. Not even we can access them.'),
        'feature_2_title': SiteSettings.get_setting('feature_2_title', 'Strict Privacy Policy'),
        'feature_2_description': SiteSettings.get_setting('feature_2_description', 'We never sell your data or share it with third parties. Your privacy is our priority.'),
        'footer_text': SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage'),
        'default_storage_limit': SiteSettings.get_setting('default_storage_limit', '5')
    }
    
    # Get current icons with defaults
    icons = {
        'feature_1_icon': IconSettings.get_icon('feature_1_icon', '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'),
        'feature_2_icon': IconSettings.get_icon('feature_2_icon', '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>')
    }
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    
    return render_template('admin/settings.html', settings=settings, icons=icons, footer_text=footer_text, now=datetime.utcnow())

@app.route('/admin/security/rotate-secret', methods=['POST'])
@login_required
@admin_required
def admin_rotate_secret():
    """Allow administrators to regenerate the Flask secret key on demand."""
    new_secret = secrets.token_hex(32)
    persist_secret_key(new_secret)
    flash('Application secret key rotated. All sessions must log in again.', 'success')
    logout_user()
    clear_session_except_flashes()
    return redirect(url_for('login'))

@app.route('/admin/backups')
@login_required
@admin_required
def admin_backups():
    # Get backup settings
    backup_settings = BackupSettings.get_settings()
    
    # Get backup history
    backup_history = BackupHistory.query.order_by(BackupHistory.created_at.desc()).all()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'OpenHosting - Secure Cloud Storage')
    
    return render_template('admin/backups.html', 
                          backup_settings=backup_settings, 
                          backup_history=backup_history, 
                          footer_text=footer_text, 
                          now=datetime.utcnow())

@app.route('/admin/backups/settings', methods=['POST'])
@login_required
@admin_required
def admin_backup_settings():
    # Get backup settings
    backup_settings = BackupSettings.get_settings()
    
    # Update settings
    backup_path = request.form.get('backup_path', 'backups')
    auto_backup = 'auto_backup' in request.form
    auto_backup_interval = int(request.form.get('auto_backup_interval', 7))
    include_user_files = 'include_user_files' in request.form
    
    # Validate backup path
    if not os.path.isabs(backup_path):
        backup_path = os.path.abspath(backup_path)
    
    # Update settings
    backup_settings.backup_path = backup_path
    backup_settings.auto_backup = auto_backup
    backup_settings.auto_backup_interval = auto_backup_interval
    backup_settings.include_user_files = include_user_files
    
    db.session.commit()
    
    flash('Backup settings updated successfully', 'success')
    return redirect(url_for('admin_backups'))

@app.route('/admin/backups/create', methods=['POST'])
@login_required
@admin_required
def admin_create_backup():
    # Get backup settings
    backup_settings = BackupSettings.get_settings()
    
    # Create backup directory if it doesn't exist
    backup_path = backup_settings.backup_path
    if not os.path.isabs(backup_path):
        backup_path = os.path.abspath(backup_path)
    
    os.makedirs(backup_path, exist_ok=True)
    
    # Create timestamp for backup folder
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_folder = os.path.join(backup_path, f'backup_{timestamp}')
    os.makedirs(backup_folder, exist_ok=True)
    
    # Backup database
    db_file = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    # If db_file is empty or relative, construct the absolute path
    if not db_file or not os.path.isabs(db_file):
        # Check in instance folder first (Flask's default location)
        instance_db_path = os.path.join(os.path.abspath('instance'), 'sephosting.db')
        if os.path.exists(instance_db_path):
            db_file = instance_db_path
        else:
            # Fallback to root directory
            db_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'sephosting.db')
    
    # Check if the database file exists
    if not os.path.exists(db_file):
        flash(f'Database file not found at {db_file}', 'error')
        return redirect(url_for('admin_backups'))
    
    db_backup_path = os.path.join(backup_folder, os.path.basename(db_file))
    shutil.copy2(db_file, db_backup_path)
    
    total_size = os.path.getsize(db_backup_path)
    include_user_files = backup_settings.include_user_files
    
    # Backup user files if enabled
    if include_user_files:
        user_files_folder = os.path.join(backup_folder, 'user_uploads')
        os.makedirs(user_files_folder, exist_ok=True)
        
        # Copy user uploads
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            for user_id in os.listdir(app.config['UPLOAD_FOLDER']):
                user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user_id)
                if os.path.isdir(user_folder):
                    user_backup_folder = os.path.join(user_files_folder, user_id)
                    os.makedirs(user_backup_folder, exist_ok=True)
                    
                    for file in os.listdir(user_folder):
                        file_path = os.path.join(user_folder, file)
                        if os.path.isfile(file_path):
                            shutil.copy2(file_path, os.path.join(user_backup_folder, file))
                            total_size += os.path.getsize(file_path)
    
    # Create zip file of the backup
    zip_path = f"{backup_folder}.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(backup_folder):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, backup_folder))
    
    # Remove the unzipped backup folder
    shutil.rmtree(backup_folder)
    
    # Create backup history record
    backup_history = BackupHistory(
        backup_path=zip_path,
        backup_size=total_size,
        database_included=True,
        user_files_included=include_user_files,
        created_by=current_user.id
    )
    
    db.session.add(backup_history)
    
    # Update last backup timestamp
    BackupSettings.update_last_backup()
    
    db.session.commit()
    
    flash('Backup created successfully', 'success')
    return redirect(url_for('admin_backups'))

@app.route('/admin/backups/download/<string:backup_id>')
@login_required
@admin_required
def admin_download_backup(backup_id):
    # Get backup
    backup = BackupHistory.query.get_or_404(backup_id)
    
    # Check if backup file exists
    if not os.path.exists(backup.backup_path):
        flash('Backup file not found', 'error')
        return redirect(url_for('admin_backups'))
    
    # Send file
    return send_file(backup.backup_path, as_attachment=True, download_name=os.path.basename(backup.backup_path))

@app.route('/admin/backups/delete/<string:backup_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_backup(backup_id):
    # Get backup
    backup = BackupHistory.query.get_or_404(backup_id)
    
    # Delete backup file
    if os.path.exists(backup.backup_path):
        os.remove(backup.backup_path)
    
    # Delete backup record
    db.session.delete(backup)
    db.session.commit()
    
    flash('Backup deleted successfully', 'success')
    return redirect(url_for('admin_backups'))

@app.route('/admin/backups/restore/<string:backup_id>', methods=['POST'])
@login_required
@admin_required
def admin_restore_backup(backup_id):
    # Get backup
    backup = BackupHistory.query.get_or_404(backup_id)
    
    # Check if backup file exists
    if not os.path.exists(backup.backup_path):
        flash('Backup file not found', 'error')
        return redirect(url_for('admin_backups'))
    
    try:
        # Create a temporary directory for extraction
        temp_dir = os.path.join(os.path.dirname(backup.backup_path), f'temp_restore_{int(time.time())}')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Extract the backup zip file
        with zipfile.ZipFile(backup.backup_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Find the database file in the extracted files
        db_file = None
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.db'):
                    db_file = os.path.join(root, file)
                    break
            if db_file:
                break
        
        if not db_file:
            flash('No database file found in the backup', 'error')
            shutil.rmtree(temp_dir)
            return redirect(url_for('admin_backups'))
        
        # Close the current database connection
        db.session.close()
        db.engine.dispose()
        
        # Get the current database path
        current_db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if not current_db_path or not os.path.isabs(current_db_path):
            # Check in instance folder first (Flask's default location)
            instance_db_path = os.path.join(os.path.abspath('instance'), 'sephosting.db')
            if os.path.exists(instance_db_path):
                current_db_path = instance_db_path
            else:
                # Fallback to root directory
                current_db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'sephosting.db')
        
        # Backup the current database before overwriting (just in case)
        current_backup_path = f"{current_db_path}.bak"
        if os.path.exists(current_db_path):
            shutil.copy2(current_db_path, current_backup_path)
        
        # Restore the database file
        shutil.copy2(db_file, current_db_path)
        
        # If user files were included in the backup, restore them too
        if backup.user_files_included:
            user_uploads_dir = os.path.join(temp_dir, 'user_uploads')
            if os.path.exists(user_uploads_dir):
                # Backup current user uploads
                if os.path.exists(app.config['UPLOAD_FOLDER']):
                    backup_uploads_dir = f"{app.config['UPLOAD_FOLDER']}.bak"
                    if os.path.exists(backup_uploads_dir):
                        shutil.rmtree(backup_uploads_dir)
                    shutil.copytree(app.config['UPLOAD_FOLDER'], backup_uploads_dir)
                    
                    # Remove current user uploads
                    shutil.rmtree(app.config['UPLOAD_FOLDER'])
                
                # Restore user uploads from backup
                shutil.copytree(user_uploads_dir, app.config['UPLOAD_FOLDER'])
        
        # Clean up temporary directory
        shutil.rmtree(temp_dir)
        
        # Generate a new secret key to invalidate all existing sessions
        # This will force all users to log in again
        new_secret_key = secrets.token_hex(32)
        persist_secret_key(new_secret_key)
        
        # Clear all sessions
        session.clear()
        
        # Log out the current user
        logout_user()
        
        flash('Backup restored successfully. All users have been logged out for security reasons. Please log in again.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'Error restoring backup: {str(e)}', 'error')
        return redirect(url_for('admin_backups'))

@app.template_filter('datetime_format')
def datetime_format(value, format='%B %d, %Y at %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

# ============================================================================
# File Sharing Routes
# ============================================================================

@app.route('/share/create/<string:file_id>', methods=['POST'])
@login_required
def create_share(file_id):
    """Create a new share link for a file"""
    # Verify user owns the file
    user_file = UserFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not user_file:
        return jsonify({'error': 'File not found or access denied'}), 404
    
    # Check if file already has an active share
    existing_share = FileShare.query.filter_by(
        file_id=file_id,
        is_active=True
    ).first()
    
    if existing_share:
        share_url = url_for('access_share', token=existing_share.share_token, _external=True)
        return jsonify({
            'success': True,
            'share_url': share_url,
            'share_id': existing_share.id,
            'existing': True
        })
    
    # Get parameters
    password = request.form.get('password', '').strip()
    expiration = request.form.get('expiration', 'never')
    max_downloads = request.form.get('max_downloads', '').strip()
    
    # Generate unique share token
    share_token = generate_share_token()
    
    # Create share
    new_share = FileShare(
        file_id=file_id,
        user_id=current_user.id,
        share_token=share_token,
        password_hash=generate_password_hash(password) if password else None,
        expires_at=calculate_expiration(expiration),
        max_downloads=int(max_downloads) if max_downloads and max_downloads.isdigit() else None,
        download_count=0,
        is_active=True
    )
    
    db.session.add(new_share)
    db.session.commit()
    
    share_url = url_for('access_share', token=share_token, _external=True)
    
    return jsonify({
        'success': True,
        'share_url': share_url,
        'share_id': new_share.id,
        'existing': False
    })

@app.route('/share/revoke/<string:share_id>', methods=['POST'])
@login_required
def revoke_share(share_id):
    """Revoke an existing share link"""
    share = FileShare.query.filter_by(id=share_id, user_id=current_user.id).first()
    if not share:
        flash('Share not found or access denied', 'error')
        return redirect(url_for('my_shares'))
    
    share.is_active = False
    share.revoked_at = datetime.utcnow()
    share.revoked_by = current_user.id
    db.session.commit()
    
    flash('Share link revoked successfully', 'success')
    return redirect(url_for('my_shares'))

@app.route('/my-shares')
@login_required
@no_cache
def my_shares():
    """Display all active shares for the current user"""
    shares = FileShare.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).order_by(FileShare.created_at.desc()).all()
    
    footer_text = SiteSettings.get_setting('footer_text', 'OpenHosting - Secure Cloud Storage')
    
    return render_template(
        'my_shares.html',
        shares=shares,
        footer_text=footer_text,
        now=datetime.utcnow()
    )

@app.route('/share/details/<string:share_id>')
@login_required
def share_details(share_id):
    """View detailed analytics for a specific share"""
    share = FileShare.query.filter_by(id=share_id, user_id=current_user.id).first()
    if not share:
        return jsonify({'error': 'Share not found or access denied'}), 404
    
    # Get access logs
    logs = ShareAccessLog.query.filter_by(share_id=share_id).order_by(
        ShareAccessLog.accessed_at.desc()
    ).limit(50).all()
    
    return jsonify({
        'share_id': share.id,
        'file_name': share.file.filename,
        'created_at': share.created_at.isoformat(),
        'expires_at': share.expires_at.isoformat() if share.expires_at else None,
        'download_count': share.download_count,
        'max_downloads': share.max_downloads,
        'last_accessed_at': share.last_accessed_at.isoformat() if share.last_accessed_at else None,
        'is_active': share.is_active,
        'has_password': share.password_hash is not None,
        'access_logs': [{
            'accessed_at': log.accessed_at.isoformat(),
            'ip_address': log.ip_address,
            'action': log.action,
            'success': log.success
        } for log in logs]
    })

@app.route('/s/<string:token>', methods=['GET', 'POST'])
def access_share(token):
    """Access a shared file via token"""
    share = FileShare.query.filter_by(share_token=token).first()
    
    if not share:
        log_share_access(None, 'view', success=False)
        return render_template('share_error.html', 
                             error_title='Invalid Link',
                             error_message='This share link is invalid or has been removed'), 404
    
    # Validate share
    is_valid, error_message = is_share_valid(share)
    if not is_valid:
        log_share_access(share.id, 'view', success=False)
        
        if 'expired' in error_message.lower():
            status_code = 410
        elif 'limit' in error_message.lower():
            status_code = 403
        else:
            status_code = 404
        
        return render_template('share_error.html',
                             error_title='Access Denied',
                             error_message=error_message), status_code
    
    # Handle password-protected shares
    if share.password_hash:
        if request.method == 'POST':
            password = request.form.get('password', '')
            
            # Check rate limit
            is_allowed, retry_after = check_rate_limit(share.id, request.remote_addr)
            if not is_allowed:
                return render_template('share_error.html',
                                     error_title='Too Many Attempts',
                                     error_message=f'Too many failed attempts. Please try again in {retry_after // 60} minutes'), 429
            
            if verify_share_password(share, password):
                session[f'share_password_verified_{share.id}'] = True
                log_share_access(share.id, 'view', success=True)
                share.last_accessed_at = datetime.utcnow()
                db.session.commit()
            else:
                log_share_access(share.id, 'password_fail', success=False)
                flash('Incorrect password. Please try again.', 'error')
                return render_template('share_password.html', share=share, token=token)
        else:
            # Check if password already verified in session
            if not session.get(f'share_password_verified_{share.id}'):
                return render_template('share_password.html', share=share, token=token)
    
    # Log successful view
    log_share_access(share.id, 'view', success=True)
    share.last_accessed_at = datetime.utcnow()
    db.session.commit()
    
    return render_template('share_access.html', share=share, token=token)

@app.route('/s/<string:token>/download')
def download_shared_file(token):
    """Download a shared file"""
    share = FileShare.query.filter_by(share_token=token).first()
    
    if not share:
        return render_template('share_error.html',
                             error_title='Invalid Link',
                             error_message='This share link is invalid or has been removed'), 404
    
    # Validate share
    is_valid, error_message = is_share_valid(share)
    if not is_valid:
        log_share_access(share.id, 'download', success=False)
        return render_template('share_error.html',
                             error_title='Access Denied',
                             error_message=error_message), 403
    
    # Check password verification
    if share.password_hash and not session.get(f'share_password_verified_{share.id}'):
        return redirect(url_for('access_share', token=token))
    
    # Increment download counter
    share.download_count += 1
    share.last_accessed_at = datetime.utcnow()
    db.session.commit()
    
    # Log download
    log_share_access(share.id, 'download', success=True)
    
    # Send file
    return send_file(share.file.filepath, as_attachment=True, download_name=share.file.filename)

@app.route('/admin/shares')
@login_required
@admin_required
@no_cache
def admin_shares():
    """View all shares across the platform (admin only)"""
    shares = FileShare.query.filter_by(is_active=True).order_by(
        FileShare.created_at.desc()
    ).all()
    
    footer_text = SiteSettings.get_setting('footer_text', 'OpenHosting - Secure Cloud Storage')
    
    return render_template(
        'admin/shares.html',
        shares=shares,
        footer_text=footer_text,
        now=datetime.utcnow()
    )

@app.route('/admin/share/revoke/<string:share_id>', methods=['POST'])
@login_required
@admin_required
def admin_revoke_share(share_id):
    """Admin revoke any share link"""
    share = FileShare.query.filter_by(id=share_id).first()
    if not share:
        flash('Share not found', 'error')
        return redirect(url_for('admin_shares'))
    
    share.is_active = False
    share.revoked_at = datetime.utcnow()
    share.revoked_by = current_user.id
    db.session.commit()
    
    flash(f'Share link for "{share.file.filename}" revoked successfully', 'success')
    return redirect(url_for('admin_shares'))

# Call the initialization function before starting the application
create_default_admin()

if __name__ == '__main__':
    import sys
    
    # Check if running with command line arguments
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode in ['production', 'prod', 'p']:
            print("\n" + "="*50)
            print("🚀 Starting OpenHosting in PRODUCTION mode")
            print("="*50)
            print("⚠️  Debug mode: OFF")
            print("🌐 Server will be accessible on: http://0.0.0.0:83")
            print("📝 Make sure to use a production WSGI server for deployment")
            print("="*50 + "\n")
            app.run(host='0.0.0.0', port=83, debug=False)
        elif mode in ['development', 'dev', 'd']:
            print("\n" + "="*50)
            print("🔧 Starting OpenHosting in DEVELOPMENT mode")
            print("="*50)
            print("🐛 Debug mode: ON")
            print("🌐 Server accessible on: http://127.0.0.1:83")
            print("="*50 + "\n")
            app.run(host='127.0.0.1', port=83, debug=True)
        else:
            print(f"❌ Unknown mode: {mode}")
            print("Usage: python app.py [production|development]")
            sys.exit(1)
    else:
        # Interactive mode selection
        print("\n" + "="*50)
        print("🚀 OpenHosting Server Configuration")
        print("="*50)
        print("\nSelect server mode:")
        print("  1. Production (all interfaces, debug OFF)")
        print("  2. Development (localhost only, debug ON)")
        print("\n⚠️  For production deployment, consider using a WSGI server")
        print("   like Gunicorn or uWSGI instead of the Flask dev server.")
        print("="*50)
        
        while True:
            try:
                choice = input("\nEnter your choice (1 or 2): ").strip()
                
                if choice == '1':
                    print("\n" + "="*50)
                    print("�  Starting in PRODUCTION mode")
                    print("="*50)
                    print("⚠️  Debug mode: OFF")
                    print("🌐 Server accessible on: http://0.0.0.0:83")
                    print("📝 Recommended: Use Gunicorn or uWSGI for production")
                    print("="*50 + "\n")
                    app.run(host='0.0.0.0', port=83, debug=False)
                    break
                elif choice == '2':
                    print("\n" + "="*50)
                    print("🔧 Starting in DEVELOPMENT mode")
                    print("="*50)
                    print("🐛 Debug mode: ON")
                    print("🌐 Server accessible on: http://127.0.0.1:83")
                    print("="*50 + "\n")
                    app.run(host='127.0.0.1', port=83, debug=True)
                    break
                else:
                    print("❌ Invalid choice. Please enter 1 or 2.")
            except KeyboardInterrupt:
                print("\n\n👋 Server startup cancelled.")
                sys.exit(0)
            except EOFError:
                # Non-interactive environment, default to development
                print("\n⚠️  Non-interactive environment detected.")
                print("🔧 Defaulting to DEVELOPMENT mode")
                print("💡 Use: python app.py production (for production mode)")
                print("="*50 + "\n")
                app.run(host='127.0.0.1', port=83, debug=True)
                break
