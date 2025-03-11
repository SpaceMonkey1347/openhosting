from flask import Flask, render_template, redirect, url_for, request, send_file, flash, abort, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, UserFile, SiteSettings, IconSettings
from werkzeug.utils import secure_filename
from functools import wraps
import os
import humanize
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from datetime import datetime
import uuid
import json
from pathlib import Path

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sephosting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'user_uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin requirement decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Replace the before_first_request decorator with an initialization function
def create_default_admin():
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        admin = User.query.filter_by(username='Admin').first()
        if not admin:
            print("Creating default administrator user...")
            admin = User(
                username='Admin',
                email='admin@sephosting.com',
                password_hash=generate_password_hash('Admin'),  # Simple default password
                is_admin=True,
                storage_limit=10 * 1024 * 1024 * 1024,  # 10GB
                is_first_login=True  # Mark that this is the first login
            )
            db.session.add(admin)
            db.session.commit()
            print("Default administrator user created successfully!")
        
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
        
        # Initialize default icons if they don't exist
        default_icons = {
            'feature_1_icon': '<svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>',
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
def login():
    # Clear old flash messages at the beginning of the function
    session.pop('_flashes', None)
    
    if current_user.is_authenticated:
        # If this is the admin's first login, redirect to the credentials change page
        if current_user.is_first_login:
            return redirect(url_for('change_credentials'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        user = User.query.filter((User.username == username) | (User.email == username)).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            
            # If this is the admin's first login, redirect to the credentials change page
            if user.is_first_login:
                return redirect(url_for('change_credentials'))
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', now=datetime.utcnow())

@app.route('/change_credentials', methods=['GET', 'POST'])
@login_required
def change_credentials():
    # Si l'utilisateur n'est pas en première connexion, rediriger vers le dashboard
    if not current_user.is_first_login:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        new_username = request.form.get('new_username')
        new_email = request.form.get('new_email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Vérifier que les champs ne sont pas vides
        if not new_username or not new_email or not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())
        
        # Vérifier que les mots de passe correspondent
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())
        
        # Vérifier que le nouveau nom d'utilisateur n'est pas déjà pris (sauf par l'utilisateur actuel)
        existing_user = User.query.filter(User.username == new_username, User.id != current_user.id).first()
        if existing_user:
            flash('Username already taken', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())
        
        # Vérifier que le nouvel email n'est pas déjà pris (sauf par l'utilisateur actuel)
        existing_email = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing_email:
            flash('Email already taken', 'error')
            return render_template('change_credentials.html', now=datetime.utcnow())
        
        # Mettre à jour les identifiants
        current_user.username = new_username
        current_user.email = new_email
        current_user.password_hash = generate_password_hash(new_password)
        current_user.is_first_login = False  # Marquer que ce n'est plus la première connexion
        
        db.session.commit()
        
        flash('Credentials updated successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_credentials.html', now=datetime.utcnow())

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Effacer les anciens messages flash au début de la fonction
    session.pop('_flashes', None)
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Vérifier si l'utilisateur existe déjà
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'error')
            return redirect(url_for('register'))
        
        # Récupérer la limite de stockage par défaut (en GB)
        default_storage_gb = float(SiteSettings.get_setting('default_storage_limit', '5'))
        # Convertir en bytes
        default_storage_bytes = int(default_storage_gb * 1024 * 1024 * 1024)
        
        # Créer un nouvel utilisateur
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            storage_limit=default_storage_bytes
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
    return redirect(url_for('home'))

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Remove file type restrictions
ALLOWED_EXTENSIONS = set()  # Accept all file types

def allowed_file(filename):
    """Check if the file is allowed"""
    return True  # Accept all file types

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
        file_size = file.content_length or 0  # Get file size from request
        
        if user_storage + file_size > current_user.storage_limit:
            flash('Storage limit exceeded', 'error')
            return redirect(url_for('dashboard'))
            
        # Save the file
        filename = secure_filename(file.filename)
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, filename)
        file.save(filepath)
        
        # Create file record
        new_file = UserFile(
            filename=filename,
            filepath=filepath,
            user_id=current_user.id
        )
        
        # Save file size
        new_file.save_filesize()
        
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
            return json.dumps({'success': False, 'error': 'No file sent'}), 400
            
        file = request.files['file']
        
        # Check if the file has a name
        if file.filename == '':
            return json.dumps({'success': False, 'error': 'No file selected'}), 400
            
        # Get the filename
        filename = secure_filename(file.filename)
        
        # Check if the file is allowed
        if not allowed_file(filename):
            return json.dumps({'success': False, 'error': 'File type not allowed'}), 400
            
        # Check storage limit
        filesize = request.content_length
        user_storage = current_user.get_used_storage()
        
        if user_storage + filesize > current_user.storage_limit:
            return json.dumps({'success': False, 'error': 'Storage limit exceeded'}), 400
            
        # Create user folder if it doesn't exist
        user_dir = os.path.join(os.path.abspath(app.config['UPLOAD_FOLDER']), str(current_user.id))
        os.makedirs(user_dir, exist_ok=True)
        
        # Full file path
        filepath = os.path.join(user_dir, filename)
        
        # Save the file
        print(f"Saving file {filename} to {filepath}")
        file.save(filepath)
        
        # Check that the file was saved correctly
        if not os.path.exists(filepath):
            return json.dumps({'success': False, 'error': 'Error saving the file'}), 500
            
        # Create database entry
        new_file = UserFile(
            filename=filename,
            filepath=filepath,
            user_id=current_user.id
        )
        
        # Save file size
        new_file.save_filesize()
        
        db.session.add(new_file)
        db.session.commit()
        print(f"File {filename} recorded in database")
        
        return json.dumps({'success': True, 'message': 'File uploaded successfully'}), 200
        
    except Exception as e:
        print(f"Error during upload: {str(e)}")
        return json.dumps({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = UserFile.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return send_file(file.filepath, as_attachment=True)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = UserFile.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    try:
        os.remove(file.filepath)
    except FileNotFoundError:
        pass
    
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    
    # Redirect to referring page
    if '/admin/' in request.referrer:
        return redirect(request.referrer)
    return redirect(url_for('dashboard'))

# User dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Effacer les anciens messages flash au début de la fonction
    session.pop('_flashes', None)
    
    files = UserFile.query.filter_by(user_id=current_user.id).all()
    used_storage = current_user.get_used_storage()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    
    return render_template(
        'dashboard.html',
        files=files,
        used_storage=humanize.naturalsize(used_storage),
        total_storage=humanize.naturalsize(current_user.storage_limit),
        storage_percent=current_user.get_storage_percentage(),
        now=datetime.utcnow(),
        footer_text=footer_text
    )

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    total_files = UserFile.query.count()
    total_storage = sum(user.get_used_storage() for user in User.query.all())
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    
    return render_template(
        'admin/dashboard.html',
        user_count=user_count,
        total_files=total_files,
        total_storage=humanize.naturalsize(total_storage),
        now=datetime.utcnow(),
        footer_text=footer_text
    )

@app.route('/admin/users')
@login_required
@admin_required
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

@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
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

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
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
            if os.path.exists(file.filepath):
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
    # Récupérer tous les fichiers
    files = UserFile.query.all()
    
    # Get footer text from settings
    footer_text = SiteSettings.get_setting('footer_text', 'Sephosting - Secure Cloud Storage')
    
    return render_template('admin/files.html', files=files, footer_text=footer_text, now=datetime.utcnow())

@app.route('/admin/files/delete/<int:file_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_file(file_id):
    file = UserFile.query.get_or_404(file_id)
    
    # Delete the file from the filesystem
    try:
        if os.path.exists(file.filepath):
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

@app.template_filter('datetime_format')
def datetime_format(value, format='%B %d, %Y at %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

if __name__ == '__main__':
    # Appeler la fonction d'initialisation avant de démarrer l'application
    create_default_admin()
    app.run(host='127.0.0.1', port=83, debug=True)