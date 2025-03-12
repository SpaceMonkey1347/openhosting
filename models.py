from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import os
import uuid

db = SQLAlchemy()

# Base model class that uses UUID as primary key
class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)

class SiteSettings(BaseModel):
    # id is inherited from BaseModel
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get_setting(cls, key, default=None):
        """Get a setting value by key with optional default value"""
        setting = cls.query.filter_by(setting_key=key).first()
        if setting:
            return setting.setting_value
        return default
    
    @classmethod
    def set_setting(cls, key, value):
        """Set or update a setting value"""
        setting = cls.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = value
        else:
            setting = cls(setting_key=key, setting_value=value)
            db.session.add(setting)
        db.session.commit()
        return setting

class BackupSettings(BaseModel):
    # id is inherited from BaseModel
    backup_path = db.Column(db.String(512), nullable=False, default='backups')
    last_backup = db.Column(db.DateTime, nullable=True)
    auto_backup = db.Column(db.Boolean, default=False)
    auto_backup_interval = db.Column(db.Integer, default=7)  # Days
    include_user_files = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get_settings(cls):
        """Get backup settings, create default if not exists"""
        settings = cls.query.first()
        if not settings:
            settings = cls(backup_path='backups')
            db.session.add(settings)
            db.session.commit()
        return settings
    
    @classmethod
    def update_last_backup(cls):
        """Update the last backup timestamp"""
        settings = cls.get_settings()
        settings.last_backup = datetime.utcnow()
        db.session.commit()
        return settings

class BackupHistory(BaseModel):
    # id is inherited from BaseModel
    backup_path = db.Column(db.String(512), nullable=False)
    backup_size = db.Column(db.BigInteger, default=0)  # Size in bytes
    database_included = db.Column(db.Boolean, default=True)
    user_files_included = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    
    # Relationship with user
    user = db.relationship('User', backref='backups', lazy=True)

class IconSettings(BaseModel):
    # id is inherited from BaseModel
    icon_key = db.Column(db.String(100), unique=True, nullable=False)
    icon_svg = db.Column(db.Text, nullable=False)  # Store SVG code
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get_icon(cls, key, default=None):
        """Get an icon SVG by key with optional default value"""
        icon = cls.query.filter_by(icon_key=key).first()
        if icon:
            return icon.icon_svg
        return default
    
    @classmethod
    def set_icon(cls, key, svg_value):
        """Set or update an icon SVG"""
        icon = cls.query.filter_by(icon_key=key).first()
        if icon:
            icon.icon_svg = svg_value
        else:
            icon = cls(icon_key=key, icon_svg=svg_value)
            db.session.add(icon)
        db.session.commit()
        return icon

class User(BaseModel, UserMixin):
    # id is inherited from BaseModel
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_first_login = db.Column(db.Boolean, default=False)  # To track first login
    storage_limit = db.Column(db.BigInteger, default=5 * 1024 * 1024 * 1024)  # 5GB in bytes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Relationship with user files
    files = db.relationship('UserFile', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def get_used_storage(self):
        """Calculate total storage used by the user in bytes"""
        total_size = 0
        for file in self.files:
            try:
                if os.path.exists(file.filepath):
                    total_size += os.path.getsize(file.filepath)
            except (OSError, IOError):
                pass
        return total_size
    
    def get_storage_percentage(self):
        """Calculate percentage of storage used"""
        if self.storage_limit == 0:  # Prevent division by zero
            return 100
        return min(100, (self.get_used_storage() / self.storage_limit) * 100)

class UserFile(BaseModel):
    # id is inherited from BaseModel
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(512), nullable=False)
    filesize = db.Column(db.BigInteger, default=0)  # File size in bytes
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Removed direct relationship that causes conflict
    # owner = db.relationship('User', foreign_keys=[user_id], backref='owned_files', lazy='joined')
    
    @property
    def owner(self):
        """Get the user who owns this file (alias for user)"""
        return self.user
    
    def save_filesize(self):
        """Update the filesize field based on the actual file size"""
        try:
            if os.path.exists(self.filepath):
                self.filesize = os.path.getsize(self.filepath)
        except (OSError, IOError):
            pass
        return self.filesize