from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import os

db = SQLAlchemy()

class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

class IconSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
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

class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(512), nullable=False)
    filesize = db.Column(db.BigInteger, default=0)  # File size in bytes
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
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