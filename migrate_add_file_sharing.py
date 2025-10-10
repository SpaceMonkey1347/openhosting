"""
Migration script to add FileShare and ShareAccessLog tables
Run this script to add file sharing functionality to an existing database.

Usage: python migrate_add_file_sharing.py
"""

from app import app, db
from models import FileShare, ShareAccessLog
from sqlalchemy import inspect, text

def table_exists(table_name):
    """Check if a table exists in the database"""
    inspector = inspect(db.engine)
    return table_name in inspector.get_table_names()

def create_indexes():
    """Create indexes for optimal query performance"""
    with db.engine.connect() as conn:
        # FileShare indexes
        if not index_exists('idx_fileshare_token'):
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_fileshare_token ON file_share(share_token)'))
            print("✓ Created index: idx_fileshare_token")
        
        if not index_exists('idx_fileshare_user_active'):
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_fileshare_user_active ON file_share(user_id, is_active)'))
            print("✓ Created index: idx_fileshare_user_active")
        
        if not index_exists('idx_fileshare_file_active'):
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_fileshare_file_active ON file_share(file_id, is_active)'))
            print("✓ Created index: idx_fileshare_file_active")
        
        # ShareAccessLog indexes
        if not index_exists('idx_shareaccess_share_time'):
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_shareaccess_share_time ON share_access_log(share_id, accessed_at)'))
            print("✓ Created index: idx_shareaccess_share_time")
        
        if not index_exists('idx_shareaccess_ip_time'):
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_shareaccess_ip_time ON share_access_log(ip_address, accessed_at)'))
            print("✓ Created index: idx_shareaccess_ip_time")
        
        conn.commit()

def index_exists(index_name):
    """Check if an index exists in the database"""
    inspector = inspect(db.engine)
    # Get all indexes from all tables
    for table_name in inspector.get_table_names():
        indexes = inspector.get_indexes(table_name)
        for index in indexes:
            if index['name'] == index_name:
                return True
    return False

def run_migration():
    """Run the migration to add file sharing tables"""
    with app.app_context():
        print("Starting migration: Add file sharing tables")
        print("-" * 50)
        
        # Check if tables already exist
        if table_exists('file_share'):
            print("⚠ Table 'file_share' already exists. Skipping creation.")
        else:
            print("Creating table: file_share")
            FileShare.__table__.create(db.engine)
            print("✓ Created table: file_share")
        
        if table_exists('share_access_log'):
            print("⚠ Table 'share_access_log' already exists. Skipping creation.")
        else:
            print("Creating table: share_access_log")
            ShareAccessLog.__table__.create(db.engine)
            print("✓ Created table: share_access_log")
        
        # Create indexes
        print("\nCreating indexes for performance optimization...")
        create_indexes()
        
        print("-" * 50)
        print("✓ Migration completed successfully!")
        print("\nFile sharing tables are now ready to use.")

if __name__ == '__main__':
    try:
        run_migration()
    except Exception as e:
        print(f"\n✗ Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)
