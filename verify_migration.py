"""Verify that the file sharing tables were created correctly"""

from app import app, db
from models import FileShare, ShareAccessLog
from sqlalchemy import inspect

def verify_tables():
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        print("Database Tables:")
        print("-" * 50)
        for table in sorted(tables):
            print(f"  ✓ {table}")
        
        print("\n" + "=" * 50)
        print("FileShare Table Structure:")
        print("=" * 50)
        if 'file_share' in tables:
            columns = inspector.get_columns('file_share')
            for col in columns:
                nullable = "NULL" if col['nullable'] else "NOT NULL"
                print(f"  {col['name']:20} {str(col['type']):20} {nullable}")
            
            print("\nFileShare Indexes:")
            indexes = inspector.get_indexes('file_share')
            for idx in indexes:
                print(f"  ✓ {idx['name']}: {idx['column_names']}")
        
        print("\n" + "=" * 50)
        print("ShareAccessLog Table Structure:")
        print("=" * 50)
        if 'share_access_log' in tables:
            columns = inspector.get_columns('share_access_log')
            for col in columns:
                nullable = "NULL" if col['nullable'] else "NOT NULL"
                print(f"  {col['name']:20} {str(col['type']):20} {nullable}")
            
            print("\nShareAccessLog Indexes:")
            indexes = inspector.get_indexes('share_access_log')
            for idx in indexes:
                print(f"  ✓ {idx['name']}: {idx['column_names']}")
        
        print("\n" + "=" * 50)
        print("✓ Verification complete!")

if __name__ == '__main__':
    verify_tables()
