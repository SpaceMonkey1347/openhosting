"""Test script to verify FileShare and ShareAccessLog models work correctly"""

from app import app, db
from models import User, UserFile, FileShare, ShareAccessLog
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import secrets

def test_models():
    with app.app_context():
        print("Testing FileShare and ShareAccessLog models...")
        print("=" * 50)
        
        # Get or create a test user
        test_user = User.query.first()
        if not test_user:
            print("✗ No test user found. Please ensure at least one user exists.")
            return
        
        print(f"✓ Using test user: {test_user.username}")
        
        # Get or create a test file
        test_file = UserFile.query.filter_by(user_id=test_user.id).first()
        if not test_file:
            print("✗ No test file found. Creating a dummy file entry...")
            test_file = UserFile(
                filename='test_file.txt',
                filepath='/tmp/test_file.txt',
                filesize=1024,
                user_id=test_user.id
            )
            db.session.add(test_file)
            db.session.commit()
        
        print(f"✓ Using test file: {test_file.filename}")
        
        # Test 1: Create a FileShare
        print("\nTest 1: Creating FileShare...")
        share_token = secrets.token_urlsafe(32)
        test_share = FileShare(
            file_id=test_file.id,
            user_id=test_user.id,
            share_token=share_token,
            password_hash=generate_password_hash('test123'),
            expires_at=datetime.utcnow() + timedelta(days=7),
            max_downloads=10,
            download_count=0,
            is_active=True
        )
        db.session.add(test_share)
        db.session.commit()
        print(f"✓ Created FileShare with token: {share_token[:20]}...")
        
        # Test 2: Query FileShare
        print("\nTest 2: Querying FileShare...")
        queried_share = FileShare.query.filter_by(share_token=share_token).first()
        if queried_share:
            print(f"✓ Found share: {queried_share.id}")
            print(f"  - File: {queried_share.file.filename}")
            print(f"  - Owner: {queried_share.owner.username}")
            print(f"  - Active: {queried_share.is_active}")
            print(f"  - Downloads: {queried_share.download_count}/{queried_share.max_downloads}")
        else:
            print("✗ Failed to query FileShare")
            return
        
        # Test 3: Create ShareAccessLog
        print("\nTest 3: Creating ShareAccessLog...")
        access_log = ShareAccessLog(
            share_id=test_share.id,
            ip_address='127.0.0.1',
            user_agent='Test Browser',
            action='view',
            success=True
        )
        db.session.add(access_log)
        db.session.commit()
        print(f"✓ Created ShareAccessLog: {access_log.id}")
        
        # Test 4: Query ShareAccessLog
        print("\nTest 4: Querying ShareAccessLog...")
        logs = ShareAccessLog.query.filter_by(share_id=test_share.id).all()
        print(f"✓ Found {len(logs)} access log(s)")
        for log in logs:
            print(f"  - Action: {log.action}, IP: {log.ip_address}, Success: {log.success}")
        
        # Test 5: Test relationships
        print("\nTest 5: Testing relationships...")
        print(f"✓ Share has {len(test_share.access_logs)} access log(s)")
        print(f"✓ File has {len(test_file.shares)} share(s)")
        print(f"✓ User has {len(test_user.file_shares)} file share(s)")
        
        # Cleanup
        print("\nCleaning up test data...")
        db.session.delete(access_log)
        db.session.delete(test_share)
        db.session.commit()
        print("✓ Test data cleaned up")
        
        print("\n" + "=" * 50)
        print("✓ All model tests passed successfully!")

if __name__ == '__main__':
    try:
        test_models()
    except Exception as e:
        print(f"\n✗ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)
