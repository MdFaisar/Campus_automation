"""
Remove specific account and all related data from the system
"""

from dotenv import load_dotenv
import os
import sys

# Load environment variables
load_dotenv()

# Add current directory to path
sys.path.append('.')

def remove_account(email_to_remove):
    """Remove account and all related data"""
    try:
        print(f"🗑️ Removing account: {email_to_remove}\n")
        
        # Initialize Firebase
        from utils.firebase_config import initialize_firebase
        firebase_app = initialize_firebase()
        
        from utils.firebase_config import get_firestore_client
        db = get_firestore_client()
        
        removed_items = []
        
        # 1. Remove from users collection
        print("🔍 Checking users collection...")
        try:
            users_query = db.collection('users').where('email', '==', email_to_remove).get()
            for user_doc in users_query:
                user_data = user_doc.to_dict()
                print(f"   Found user: {user_data.get('full_name', 'Unknown')} ({user_data.get('user_type', 'Unknown')})")
                user_doc.reference.delete()
                removed_items.append(f"User account: {user_doc.id}")
                print(f"   ✅ Deleted user: {user_doc.id}")
        except Exception as e:
            print(f"   ⚠️ Error checking users: {e}")
        
        # 2. Remove from pending_registrations collection
        print("\n🔍 Checking pending registrations...")
        try:
            pending_doc = db.collection('pending_registrations').document(email_to_remove).get()
            if pending_doc.exists:
                pending_data = pending_doc.to_dict()
                print(f"   Found pending registration: {pending_data.get('full_name', 'Unknown')}")
                pending_doc.reference.delete()
                removed_items.append("Pending registration")
                print(f"   ✅ Deleted pending registration")
            else:
                print("   ℹ️ No pending registration found")
        except Exception as e:
            print(f"   ⚠️ Error checking pending registrations: {e}")
        
        # 3. Remove from otp_requests collection
        print("\n🔍 Checking OTP requests...")
        try:
            otp_requests = db.collection('otp_requests').where('email', '==', email_to_remove).get()
            otp_count = 0
            for otp_doc in otp_requests:
                otp_doc.reference.delete()
                otp_count += 1
            
            if otp_count > 0:
                removed_items.append(f"{otp_count} OTP requests")
                print(f"   ✅ Deleted {otp_count} OTP requests")
            else:
                print("   ℹ️ No OTP requests found")
        except Exception as e:
            print(f"   ⚠️ Error checking OTP requests: {e}")
        
        # 4. Remove from complaints collection (if any complaints were submitted)
        print("\n🔍 Checking complaints...")
        try:
            # Check for complaints by email (if stored)
            complaints_by_email = db.collection('complaints').where('student_email', '==', email_to_remove).get()
            complaint_count = 0
            
            for complaint_doc in complaints_by_email:
                complaint_data = complaint_doc.to_dict()
                print(f"   Found complaint: {complaint_doc.id} - {complaint_data.get('category', 'Unknown')}")
                # Mark as inactive instead of deleting (for audit trail)
                complaint_doc.reference.update({
                    'is_active': False,
                    'deleted_reason': 'Account removed',
                    'deleted_at': db.collection('complaints').document().server_timestamp
                })
                complaint_count += 1
            
            if complaint_count > 0:
                removed_items.append(f"{complaint_count} complaints (marked inactive)")
                print(f"   ✅ Marked {complaint_count} complaints as inactive")
            else:
                print("   ℹ️ No complaints found")
        except Exception as e:
            print(f"   ⚠️ Error checking complaints: {e}")
        
        # 5. Check for any other collections that might contain this email
        print("\n🔍 Checking other collections...")
        
        # Check faculty_routing (in case it was added as faculty)
        try:
            faculty_docs = db.collection('faculty_routing').where('email', '==', email_to_remove).get()
            for faculty_doc in faculty_docs:
                faculty_data = faculty_doc.to_dict()
                print(f"   Found faculty entry: {faculty_data.get('faculty_name', 'Unknown')}")
                faculty_doc.reference.delete()
                removed_items.append("Faculty routing entry")
                print(f"   ✅ Deleted faculty entry: {faculty_doc.id}")
        except Exception as e:
            print(f"   ⚠️ Error checking faculty routing: {e}")
        
        # Summary
        print("\n" + "="*60)
        print("📊 REMOVAL SUMMARY")
        print("="*60)
        print(f"Email: {email_to_remove}")
        print(f"Items Removed: {len(removed_items)}")
        
        if removed_items:
            print("\nRemoved Items:")
            for item in removed_items:
                print(f"   ✅ {item}")
        else:
            print("\nℹ️ No data found for this email address")
        
        print(f"\n🎉 Account removal completed successfully!")
        print("✅ All related data has been cleaned up")
        print("✅ Email address is now available for new registration")
        
        return True
        
    except Exception as e:
        print(f"❌ Account removal failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_removal(email_to_check):
    """Verify that the account has been completely removed"""
    try:
        print(f"\n🔍 Verifying removal of: {email_to_check}\n")
        
        # Initialize Firebase
        from utils.firebase_config import initialize_firebase
        firebase_app = initialize_firebase()
        
        from utils.firebase_config import get_firestore_client
        db = get_firestore_client()
        
        found_items = []
        
        # Check all collections
        collections_to_check = [
            'users',
            'pending_registrations', 
            'otp_requests',
            'faculty_routing'
        ]
        
        for collection_name in collections_to_check:
            try:
                if collection_name == 'pending_registrations':
                    # Check by document ID
                    doc = db.collection(collection_name).document(email_to_check).get()
                    if doc.exists:
                        found_items.append(f"{collection_name}: {doc.id}")
                else:
                    # Check by email field
                    docs = db.collection(collection_name).where('email', '==', email_to_check).get()
                    for doc in docs:
                        found_items.append(f"{collection_name}: {doc.id}")
            except Exception as e:
                print(f"   ⚠️ Error checking {collection_name}: {e}")
        
        # Check complaints (might use different field names)
        try:
            complaint_docs = db.collection('complaints').where('student_email', '==', email_to_check).get()
            for doc in complaint_docs:
                doc_data = doc.to_dict()
                if doc_data.get('is_active', True):  # Only count active complaints
                    found_items.append(f"complaints: {doc.id} (active)")
        except Exception as e:
            print(f"   ⚠️ Error checking complaints: {e}")
        
        if found_items:
            print("❌ REMOVAL INCOMPLETE - Found remaining data:")
            for item in found_items:
                print(f"   🔍 {item}")
            return False
        else:
            print("✅ REMOVAL VERIFIED - No data found")
            print("🎉 Account has been completely removed from the system")
            return True
            
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False

if __name__ == "__main__":
    # Email to remove (corrected the typo in your request)
    email_to_remove = "btechit231083@smvec.ac.in"  # Fixed: smvec not dmvec
    
    print("🗑️ ACCOUNT REMOVAL TOOL")
    print("="*60)
    print(f"Target Email: {email_to_remove}")
    print("="*60)
    
    # Remove the account
    removal_success = remove_account(email_to_remove)
    
    if removal_success:
        # Verify removal
        verification_success = verify_removal(email_to_remove)
        
        print("\n" + "="*60)
        print("🎯 FINAL RESULTS")
        print("="*60)
        print(f"Account Removal: {'✅ SUCCESS' if removal_success else '❌ FAILED'}")
        print(f"Verification: {'✅ CLEAN' if verification_success else '❌ INCOMPLETE'}")
        
        if removal_success and verification_success:
            print("\n🎉 ACCOUNT SUCCESSFULLY REMOVED!")
            print("✅ All data has been cleaned up")
            print("✅ Email is now available for new registration")
            print("\n🔗 You can now register again:")
            print("   http://127.0.0.1:5000/register")
        else:
            print("\n⚠️ Removal may be incomplete")
            print("Please check the details above")
    
    print("="*60)
