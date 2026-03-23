import os
import django
import logging

# Setup the DjanGO Environment vars
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "intel_owl.settings")
django.setup()

from django.contrib.auth import get_user_model
from api_app.models import Job, Analyzable
from api_app.websocket import JobConsumer
from api_app.choices import Classification, TLP

User = get_user_model()

def verify_fix():
    # 1. Setup  the data
    print("--- Setting up test data ---")
    user_a, _ = User.objects.get_or_create(username="user_a_test")
    user_b, _ = User.objects.get_or_create(username="user_b_test")
    
    import uuid
    analyzable_name = f"test_{uuid.uuid4()}.com"
    analyzable = Analyzable.objects.create(name=analyzable_name, classification=Classification.DOMAIN)
    job_b = Job.objects.create(user=user_b, analyzable=analyzable, tlp=TLP.RED)
    print(f"Created Job {job_b.id} with TLP:RED owned by {user_b.username}")


    class MockJobConsumer(JobConsumer):
        def __init__(self, scope):
            self.scope = scope
            self.closed_code = None
            self.accepted = False
            self.sent_data = False

        def close(self, code=None):
            self.closed_code = code
            print(f"Consumer closed with code: {code}")

        def accept(self):
            self.accepted = True
            print("Consumer accepted connection")
        
        @classmethod
        def serialize_and_send_job(cls, job):
            pass

    # 2. Test for unauthorized access
    print("\n--- Testing Unauthorized Access (User A -> Job B) ---")
    scope_unauth = {
        "user": user_a,
        "url_route": {"kwargs": {"job_id": job_b.id}}
    }
    consumer_unauth = MockJobConsumer(scope_unauth)
    
    try:
        consumer_unauth.connect()
    except Exception as e:
        print(f"Error during connect: {e}")

    if consumer_unauth.closed_code == 4040 and not consumer_unauth.accepted:
        print("✅ SUCCESS: Connection was REJECTED with 4040. Access blocked.")
    else:
        print(f"❌ FAILURE: Connection was NOT rejected properly. Code: {consumer_unauth.closed_code}, Accepted: {consumer_unauth.accepted}")

    # 3. Test for unauthorized access
    print("\n--- Testing Authorized Access (User B -> Job B) ---")
    scope_auth = {
        "user": user_b,
        "url_route": {"kwargs": {"job_id": job_b.id}}
    }
    consumer_auth = MockJobConsumer(scope_auth)
    
    try:
        consumer_auth.connect()
    except Exception as e:
        print(f"Error during connect: {e}")

    if consumer_auth.accepted:
        print("✅ SUCCESS: Connection was ACCEPTED for the owner.")
    else:
        print(f"❌ FAILURE: Connection was REJECTED for the owner. Code: {consumer_auth.closed_code}")

    # Cleanup
    job_b.delete()
    analyzable.delete()
    user_a.delete()
    user_b.delete()

if __name__ == "__main__":
    # Suppress logs for cleaner output
    logging.getLogger("api_app.websocket").setLevel(logging.CRITICAL)
    try:
        verify_fix()
    except Exception as e:
        print(f"Critical error: {e}")
