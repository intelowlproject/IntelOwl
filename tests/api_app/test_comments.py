from django.test import TransactionTestCase

from api_app.models import Job, Comment
from certego_saas.models import User

class TestComments(TransactionTestCase):
    def test_making_comments(self):
        user = User.objects.create_user(
            username="user",
            email="user@intelowl.com",
            password="test",
        )
        job = Job.objects.create(
            analyzers_to_execute=["AbuseIPDB"],
            user=user,
        )

        comment = Comment.objects.create(
            job=job,
            user=user,
            content="test comment",
        )
        self.assertEqual(comment.content, "test comment")
        self.assertEqual(comment.user, user)
        self.assertEqual(comment.job, job)
        comment.delete()
        job.delete()
        user.delete()
