from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from authentication.models import UserProfile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def post_save_user(sender, instance, created, **kwargs):
    """
    Signal handler that creates a UserProfile instance whenever a new user is created.

    Args:
        sender (Model class): The model class that sent the signal (User model in this case).
        instance (Model instance): The actual instance of the model being saved.
        created (bool): A boolean indicating whether a new record was created.
        **kwargs: Additional keyword arguments.

    If a new user is created (created=True), this function will automatically create
    a corresponding UserProfile instance linked to the user.
    """
    if created:
        UserProfile.objects.create(user=instance)
