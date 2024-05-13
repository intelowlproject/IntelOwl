from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from authentication.models import UserProfile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def post_save_user(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
