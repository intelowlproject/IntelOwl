from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth.models import Group
from guardian.shortcuts import assign_perm


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_profile(sender, instance, created, **kwargs):
    """
    Everytime a new user is created, add it to the DefaultGlobal group.
    """
    if instance.username == "AnonymousUser":
        # NoOp during testing
        return

    if created:
        grp, grp_created = Group.objects.get_or_create(name="DefaultGlobal")
        if grp_created:
            # view/add permissions for Job model
            assign_perm("api_app.view_job", grp)
            assign_perm("api_app.add_job", grp)
            # view/add/change permissions for Tag model
            assign_perm("api_app.view_tag", grp)
            assign_perm("api_app.add_tag", grp)
            assign_perm("api_app.change_tag", grp)
            grp.save()
        instance.groups.add(grp)
