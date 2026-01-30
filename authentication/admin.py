# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Optional

import email_utils
from django.conf import settings
from django.contrib import admin, messages
from django.db.models import Q
from django.utils.translation import ngettext

from certego_saas.apps.user.admin import AbstractUserAdmin
from certego_saas.apps.user.models import User

from .models import UserProfile

__all__ = ["UserAdminView", "UserProfileAdmin"]


class UserProfileInlineAdmin(admin.StackedInline):
    model = UserProfile


# certego-saas
@admin.register(User)
class UserAdminView(AbstractUserAdmin):
    inlines = (UserProfileInlineAdmin,)
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_active",
        "approved",
        "is_email_verified",
        "is_staff",
    )
    actions = ["accept_users", "decline_users"]

    @admin.display(boolean=True)
    def is_email_verified(self, obj: User) -> Optional[bool]:
        return obj.is_email_verified

    @admin.action(description="Decline selected users")
    def decline_users(self, request, queryset):
        # 1. user email may or may not be verified
        # 2. we can not decline users that have been already accept
        declinable = Q(is_active=False) & Q(approved=None)
        users = queryset.filter(declinable).all()
        for user in users:
            email_utils.send_email(
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                subject="IntelOwl - Your account request has been declined",
                template_name="authentication/emails/account-declined",
                context={
                    "full_name": user.get_full_name(),
                    "username": user.get_username(),
                    "host_uri": settings.HOST_URI,
                    "host_name": settings.HOST_NAME,
                    "default_email": settings.DEFAULT_EMAIL,
                },
            )
        number_declined = users.update(approved=False, is_active=False)
        self.message_user(
            request,
            ngettext(
                "%d user was declined.",
                "%d users were declined.",
                number_declined,
            )
            % number_declined,
            messages.SUCCESS,
        )

    @admin.action(description="Accept selected users")
    def accept_users(self, request, queryset):
        # 1. user email should be verified
        # 2. we can accept previously declined users
        acceptable = (
            Q(email_address__is_verified=True) & Q(is_active=False) & (Q(approved=False) | Q(approved=None))
        )
        users = queryset.filter(acceptable).all()
        for user in users:
            email_utils.send_email(
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                subject="IntelOwl - Your account has been successfully activated!",
                template_name="authentication/emails/account-activated",
                context={
                    "full_name": user.get_full_name(),
                    "username": user.get_username(),
                    "host_uri": settings.HOST_URI,
                    "host_name": settings.HOST_NAME,
                    "default_email": settings.DEFAULT_EMAIL,
                },
            )
        number_updated = users.update(is_active=True, approved=True)
        self.message_user(
            request,
            ngettext(
                "%d user was successfully activated.",
                "%d users were successfully activated.",
                number_updated,
            )
            % number_updated,
            messages.SUCCESS,
        )


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_select_related = ("user",)
    list_display = (
        "user",
        "user_is_active",
        "user_is_approved",
        "twitter_handle",
        "company_name",
        "company_role",
        "discover_from",
        "task_priority",
        "is_robot",
    )
    list_filter = ["task_priority", "is_robot"]

    @admin.display(boolean=True)
    def user_is_active(self, obj: UserProfile) -> bool:
        return obj.user.is_active

    @admin.display(boolean=True)
    def user_is_approved(self, obj: UserProfile) -> Optional[bool]:
        return obj.user.approved
