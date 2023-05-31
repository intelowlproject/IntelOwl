from django.urls import path

from .views import PhoneDeleteView, PhoneSetupView

urlpatterns = [
    path(
        "account/two_factor/backup/phone/register/",
        PhoneSetupView.as_view(),
        name="phone_create",
    ),
    path(
        "account/two_factor/backup/phone/unregister/<int:pk>/",
        PhoneDeleteView.as_view(),
        name="phone_delete",
    ),
]
