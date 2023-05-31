from django.urls import path

from .views import TwilioCallApp

urlpatterns = (
    [
        path(
            "twilio/inbound/two_factor/<int:token>/",
            TwilioCallApp.as_view(),
            name="call_app",
        ),
    ],
    "two_factor_twilio",
)
