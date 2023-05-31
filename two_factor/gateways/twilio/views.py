from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.response import TemplateResponse
from django.utils import translation
from django.utils.translation import check_for_language, pgettext
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from ...views.utils import class_view_decorator
from .gateway import validate_voice_locale


@class_view_decorator(never_cache)
@class_view_decorator(csrf_exempt)
class TwilioCallApp(View):
    """
    View used by Twilio for the interactive token verification by phone.
    """

    templates = {
        "press_a_key": "two_factor/twilio/press_a_key.xml",
        "token": "two_factor/twilio/token.xml",
    }

    def get(self, request, token):
        return self.create_response(request, self.templates["press_a_key"])

    def post(self, request, token):
        return self.create_response(request, self.templates["token"])

    def create_response(self, request, template_path):
        with translation.override(self.get_locale()):
            template_context = {
                "locale": self.get_twilio_locale(),
                "site_name": get_current_site(self.request).name,
                "token": list(str(self.kwargs["token"]))
                if self.request.method == "POST"
                else "",
            }
            return TemplateResponse(
                request, template_path, template_context, content_type="text/xml"
            )

    def get_locale(self):
        locale = self.request.GET.get("locale", "")
        if not check_for_language(locale):
            locale = settings.LANGUAGE_CODE
        validate_voice_locale(locale)
        return locale

    def get_twilio_locale(self):
        # Translators: twilio_locale should be a locale supported by
        # Twilio, see http://bit.ly/187I5cr
        return pgettext("twilio_locale", "en")
