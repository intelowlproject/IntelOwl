from django.contrib.auth.decorators import login_required
from django.http.response import Http404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic import TemplateView


@method_decorator(never_cache, name="dispatch")
class DynamicJS(TemplateView):
    def get_extra_context_data(self):
        raise NotImplementedError()

    def get_context_data(self, *args, **kwargs):
        extra_context = self.get_extra_context_data()
        if not extra_context:
            raise Http404()

        context = super().get_context_data(*args, **kwargs)
        context.update(extra_context)

        return context


@method_decorator(login_required, name="dispatch")
class CreateCredentialJS(DynamicJS):
    template_name = "two_factor_webauthn/create_credential.js"

    def get_extra_context_data(self):
        credential_creation_options = self.request.session.get(
            "webauthn_creation_options"
        )
        if credential_creation_options:
            return {"credential_creation_options": credential_creation_options}
        return None


class GetCredentialJS(DynamicJS):
    template_name = "two_factor_webauthn/get_credential.js"

    def get_extra_context_data(self):
        credential_request_options = self.request.session.get(
            "webauthn_request_options"
        )
        if credential_request_options:
            return {"credential_request_options": credential_request_options}
        return None
