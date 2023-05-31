from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

# from django.urls import reverse_lazy
# from django.utils.decorators import method_decorator
# from django.utils.functional import lazy
from django.views.decorators.cache import never_cache

# from django.views.generic import FormView, TemplateView
from django_otp import devices_for_user
from django_otp.decorators import otp_required

from two_factor.plugins.phonenumber.utils import (
    backup_phones,
    get_available_phone_methods,
)

from ..forms import DisableForm
from ..utils import default_device


@never_cache
@login_required
def ProfileView(request):
    try:
        backup_tokens = request.user.staticdevice_set.all()[0].token_set.count()
    except Exception:
        backup_tokens = 0

    context = {
        "default_device": default_device(request.user),
        "default_device_type": default_device(request.user).__class__.__name__,
        "backup_phones": backup_phones(request.user),
        "backup_tokens": backup_tokens,
        "available_phone_methods": get_available_phone_methods(),
    }

    return render(request, "profile.jsx", context)


@never_cache
@otp_required(login_url=settings.LOGIN_REDIRECT_URL, redirect_field_name=None)
def DisableView(request):
    if request.method == "POST":
        form = DisableForm(request.POST)
        if form.is_valid():
            for device in devices_for_user(request.user):
                device.delete()
            return redirect(settings.LOGIN_REDIRECT_URL)
    else:
        form = DisableForm()

    context = {
        "form": form,
    }

    return render(request, "disable.jsx", context)
