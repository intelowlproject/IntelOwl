from django.dispatch import Signal

# Signal additional parameters are: request, user, and device.
user_verified = Signal()
