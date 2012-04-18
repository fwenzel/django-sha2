"""Make sure django.contrib.auth monkeypatching happens on load."""
from django.conf import settings

# If we don't have password hashers, we need to monkey patch the auth module.
if not hasattr(settings, 'PASSWORD_HASHERS'):
    from django_sha2 import auth
