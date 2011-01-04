"""
from future import django_sha2_support

Monkey-patch SHA-2 support into Django's auth system. If Django ticket #5600
ever gets fixed, this can be removed.


"""
import base64
import hashlib
import random
import os

from django.conf import settings
from django.contrib.auth import models as auth_models
from django.contrib.auth.backends import ModelBackend


BACKENDS = {
    'Sha256Backend': 'sha256',
    'Sha512Backend': 'sha512',
    'Sha512Base64Backend': 'sha512b64',
}

__all__ = (locals()[k] for k in BACKENDS.keys())


def monkeypatch():
    """
    Monkeypatch authentication backend if one of our backends was selected.
    """

    if not getattr(settings, 'AUTHENTICATION_BACKENDS'):
        return

    algo = ''
    for backend in BACKENDS:
        if (('django_sha2.auth.%s' % backend) in
            settings.AUTHENTICATION_BACKENDS):
            algo = BACKENDS[backend]
            break

    if not algo:
        return

    def get_hexdigest(algorithm, salt, raw_password):
        """Generate SHA-256 or SHA-512 hash."""
        if algorithm in ('sha256', 'sha512'):
            return getattr(hashlib, algorithm)(salt + raw_password).hexdigest()
        elif algorithm == 'sha512b64':
            return base64.encodestring(hashlib.sha512(
                salt + raw_password).digest())
        else:
            return get_hexdigest_old(algorithm, salt, raw_password)
    get_hexdigest_old = auth_models.get_hexdigest
    auth_models.get_hexdigest = get_hexdigest

    def set_password(self, raw_password):
        salt = os.urandom(10).encode('hex')  # Random, 20-digit (hex) salt.
        hsh = get_hexdigest(algo, salt, raw_password)
        self.password = '$'.join((algo, salt, hsh))
    set_password_old = auth_models.User.set_password
    auth_models.User.set_password = set_password

    # max_length for SHA512 must be at least 156 characters. NB: The DB needs
    # to be fixed separately.
    if algo == 'sha512':
        pwfield = auth_models.User._meta.get_field('password')
        pwfield.max_length = max(pwfield.max_length, 255)  # Need at least 156.
monkeypatch()


class Sha256Backend(ModelBackend):
    """
    Overriding the Django model backend without changes ensures our
    monkeypatching happens by the time we import auth.
    """
    pass


class Sha512Backend(ModelBackend):
    """SHA512 backend that does not fit into a 128-char password field."""
    pass


class Sha512Base64Backend(ModelBackend):
    """SHA512 backend that fits into a 128-char password field."""
    pass

