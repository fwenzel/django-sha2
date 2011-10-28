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


ALGOS = (
    'bcrypt',
    'sha256',
    'sha512',
    'sha512b64',
)


def monkeypatch():
    """
    Monkeypatch authentication backend if one of our backends was selected.
    """

    algo = getattr(settings, 'PWD_ALGORITHM', 'bcrypt')
    if not algo in ALGOS:
        return  # TODO: log a warning?

    # max_length for SHA512 must be at least 156 characters. NB: The DB needs
    # to be fixed separately.
    if algo == 'sha512':
        pwfield = auth_models.User._meta.get_field('password')
        pwfield.max_length = max(pwfield.max_length, 255)  # Need at least 156.

    # Do not import bcrypt stuff unless needed
    if algo == 'bcrypt':
        from django_sha2 import bcrypt_auth


    def set_password(self, raw_password):
        """Wrapper to set strongly hashed password for Django."""
        if raw_password is None:
            self.set_unusable_password()
            return
        if algo != 'bcrypt':
            salt = os.urandom(10).encode('hex')  # Random, 20-digit (hex) salt.
            hsh = get_hexdigest(algo, salt, raw_password)
            self.password = '$'.join((algo, salt, hsh))
        else:
            self.password = bcrypt_auth.create_hash(raw_password)
    set_password_old = auth_models.User.set_password
    auth_models.User.set_password = set_password

    def check_password(self, raw_password):
        """
        Check a raw PW against the DB.

        Checks strong hashes, but falls back to built-in hashes as needed.
        Supports automatic upgrading to stronger hashes.
        """
        hashed_with = self.password.split('$', 1)[0]
        if hashed_with == 'bcrypt':
            matched = bcrypt_auth.check_password(self, raw_password)
        else:
            matched = check_password_old(self, raw_password)

        # Update password hash in DB if out-of-date hash algorithm is used and
        # auto-upgrading is enabled.
        if (matched and getattr(settings, 'PWD_REHASH', True) and
            hashed_with != algo):
            self.set_password(raw_password)
            self.save()

        return matched
    check_password_old = auth_models.User.check_password
    auth_models.User.check_password = check_password

    def get_hexdigest(algorithm, salt, raw_password):
        """Generate SHA-256 or SHA-512 hash (not used for bcrypt)."""
        salt, raw_password = map(lambda s: unicode(s).encode('utf-8'),
                                 (salt, raw_password))
        if algorithm in ('sha256', 'sha512'):
            return getattr(hashlib, algorithm)(salt + raw_password).hexdigest()
        elif algorithm == 'sha512b64':
            return base64.encodestring(hashlib.sha512(
                salt + raw_password).digest())
        else:
            return get_hexdigest_old(algorithm, salt, raw_password)
    get_hexdigest_old = auth_models.get_hexdigest
    auth_models.get_hexdigest = get_hexdigest

monkeypatch()
