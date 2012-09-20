"""bcrypt and hmac implementation for Django."""
import base64
import hashlib
import logging

import bcrypt
import hmac

from django.conf import settings
from django.contrib.auth.models import get_hexdigest
from django.utils.encoding import smart_str


log = logging.getLogger('django_sha2')


def create_hash(userpwd):
    """Given a password, create a key to be stored in the DB."""
    if not settings.HMAC_KEYS:
        raise ImportError('settings.HMAC_KEYS must not be empty. Read the '
                          'django_sha2 docs!')
    latest_key_id = max(settings.HMAC_KEYS.keys())
    shared_key = settings.HMAC_KEYS[latest_key_id]

    return ''.join((
        'bcrypt', _bcrypt_create(_hmac_create(userpwd, shared_key)),
        '$', latest_key_id))


def check_password(user, raw_password):
    """Given a DB entry and a raw password, check its validity."""

    # Check if the user's password is a "hardened hash".
    if user.password.startswith('hh$'):
        alg, salt, bc_pwd = user.password.split('$', 3)[1:]
        hash = get_hexdigest(alg, salt, raw_password)
        algo_and_hash, key_ver = bc_pwd.rsplit('$', 1)
        try:
            shared_key = settings.HMAC_KEYS[key_ver]
        except KeyError:
            log.info('Invalid shared key version "{0}"'.format(key_ver))
            return False
        bc_value = algo_and_hash[6:]
        hmac_value = _hmac_create('$'.join([alg, salt, hash]), shared_key)

        if _bcrypt_verify(hmac_value, bc_value):
            # Password is a match, convert to bcrypt format.
            user.set_password(raw_password)
            user.save()
            return True

        return False

    # Normal bcrypt password checking.
    algo_and_hash, key_ver = user.password.rsplit('$', 1)
    try:
        shared_key = settings.HMAC_KEYS[key_ver]
    except KeyError:
        log.info('Invalid shared key version "{0}"'.format(key_ver))
        return False
    bc_value = algo_and_hash[algo_and_hash.find('$'):]  # Yes, bcrypt <3s the leading $.
    hmac_value = _hmac_create(raw_password, shared_key)
    matched = _bcrypt_verify(hmac_value, bc_value)

    # Update password hash if HMAC key has since changed.
    if matched and getattr(settings, 'PWD_HMAC_REKEY', True):
        latest_key_id = max(settings.HMAC_KEYS.keys())
        if key_ver != latest_key_id:
            user.set_password(raw_password)
            user.save()

    return matched


def _hmac_create(userpwd, shared_key):
    """Create HMAC value based on pwd and system-local and per-user salt."""
    hmac_value = base64.b64encode(hmac.new(
        smart_str(shared_key), smart_str(userpwd), hashlib.sha512).digest())
    return hmac_value


def _bcrypt_create(hmac_value):
    """Create bcrypt hash."""
    rounds = getattr(settings, 'BCRYPT_ROUNDS', 12)
    # No need for us to create a user salt, bcrypt creates its own.
    bcrypt_value = bcrypt.hashpw(hmac_value, bcrypt.gensalt(int(rounds)))
    return bcrypt_value


def _bcrypt_verify(hmac_value, bcrypt_value):
    """Verify an hmac hash against a bcrypt value."""
    return bcrypt.hashpw(hmac_value, bcrypt_value) == bcrypt_value
