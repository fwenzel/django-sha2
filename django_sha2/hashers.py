import base64
import hmac
import hashlib
import logging

import bcrypt

from django.conf import settings
from django.contrib.auth.hashers import (BCryptPasswordHasher,
                                         BasePasswordHasher, mask_hash)
from django.utils.crypto import constant_time_compare
from django.utils.encoding import smart_str
from django.utils.datastructures import SortedDict

log = logging.getLogger('common.hashers')

algo_name = lambda hmac_id: 'bcrypt{0}'.format(hmac_id.replace('-', '_'))


def get_hasher(hmac_id):
    """
    Dynamically create password hashers based on hmac_id.

    This class takes the hmac_id corresponding to an HMAC_KEY and creates a
    password hasher class based off of it. This allows us to use djangos
    built-in updating mechanisms to automatically update the HMAC KEYS.
    """
    dash_hmac_id = hmac_id.replace('_', '-')

    class BcryptHMACPasswordHasher(BCryptPasswordHasher):
        algorithm = algo_name(hmac_id)
        rounds = getattr(settings, 'BCRYPT_ROUNDS', 12)

        def encode(self, password, salt):

            shared_key = settings.HMAC_KEYS[dash_hmac_id]

            hmac_value = self._hmac_create(password, shared_key)
            bcrypt_value = bcrypt.hashpw(hmac_value, salt)
            return '{0}{1}${2}'.format(
                self.algorithm,
                bcrypt_value,
                dash_hmac_id)

        def verify(self, password, encoded):
            algo_and_hash, key_ver = encoded.rsplit('$', 1)
            try:
                shared_key = settings.HMAC_KEYS[key_ver]
            except KeyError:
                log.info('Invalid shared key version "{0}"'.format(key_ver))
                return False

            bc_value = '${0}'.format(algo_and_hash.split('$', 1)[1])  # Yes, bcrypt <3s the leading $.
            hmac_value = self._hmac_create(password, shared_key)
            return bcrypt.hashpw(hmac_value, bc_value) == bc_value

        def _hmac_create(self, password, shared_key):
            """Create HMAC value based on pwd"""
            hmac_value = base64.b64encode(hmac.new(
                    smart_str(shared_key),
                    smart_str(password),
                    hashlib.sha512).digest())
            return hmac_value

    return BcryptHMACPasswordHasher

# We must have HMAC_KEYS. If not, let's raise an import error.
if not settings.HMAC_KEYS:
    raise ImportError('settings.HMAC_KEYS must not be empty.')

# For each HMAC_KEY, dynamically create a hasher to be imported.
for hmac_key in settings.HMAC_KEYS.keys():
    hmac_id = hmac_key.replace('-', '_')
    globals()[algo_name(hmac_id)] = get_hasher(hmac_id)


class BcryptHMACCombinedPasswordVerifier(BCryptPasswordHasher):
    """
    This reads anything with 'bcrypt' as the algo. This should be used
    to read bcypt values (with or without HMAC) in order to re-encode them
    as something else.
    """
    algorithm = 'bcrypt'
    rounds = getattr(settings, 'BCRYPT_ROUNDS', 12)

    def encode(self, password, salt):
        """This hasher is not meant to be used for encoding"""
        raise NotImplementedError()

    def verify(self, password, encoded):
        algo_and_hash, key_ver = encoded.rsplit('$', 1)
        try:
            shared_key = settings.HMAC_KEYS[key_ver]
        except KeyError:
            log.info('Invalid shared key version "{0}"'.format(key_ver))
            # Fall back to normal bcrypt
            algorithm, data = encoded.split('$', 1)
            return constant_time_compare(data, bcrypt.hashpw(password, data))

        bc_value = '${0}'.format(algo_and_hash.split('$', 1)[1])  # Yes, bcrypt <3s the leading $.
        hmac_value = self._hmac_create(password, shared_key)
        return bcrypt.hashpw(hmac_value, bc_value) == bc_value

    def _hmac_create(self, password, shared_key):
        """Create HMAC value based on pwd"""
        hmac_value = base64.b64encode(hmac.new(
                smart_str(shared_key),
                smart_str(password),
                hashlib.sha512).digest())
        return hmac_value


class SHA256PasswordHasher(BasePasswordHasher):
    """The SHA256 password hashing algorithm."""
    algorithm = 'sha256'

    def encode(self, password, salt):
        assert password
        assert salt and '$' not in salt
        hash = getattr(hashlib, self.algorithm)(salt + password).hexdigest()
        return '%s$%s$%s' % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        return SortedDict([
            ('algorithm', algorithm),
            ('salt', mask_hash(salt, show=2)),
            ('hash', mask_hash(hash)),
        ])


class SHA1PasswordHasher(SHA256PasswordHasher):
    """The SHA1 password hashing algorithm."""
    algorithm = 'sha1'


class SHA512PasswordHasher(SHA256PasswordHasher):
    """The SHA512 password hashing algorithm."""
    algorithm = 'sha512'


class SHA512b64PasswordHasher(SHA512PasswordHasher):
    """The SHA512 password hashing algorithm with base64 encoding."""
    algorithm = 'sha512b64'

    def encode(self, password, salt):
        assert password
        assert salt and '$' not in salt
        hash = base64.encodestring(hashlib.sha512(salt + password).digest())
        return '%s$%s$%s' % (self.algorithm, salt, hash)
