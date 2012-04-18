import os
import sys

## Generic settings
TEST_RUNNER = 'django_nose.runner.NoseTestSuiteRunner'

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
path = lambda *a: os.path.join(PROJECT_ROOT, *a)

sys.path.insert(0, path('..', '..'))

DATABASES = {
    'default': {
        'NAME': 'test.db',
        'ENGINE': 'django.db.backends.sqlite3',
    }
}

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django_nose',
)

## django-sha2 settings
HMAC_KEYS = {
    '2010-06-01': 'OldSharedKey',
    '2011-01-01': 'ThisisASharedKey',
    '2010-01-01': 'EvenOlderSharedKey'
}

BASE_PASSWORD_HASHERS = (
    'django_sha2.hashers.BcryptHMACCombinedPasswordVerifier',
    'django_sha2.hashers.SHA512PasswordHasher',
    'django_sha2.hashers.SHA256PasswordHasher',
    'django.contrib.auth.hashers.SHA1PasswordHasher',
    'django.contrib.auth.hashers.MD5PasswordHasher',
    'django.contrib.auth.hashers.UnsaltedMD5PasswordHasher',
)

from django_sha2 import get_password_hashers
PASSWORD_HASHERS = get_password_hashers(BASE_PASSWORD_HASHERS, HMAC_KEYS)
