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
    'django_sha2',
    'django.contrib.contenttypes',
    'django_nose',
)

## django-sha2 settings
PWD_ALGORITHM = 'bcrypt'
HMAC_KEYS = {
    '2011-01-01': 'ThisisASharedKey',
    '2010-06-01': 'OldSharedKey',
    '2010-01-01': 'EvenOlderSharedKey'
}
