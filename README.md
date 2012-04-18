Strong password hashes for Django
=================================

This is a monkey-patch for Django, adding strong password hashing to be used
by default.

Getting started
---------------

Install this app using ``easy_install`` or ``pip``, and enable it by adding
the following to your ``settings.py`` file:

    INSTALLED_APPS = (
        # ...
        'django.contrib.auth',
        'django_sha2',  # Load after auth to monkey-patch it.
        # ...
    )
    PWD_ALGORITHM = 'bcrypt'  # one of: bcrypt, sha512, sha512b64, sha256
    BCRYPT_ROUNDS = 12  # optional. 12 is the default. Only needed for bcrypt.

Add something like the following to your ``settings_local.py`` file, and keep
it secret:

    HMAC_KEYS = {
        '2011-01-01': 'ThisisASharedKey',
        '2010-06-01': 'OldSharedKey',
        '2010-01-01': 'EvenOlderSharedKey'
    }

``HMAC_KEYS`` is a dictionary ``{key-id: shared-secret}``. You only need one
key to start. The dictionary key can be an ISO date, or almost anything else,
but the latest key will be determined by sorting.

**Note:** If you don't have a ``settings_local.py`` file or similar, make sure
to use ``from settings_local import *`` at the end of ``settings.py`` and add
it to the ignore file for your version control system, so it becomes part of
your Django settings, but is not committed to the repository.

This change is backwards-compatible (i.e., existing SHA-1 hashes in the
database keep on working), and does not require database changes\*.

\*: unless you're using SHA-512 (see below).


The default: Bcrypt and HMAC
----------------------------

A quick overview over the default hash algorithm: It uses a combination of
Bcrypt and HMAC with SHA-512. [HMAC][hmac] is a hash function that involves
the use of a secret key -- the ``HMAC_KEYS`` you entered above will be used
for the calculation.

The reason a machine-local secret is involved in the calculation is so that
if an attacker gains access to a database, the data will be useless without
_also_ having gained file-system access to steal the local secret.

``HMAC_KEYS`` is a dictionary so that you can change the key periodically
and deprecate old keys, or revoke keys altogether that are too old or you
fear might have leaked.

Second, the hash is hashed again using [bcrypt][bcrypt], which is
computationally hard and therefore protects better against brute-force offline
attacks.

[hmac]: http://en.wikipedia.org/wiki/HMAC
[bcrypt]: http://bcrypt.sourceforge.net/


Transparent password rehashing
------------------------------
In case you have existing users with weaker password hashes (like SHA-1) in
the database, django\_sha2 will **automatically rehash** their password in the
database with a your currently chosen hash algorithm during their next login.

This is enabled by default. If you don't like it, set this in your settings
file:

    PWD_REHASH = False

Similarly, django\_sha2 automatically updates users' password hashes to the
**latest HMAC key** on login, which is usually what you want, so it is enabled
by default. To disable, set this setting:

    PWD_HMAC_REKEY = False


A note on SHA-512
-----------------
Django's default password field is limited to 128 characters, which does not
fit a hex-encoded SHA512 hash. In order to not require a database migration
for every project that uses this, we encode the SHA512 hash in Base 64 as
opposed to hex. To use this, set your hash backend as follows:

    PWD_ALGORITHM = 'sha512b64'

If you want to use hex-encoded SHA512 instead, use the following:

    PWD_ALGORITHM = 'sha512'

Be advised, however, that you need to ensure your database's password field can
hold at least 156 characters.

When starting a new project, it is safe to use the Sha512 backend straight away:
django\_sha2 will create the password field with a ``max_length`` of 255 when
running ``syncdb`` for the first time.


History
-------
This started off as a monkey-patch for SHA-256 in Django and, over SHA-512,
turned into a strong hash library featuring bcrypt and hmac support.

For the initial idea, read the [blog post][blog] about it.

[blog]: http://fredericiana.com/2010/10/12/adding-support-for-stronger-password-hashes-to-django/

Using django 1.4
-------

Django 1.4 allows us to create our own password hashers. Because of some of the
design choices of django's model, we have to generate a hasher class for each
of our HMAC_KEYS. Lucky for you, we have code to help you! Define
BASE_PASSWORD_HASHERS for all hashers you might use to decrypt something in
your database (i.e. if in the past you used SHA256, make sure its in this
setting). Form there, if you follow the code below, all your passwords will
automatically stay up to date with the latest algorthim/hmac_key.

This is an example settings file snippet:

```python
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
```
