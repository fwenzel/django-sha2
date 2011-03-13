Strong password hashes for Django
=================================

This is a monkey-patch for Django, adding strong password hashing to be used
by default.

Getting started
---------------

Install this app using ``easy_install`` or ``pip``, and enable it by adding
the following line to your ``settings.py`` file:

    AUTHENTICATION_BACKENDS = ('django_sha2.auth.BcBackend',)
    BCRYPT_ROUNDS = 12  # optional. 12 is the default.

Add the following to your ``settings_local.py`` file, and keep it secret:

    HMAC_KEYS = {
        '2011-01-01': 'ThisisASharedKey',
        '2010-06-01': 'OldSharedKey',
        '2010-01-01': 'EvenOlderSharedKey'
    }

``HMAC_KEYS`` is a dictionary ``{key-id: shared-secret}``. You only need one
key to start. The dictionary key can be an ISO date, or almost anything else,
but the latest key will be determined by sorting.

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


A note on SHA-512
-----------------
Django's default password field is limited to 128 characters, which does not
fit a hex-encoded SHA512 hash. In order to not require a database migration
for every project that uses this, we encode the SHA512 hash in Base 64 as
opposed to hex. To use this, set your authentication backend as follows:

    AUTHENTICATION_BACKENDS = ('django_sha2.auth.Sha512Base64Backend',)

If you want to use hex-encoded SHA512 instead, use the following:

    AUTHENTICATION_BACKENDS = ('django_sha2.auth.Sha512Backend',)

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

