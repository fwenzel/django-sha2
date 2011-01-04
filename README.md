SHA-2 password hashes for Django
================================

This is a monkey-patch for Django to use SHA-256 or SHA-512 hashes for its
passwords by default.

For more information, read the [blog post][blog] about it.

[blog]: http://fredericiana.com/2010/10/12/adding-support-for-stronger-password-hashes-to-django/


Getting started
---------------

Install this app using ``easy_install`` or ``pip``, and enable it by adding
the following line to your ``settings.py`` file:

    AUTHENTICATION_BACKENDS = ('django_sha2.auth.Sha256Backend',)

This change is backwards-compatible (i.e., existing SHA-1 hashes in the
database keep on working), and does not require database changes.


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

