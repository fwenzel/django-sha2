SHA-256 password hashes for Django
==================================

This is a monkey-patch for Django to use SHA-256 hashes for its passwords by
default.

For more information, read the [blog post][blog] about it.

[blog]: http://fredericiana.com/2010/10/12/adding-support-for-stronger-password-hashes-to-django/


Getting started
---------------

Install this app using ``easy_install`` or ``pip``, and enable it by adding
the following line to your ``settings.py`` file:

    AUTHENTICATION_BACKENDS = ('myapp.auth.Sha256Backend',)

