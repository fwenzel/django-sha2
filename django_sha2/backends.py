from django.contrib.auth.backends import ModelBackend


class BcBackend(ModelBackend):
    """bcrypt and HMAC backend."""
    pass


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
