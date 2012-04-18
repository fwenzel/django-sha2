VERSION = (0, 4)
__version__ = '.'.join(map(str, VERSION))


def get_password_hashers(BASE_PASSWORD_HASHERS, HMAC_KEYS):
    """
    Returns the names of the dynamic and regular hashers
    created in our hashers file
    """
    # Where is the bcrypt hashers file located?
    hashers_base = 'django_sha2.hashers.{0}'
    algo_name = lambda hmac_id: 'bcrypt{0}'.format(hmac_id.replace('-', '_'))

    dynamic_hasher_names = [algo_name(key) for key in HMAC_KEYS.keys()]
    dynamic_hashers = [hashers_base.format(k) for k in dynamic_hasher_names]

    return dynamic_hashers + list(BASE_PASSWORD_HASHERS)
