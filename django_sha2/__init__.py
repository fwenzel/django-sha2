VERSION = (0, 4)
__version__ = '.'.join(map(str, VERSION))

def get_dynamic_hasher_names(HMAC_KEYS):
    """
    Return base dynamic hasher names for each entry in HMAC_KEYS (we need to
    create one hasher class for each key). Names are sorted to make sure
    the HMAC_KEYS are tested in the correct order and the first one is always
    the first hasher name returned.
    """
    algo_name = lambda hmac_id: 'bcrypt{0}'.format(hmac_id.replace('-', '_'))
    return [algo_name(key) for key in sorted(HMAC_KEYS.keys(), reverse=True)]

def get_password_hashers(BASE_PASSWORD_HASHERS, HMAC_KEYS):
    """
    Return the names of the dynamic and regular hashers
    created in our hashers file.
    """
    # Where is the bcrypt hashers file located?
    hashers_base = 'django_sha2.hashers.{0}'

    dynamic_hasher_names = get_dynamic_hasher_names(HMAC_KEYS)
    dynamic_hashers = [hashers_base.format(k) for k in dynamic_hasher_names]

    return dynamic_hashers + list(BASE_PASSWORD_HASHERS)
