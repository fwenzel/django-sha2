from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import NoArgsCommand

from django_sha2 import bcrypt_auth


class Command(NoArgsCommand):

    requires_model_validation = False
    output_transaction = True

    def handle_noargs(self, **options):

        if not settings.PWD_ALGORITHM == 'bcrypt':
            return

        for user in User.objects.all():
            pwd = user.password
            if pwd.startswith('hh$') or pwd.startswith('bcrypt$'):
                continue  # Password has already been strengthened.

            try:
                alg, salt, hash = pwd.split('$')
            except ValueError:
                continue  # Probably not a password we understand.

            bc_value = bcrypt_auth.create_hash(pwd)
            # 'hh' stands for 'hardened hash'.
            new_password = '$'.join(['hh', alg, salt, bc_value])
            user.password = new_password
            user.save()
