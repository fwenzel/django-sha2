# -*- coding:utf-8 -*-
from django import test
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from mock import patch
from nose.tools import eq_


class BcryptTests(test.TestCase):
    def setUp(self):
        super(BcryptTests, self).setUp()
        User.objects.create_user('john', 'johndoe@example.com',
                                 password='123456')
        User.objects.create_user('jane', 'janedoe@example.com',
                                 password='abc')
        User.objects.create_user('jude', 'jeromedoe@example.com',
                                 password=u'abcéäêëôøà')

    def test_bcrypt_used(self):
        """Make sure bcrypt was used as the hash."""
        eq_(User.objects.get(username='john').password[:6], 'bcrypt')
        eq_(User.objects.get(username='jane').password[:6], 'bcrypt')
        eq_(User.objects.get(username='jude').password[:6], 'bcrypt')

    def test_bcrypt_auth(self):
        """Try authenticating."""
        assert authenticate(username='john', password='123456')
        assert authenticate(username='jane', password='abc')
        assert not authenticate(username='jane', password='123456')
        assert authenticate(username='jude', password=u'abcéäêëôøà')
        assert not authenticate(username='jude', password=u'çççbbbààà')

    @patch.object(settings._wrapped, 'HMAC_KEYS', dict())
    def test_nokey(self):
        """With no HMAC key, no dice."""
        assert not authenticate(username='john', password='123456')
        assert not authenticate(username='jane', password='abc')
        assert not authenticate(username='jane', password='123456')
        assert not authenticate(username='jude', password=u'abcéäêëôøà')
        assert not authenticate(username='jude', password=u'çççbbbààà')

    def test_hmac_autoupdate(self):
        """Auto-update HMAC key if hash in DB is outdated."""
        # Get HMAC key IDs to compare
        old_key_id = max(settings.HMAC_KEYS.keys())
        new_key_id = '2020-01-01'

        # Add a new HMAC key
        new_keys = settings.HMAC_KEYS.copy()
        new_keys[new_key_id] = 'a_new_key'
        with patch.object(settings._wrapped, 'HMAC_KEYS', new_keys):
            # Make sure the database has the old key ID.
            john = User.objects.get(username='john')
            eq_(john.password.rsplit('$', 1)[1], old_key_id)

            # Log in.
            assert authenticate(username='john', password='123456')

            # Make sure the DB now has a new password hash.
            john = User.objects.get(username='john')
            eq_(john.password.rsplit('$', 1)[1], new_key_id)

    def test_rehash(self):
        """Auto-upgrade to stronger hash if needed."""
        # Set a sha256 hash for a user. This one is "123".
        john = User.objects.get(username='john')
        john.password = ('sha256$7a49025f024ad3dcacad$aaff1abe5377ffeab6ccc68'
                         '709d94c1950edf11f02d8acb83c75d8fcac1ebeb1')
        john.save()

        # The hash should be sha256 now.
        john = User.objects.get(username='john')
        eq_(john.password.split('$', 1)[0], 'sha256')

        # Log in (should rehash transparently).
        assert authenticate(username='john', password='123')

        # Make sure the DB now has a bcrypt hash.
        john = User.objects.get(username='john')
        eq_(john.password.split('$', 1)[0], 'bcrypt')

        # Log in again with the new hash.
        assert authenticate(username='john', password='123')

