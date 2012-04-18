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

    def test_newest_hmac_key_used(self):
        """
        Make sure the first hasher (the one used for encoding) has the right
        hmac key.
        """
        eq_(settings.PASSWORD_HASHERS[0][-10:].replace('_', '-'),
            max(settings.HMAC_KEYS.keys()))

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
        # Get an old password hasher to encode John's password with.
        from django_sha2.hashers import bcrypt2010_01_01
        old_hasher = bcrypt2010_01_01()

        john = User.objects.get(username='john')
        john.password = old_hasher.encode('123456', old_hasher.salt())
        john.save()

        # Log in.
        assert authenticate(username='john', password='123456')

        # Make sure the DB now has a new password hash.
        john = User.objects.get(username='john')
        eq_(john.password.rsplit('$', 1)[1], max(settings.HMAC_KEYS.keys()))

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
        eq_(john.password[:6], 'bcrypt')

        # Log in again with the new hash.
        assert authenticate(username='john', password='123')
