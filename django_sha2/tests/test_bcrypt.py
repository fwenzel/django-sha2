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
