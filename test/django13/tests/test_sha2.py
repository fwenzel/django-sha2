# -*- coding:utf-8 -*-
from django import test
from django.contrib.auth.models import get_hexdigest

from nose.tools import eq_


class Sha2Tests(test.TestCase):
    """Tests for sha256 and sha512."""
    SALT = '1234567890'
    HASHES = {
        'sha256': {
            '123456': ('7a51d064a1a216a692f753fcdab276e4ff201a01d8b66f56d50d'
                       '4d719fd0dc87'),
            'abc': ('343c791deda10905e9c03bccaeb75413c9ee960af7b1f2291f4acc9'
                    '925e2065a'),
            u'abcéäêëôøà': ('c69c2fba36f26b3fcb39a0ed1fec005271c93725'
                            'bcac10521333259179cc2a7f'),
        },
        'sha512': {
            '123456': ('1f52ed515871c913164398ec24c47088cdf957e81af28c899a8a'
                       '0195d3620e083968a6d4d86cb8f9bd7f909b23f75a1c044ec8e6'
                       '75c6efbcb0e4bf0eb445525d'),
            'abc': ('a559db3d96b76dee0c3cdaa9e9ee1f87bbc6c9c521636fd840e96fe'
                    '78959d4e8ebf99a13eab3fd2df4ec76aac733cc5e2e5a7f641e2b41'
                    '98b4a7e634f11b48f3'),
            u'abcéäêëôøà': ('016e02ae147cd23abfb94f3c97cb90e4e68aabd4c36a950'
                            'aed76fd74bdea966d7b57fd57979b8ae55ae8c6a2c25250'
                            '02ae243127f9dc57a672caf0dfe508c74d'),
        },
        'sha512b64': {
            '123456': ("H1LtUVhxyRMWQ5jsJMRwiM35V+ga8oyJmooBldNiDgg5aKbU2Gy4"
                       "+b1/kJsj91ocBE7I5nXG77yw\n5L8OtEVSXQ==\n"),
            'abc': ("pVnbPZa3be4MPNqp6e4fh7vGycUhY2/YQOlv54lZ1Ojr+ZoT6rP9LfT"
                    "sdqrHM8xeLlp/ZB4rQZi0\np+Y08RtI8w==\n"),
            u'abcéäêëôøà': ("AW4CrhR80jq/uU88l8uQ5OaKq9TDapUK7Xb9dL3qlm17V/1"
                            "Xl5uK5VroxqLCUlACriQxJ/ncV6Zy\nyvDf5QjHTQ==\n"),
        }
    }

    def test_hexdigest(self):
        """Test various password hashes."""
        for algo, pws in self.HASHES.items():
            for pw, hashed in pws.items():
                eq_(get_hexdigest(algo, self.SALT, pw), hashed)
