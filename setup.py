import os
import sys
from setuptools import setup, Command

import django_sha2


class RunTests(Command):
    user_options = []

    def run(self):
        os.chdir(self.testproj_dir)
        sys.path.append(self.testproj_dir)
        os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
        settings_file = os.environ['DJANGO_SETTINGS_MODULE']
        settings_mod = __import__(settings_file, {}, {}, [''])
        from django.core.management import execute_manager
        execute_manager(settings_mod, argv=[__file__, "test"])

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass


class RunTests_django13(RunTests):
    description = "Run the test suit for the django 1.3 tests."
    testproj_dir = os.path.join(os.getcwd(), 'test/django13')


class RunTests_django14(RunTests):
    description = "Run the test suit for the django 1.4 tests."
    testproj_dir = os.path.join(os.getcwd(), 'test/django14')


setup(
    name='django-sha2',
    version=django_sha2.__version__,
    description='Enable strong password hashes (bcrypt+hmac or SHA-2) in Django by default.',
    long_description=open('README.md').read(),
    author='Fred Wenzel',
    author_email='fwenzel@mozilla.com',
    url='http://github.com/fwenzel/django-sha2',
    license='BSD',
    packages=['django_sha2'],
    include_package_data=True,
    zip_safe=False,
    install_requires=['Django>=1.2'],
    cmdclass=dict(test13=RunTests_django13, test14=RunTests_django14),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Environment :: Web Environment :: Mozilla',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
