from setuptools import setup

import django_sha256


setup(
    name='django-sha256',
    version=django_sha256.__version__,
    description='Enable SHA-256 password hashes in Django by default.',
    long_description=open('README.md').read(),
    author='Fred Wenzel',
    author_email='fwenzel@mozilla.com',
    url='http://github.com/fwenzel/django-sha256',
    license='BSD',
    packages=['django_sha256'],
    include_package_data=True,
    zip_safe=False,
    install_requires=['Django>=1.1'],
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
