from setuptools import setup

import django_sha2


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
