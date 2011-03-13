"""
Creating standalone Django apps is a PITA because you're not in a project, so
you don't have a settings.py file. I can never remember to define
DJANGO_SETTINGS_MODULE, so I run these commands which get the right env
automatically.
"""
import functools
import os

from fabric.api import local, cd, env
from fabric.contrib.project import rsync_project

NAME = os.path.basename(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.dirname(__file__))

os.environ['DJANGO_SETTINGS_MODULE'] = '%s-project.settings' % NAME
os.environ['PYTHONPATH'] = os.pathsep.join([ROOT,
                                            os.path.join(ROOT, 'examples')])

env.hosts = ['localhost']

local = functools.partial(local, capture=False)

def shell():
    local('django-admin.py shell')

def test(pdb=False):
    cmd = 'django-admin.py test'

    if pdb:
        cmd += ' --pdb --pdb-failures -s'

    local(cmd)
