import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Twitter_clone.settings')

application = get_wsgi_application()

gunicorn  Twitter_clone:tweets -b xx.xxx.xxx.xx:8000