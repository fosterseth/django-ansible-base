import os

from split_settings.tools import include

DEBUG = True

ALLOWED_HOSTS = ["*"]

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {'format': '%(asctime)s %(levelname)-8s %(name)s %(message)s'},
    },
    'handlers': {
        'console': {
            '()': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'ansible_base': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
for logger in LOGGING["loggers"]:  # noqa: F405
    # We want to ensure that all loggers are at DEBUG because we have tests which validate log messages
    LOGGING["loggers"][logger]["level"] = "DEBUG"  # noqa: F405

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'social_django',
    'ansible_base.api_documentation',
    'ansible_base.authentication',
    'ansible_base.rest_filters',
    'ansible_base.jwt_consumer',
    'ansible_base.resource_registry',
    'test_app',
    'django_extensions',
    'debug_toolbar',
]

MIDDLEWARE = [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'crum.CurrentRequestUserMiddleware',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': ['test_app.authentication.logged_basic_auth.LoggedBasicAuthentication'],
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": os.getenv("DB_HOST", "127.0.0.1"),
        "PORT": os.getenv("DB_PORT", 55432),
        "USER": os.getenv("DB_USER", "dab"),
        "PASSWORD": os.getenv("DB_PASSWORD", "dabing"),
        "NAME": os.getenv("DB_NAME", "dab_db"),
    }
}

AUTH_USER_MODEL = 'test_app.User'

ROOT_URLCONF = 'test_app.urls'

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.request',
            ]
        },
    },
]

INTERNAL_IPS = [
    "127.0.0.1",
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

DEMO_DATA_COUNTS = {'organization': 150, 'user': 379, 'team': 43}

ANSIBLE_BASE_TEAM_MODEL = 'test_app.Team'
ANSIBLE_BASE_ORGANIZATION_MODEL = 'test_app.Organization'

STATIC_URL = '/static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SECRET_KEY = "asdf1234"

ANSIBLE_BASE_AUTHENTICATOR_CLASS_PREFIXES = ['ansible_base.authentication.authenticator_plugins']

from ansible_base.lib import dynamic_config  # noqa: E402

settings_file = os.path.join(os.path.dirname(dynamic_config.__file__), 'dynamic_settings.py')
include(settings_file)

ANSIBLE_BASE_RESOURCE_CONFIG_MODULE = "test_app.resource_api"

SYSTEM_USERNAME = '_system'
