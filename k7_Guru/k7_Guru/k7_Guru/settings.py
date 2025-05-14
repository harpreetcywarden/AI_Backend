import os
import sys
import json
import logging
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from django.core.exceptions import ImproperlyConfigured # Import for clearer errors

# --- Basic Setup ---
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(os.path.join(BASE_DIR, '.env'))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
logger = logging.getLogger(__name__)

# --- AWS Secrets Manager Integration ---
SECRETS = {} # Dictionary to hold fetched secrets
SETTINGS_SECRET_ARN = os.environ.get('SETTINGS_SECRET_ARN')
print(f"Attempting to use Secret ARN: {SETTINGS_SECRET_ARN}") # Keep for debugging startup

if SETTINGS_SECRET_ARN:
    logger.info(f"Attempting to fetch settings from AWS Secrets Manager: {SETTINGS_SECRET_ARN}")
    # Boto3 will automatically use the IAM role if AWS keys are not configured explicitly
    session = boto3.session.Session()
    # Ensure correct region is specified for the Secrets Manager client
    secrets_manager_region = SETTINGS_SECRET_ARN.split(':')[3] # Extract region from ARN generally
    client = session.client(service_name='secretsmanager', region_name=secrets_manager_region)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=SETTINGS_SECRET_ARN)
        if 'SecretString' in get_secret_value_response:
            secret_string = get_secret_value_response['SecretString']
            SECRETS = json.loads(secret_string)
            logger.info("Successfully loaded secrets from Secrets Manager.")
        else:
            logger.warning("SecretString not found in Secrets Manager response.")

    except NoCredentialsError:
        logger.error("AWS credentials not found by Boto3. Ensure IAM role is attached and configured correctly.")
        # Decide handling: raise error or allow fallback using environment variables? Raising is safer.
        # raise ImproperlyConfigured("AWS credentials not found for Secrets Manager access.")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        logger.error(f"Failed to retrieve secrets from Secrets Manager ({error_code}): {e}")
        # Log but continue to allow fallbacks if desired, or raise ImproperlyConfigured
        # raise ImproperlyConfigured(f"Could not retrieve secrets: {e}") from e
    except json.JSONDecodeError as e:
         logger.error(f"Failed to parse JSON from secret string: {e}")
         # raise ImproperlyConfigured(f"Invalid JSON in secret: {e}") from e
    except Exception as e:
         logger.error(f"An unexpected error occurred fetching secrets: {e}")
         # raise ImproperlyConfigured(f"Unexpected error fetching secrets: {e}") from e
else:
    logger.warning("SETTINGS_SECRET_ARN not set. Relying solely on environment variables or defaults.")

# --- Core Settings (Use fetched secrets, fallback to env vars, then defaults/errors) ---

# SECRET_KEY: Required - Fetch from secrets, fallback to env var, raise error if missing
SECRET_KEY = SECRETS.get('DJANGO_SECRET_KEY', os.environ.get('SECRET_KEY'))
if not SECRET_KEY:
    raise ImproperlyConfigured("SECRET_KEY is missing. Set it in Secrets Manager or environment variables.")

# DEBUG: Default to False if not set
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# ALLOWED_HOSTS: Fetch from secrets, fallback to env var, default to empty list (or localhost for dev)
ALLOWED_HOSTS_STRING = SECRETS.get(
    'ALLOWED_HOSTS',
    os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1' if DEBUG else '') # Safer default for dev
)
ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS_STRING.split(',') if host.strip()]
if not ALLOWED_HOSTS and not DEBUG:
     logger.warning("ALLOWED_HOSTS is empty in production!")

ALLOWED_HOSTS = ['*']

# --- Cognito Settings ---
COGNITO_REGION = SECRETS.get('COGNITO_REGION_NAME', os.environ.get('COGNITO_REGION_NAME')) # Renamed variable
COGNITO_REGION_NAME = SECRETS.get('COGNITO_REGION_NAME', os.environ.get('COGNITO_REGION_NAME')) # Renamed variable

COGNITO_USERPOOL_ID = SECRETS.get('COGNITO_USERPOOL_ID', os.environ.get('COGNITO_USERPOOL_ID'))
COGNITO_APP_CLIENT_ID = SECRETS.get('COGNITO_APP_CLIENT_ID', os.environ.get('COGNITO_APP_CLIENT_ID'))
# Client Secret likely not needed if using public client + Bearer tokens, but fetch if present/required
COGNITO_APP_CLIENT_SECRET = SECRETS.get('COGNITO_APP_CLIENT_SECRET', os.environ.get('COGNITO_APP_CLIENT_SECRET', None))
print(COGNITO_APP_CLIENT_ID)
# Add warnings if essential Cognito settings are missing
if not COGNITO_REGION: logger.warning("COGNITO_REGION_NAME not configured.")
if not COGNITO_USERPOOL_ID: logger.warning("COGNITO_USERPOOL_ID not configured.")
if not COGNITO_APP_CLIENT_ID: logger.warning("COGNITO_APP_CLIENT_ID not configured.")
# Warning for secret only if it was expected
# if not COGNITO_APP_CLIENT_SECRET: logger.warning("COGNITO_APP_CLIENT_SECRET not configured.")


EXTERNAL_API_KEY = "a3f7b1e9c2d8a4e0f5b3c1a8d0e7f6b2a1d9e8c7b6a5f4e3d2c1b0a9e8d7c6f5"
EXTERNAL_API_URL = "http://localhost:8000/"

FASTAPI_SERVICE_URL = os.getenv('FASTAPI_SERVICE_URL', 'http://localhost:8000/')
FASTAPI_API_KEY ="a3f7b1e9c2d8a4e0f5b3c1a8d0e7f6b2a1d9e8c7b6a5f4e3d2c1b0a9e8d7c6f5"

# URL of the service handling LLM generation (e.g., the one with /generate)
GENERATION_SERVICE_URL = os.getenv('GENERATION_SERVICE_URL','http://localhost:8001/') # IMPORTANT: Set this env var! e.g., http://other-service:8001
# API Key required by the generation service (might be the same or different)
GENERATION_API_KEY = os.getenv('GENERATION_API_KEY',EXTERNAL_API_KEY ) # IMPORTANT: Set this env var!

if not FASTAPI_API_KEY:
    print("WARNING: FASTAPI_API_KEY environment variable is not set. Calls to FastAPI service will likely fail.")

# --- AWS S3 Settings ---
# ** REMOVE EXPLICIT KEYS - Rely on IAM Role **
# AWS_ACCESS_KEY_ID = None
# AWS_SECRET_ACCESS_KEY = None

AWS_STORAGE_BUCKET_NAME = SECRETS.get('AWS_STORAGE_BUCKET_NAME', os.environ.get('AWS_STORAGE_BUCKET_NAME'))
AWS_S3_REGION_NAME = SECRETS.get('AWS_S3_REGION_NAME', os.environ.get('AWS_S3_REGION_NAME')) # Can often be same as Cognito region

if not AWS_STORAGE_BUCKET_NAME: logger.warning("AWS_STORAGE_BUCKET_NAME not configured.")
if not AWS_S3_REGION_NAME: logger.warning("AWS_S3_REGION_NAME not configured.")
AWS_STORAGE_BUCKET_NAME = "guruaibucket"
AWS_S3_SIGNATURE_VERSION = 's3v4'
AWS_S3_ADDRESSING_STYLE = "virtual"

# --- Application definition ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'apps.users',
    'apps.storage',
    'apps.ai',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware', # Place CORS middleware high up
    'django.middleware.common.CommonMiddleware',
    #'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'k7_Guru.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')], # If you need project-level templates
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


WSGI_APPLICATION = 'k7_Guru.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set.")

DATABASES = {
    'default': {  # Remove dj_database_url.config() wrapper
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'guru-db',
        'USER': 'guruai',
        'PASSWORD': 'guru_k7group',  # Consider getting this from secrets/env vars too!
        'HOST': 'guru-db.cgfo2460yct3.us-east-1.rds.amazonaws.com', # Use the confirmed correct endpoint
        'PORT': 5432,
    }
}


AUTHENTICATION_BACKENDS = [
    'apps.users.backends.CognitoAuthenticationBackend', # The class handling token->user and get_user
    'django.contrib.auth.backends.ModelBackend',      # For admin login / createsuperuser
]

# ... your REST_FRAMEWORK setting (which is already correct) ...
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apps.users.authentication.CognitoAuthentication', # Correct: Handles Bearer token
        'rest_framework.authentication.SessionAuthentication', # Keep if admin/browsable API needs session login
        # Or use 'apps.users.authentication.CsrfExemptSessionAuthentication' if needed for testing
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated', # Correct: Requires successful auth
        # Remove the authenticator class from here:
        # 'apps.users.authentication.CognitoAuthentication'
    ],
    # ... other DRF settings ...
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Custom User Model
AUTH_USER_MODEL = 'users.CustomUser'

# Django REST Framework Settings

OPENSEARCH_HOST = 'vpc-guruvectordb-qcasgprbdyout4otbqqkuklwdi.us-east-1.es.amazonaws.com'
OPENSEARCH_PORT = 443
OPENSEARCH_AUTH = ('Guruai', 'Guru_ai1')

CHUNK_SIZE = 900
CHUNK_OVERLAP = 200

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'
# Add STATIC_ROOT for collectstatic in production
# STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
# Add STATICFILES_DIRS if you have project-level static files
# STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]


# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AWS_STORAGE_BUCKET_NAME = SECRETS.get('AWS_STORAGE_BUCKET_NAME', os.environ.get('AWS_STORAGE_BUCKET_NAME'))
AWS_S3_REGION_NAME = SECRETS.get('AWS_S3_REGION_NAME', os.environ.get('AWS_S3_REGION_NAME'))

if not AWS_STORAGE_BUCKET_NAME:
    logger.warning("AWS_STORAGE_BUCKET_NAME not configured.")
if not AWS_S3_REGION_NAME:
     logger.warning("AWS_S3_REGION_NAME not configured. Boto3 might use default region.")


AWS_S3_SIGNATURE_VERSION = 's3v4'
AWS_S3_ADDRESSING_STYLE = "virtual"

# --- CORS Headers Settings ---
CORS_ALLOWED_ORIGINS_STRING = os.environ.get('CORS_ALLOWED_ORIGINS', '')
CORS_ALLOWED_ORIGINS = [origin.strip() for origin in CORS_ALLOWED_ORIGINS_STRING.split(',') if origin.strip()]
# CORS_ALLOW_ALL_ORIGINS = os.environ.get('CORS_ALLOW_ALL_ORIGINS', 'False').lower() == 'true'
CORS_ALLOW_CREDENTIALS = True
AWS_STORAGE_BUCKET_NAME = "guruaibucket"


# --- Logging ---
LOGGING = {
    # ... (keep as before or enhance) ...
     'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'apps': {
             'handlers': ['console'],
             'level': 'INFO', # Set to DEBUG for app-level debugging
             'propagate': True,
        },
         'boto3': {
            'handlers': ['console'],
            'level': 'WARNING', # Reduce boto3 noise unless debugging AWS calls
            'propagate': True,
        },
        'botocore': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': True,
        },
        # Add logger specific to secrets fetching
        __name__: { # Logger for settings.py itself
             'handlers': ['console'],
             'level': 'INFO',
             'propagate': False,
         }
    },
}
