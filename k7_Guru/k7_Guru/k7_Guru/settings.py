import os
import sys
import json
import logging
from pathlib import Path
import boto3
from dotenv import load_dotenv
from botocore.exceptions import ClientError, NoCredentialsError
from django.core.exceptions import ImproperlyConfigured

# --- Basic Setup ---
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(os.path.join(BASE_DIR, '.env')) # Only if you want .env for local dev when SETTINGS_SECRET_ARN is not set
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
logger = logging.getLogger(__name__)

# --- Logging Configuration (Early for Secrets Manager Process) ---
# Basic console logging until full config is loaded
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


# --- AWS Secrets Manager Integration ---
SECRETS = {}
SETTINGS_SECRET_ARN ='arn:aws:secretsmanager:us-east-1:288761728891:secret:GURU_SECRET-WSKkCr'
if not SETTINGS_SECRET_ARN:
    logger.critical("SETTINGS_SECRET_ARN environment variable is not set. Cannot fetch configuration from AWS Secrets Manager.")
    raise ImproperlyConfigured("SETTINGS_SECRET_ARN environment variable is not set.")

logger.info(f"Attempting to fetch settings from AWS Secrets Manager using ARN: {SETTINGS_SECRET_ARN}")
try:
    session = boto3.session.Session()
    # Extract region from ARN
    secrets_manager_region = SETTINGS_SECRET_ARN.split(':')[3]
    client = session.client(service_name='secretsmanager', region_name=secrets_manager_region)
    get_secret_value_response = client.get_secret_value(SecretId=SETTINGS_SECRET_ARN)

    if 'SecretString' in get_secret_value_response:
        secret_string = get_secret_value_response['SecretString']
        SECRETS = json.loads(secret_string)
        logger.info("Successfully loaded secrets from AWS Secrets Manager.")
    else:
        logger.error("SecretString not found in AWS Secrets Manager response.")
        raise ImproperlyConfigured("SecretString not found in AWS Secrets Manager response.")

except NoCredentialsError:
    logger.error("AWS credentials not found by Boto3. Ensure IAM role is attached and configured correctly.")
    raise ImproperlyConfigured("AWS credentials not found for Secrets Manager access.")
except ClientError as e:
    error_code = e.response.get("Error", {}).get("Code")
    logger.error(f"Failed to retrieve secrets from Secrets Manager ({error_code}): {e}")
    raise ImproperlyConfigured(f"Could not retrieve secrets from AWS Secrets Manager: {e}") from e
except json.JSONDecodeError as e:
    logger.error(f"Failed to parse JSON from secret string: {e}")
    raise ImproperlyConfigured(f"Invalid JSON in secret from AWS Secrets Manager: {e}") from e
except Exception as e: # Catch any other unexpected errors
    logger.error(f"An unexpected error occurred fetching secrets: {e}")
    raise ImproperlyConfigured(f"Unexpected error fetching secrets from AWS Secrets Manager: {e}") from e

# --- Helper function to get required secrets ---
def get_secret(key_name, is_bool=False, is_int=False, is_list=False, default_if_not_essential=None):
    """
    Retrieves a secret from the SECRETS dictionary.
    Raises ImproperlyConfigured if essential and not found.
    Handles type conversions.
    """
    if key_name not in SECRETS:
        if default_if_not_essential is not None:
            logger.warning(f"Secret '{key_name}' not found in Secrets Manager, using default: {default_if_not_essential}")
            return default_if_not_essential
        raise ImproperlyConfigured(f"Essential setting '{key_name}' not found in AWS Secrets Manager.")

    value = SECRETS[key_name]

    if is_bool:
        if isinstance(value, bool): return value 
        return value.lower() in ['true', '1', 't', 'y', 'yes']
    if is_int:
        try:
            return int(value)
        except ValueError:
            raise ImproperlyConfigured(f"Setting '{key_name}' (value: '{value}') must be an integer.")
    if is_list:
        if isinstance(value, list): return value # if already list (e.g. from direct JSON array)
        if not value: return [] # Handle empty string for lists
        return [item.strip() for item in value.split(',') if item.strip()]
    return value

# --- Core Settings ---
SECRET_KEY =    get_secret('DJANGO_SECRET_KEY')
DEBUG = os.environ.get('DEBUG')

ALLOWED_HOSTS_STRING = os.environ.get('ALLOWED_HOSTS')
ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS_STRING.split(',') if host.strip()]
if not ALLOWED_HOSTS and not DEBUG:
    logger.warning("ALLOWED_HOSTS is empty in production!")
#ALLOWED_HOSTS = ['*'] # If you intend this, put '*' in your secret or handle it explicitly

# --- Cognito Settings ---
COGNITO_REGION = get_secret('COGNITO_REGION_NAME')
COGNITO_USERPOOL_ID = get_secret('COGNITO_USERPOOL_ID')
COGNITO_APP_CLIENT_ID = get_secret('COGNITO_APP_CLIENT_ID')
COGNITO_APP_CLIENT_SECRET = get_secret('COGNITO_APP_CLIENT_SECRET', default_if_not_essential=None) # Optional

if not COGNITO_REGION: logger.warning("COGNITO_REGION_NAME not configured (expected from Secrets Manager).")
if not COGNITO_USERPOOL_ID: logger.warning("COGNITO_USERPOOL_ID not configured (expected from Secrets Manager).")
if not COGNITO_APP_CLIENT_ID: logger.warning("COGNITO_APP_CLIENT_ID not configured (expected from Secrets Manager).")

# --- External Service Settings ---
SAGEMAKER_ENDPOINT = get_secret('SAGEMAKER_ENDPOINT')
FASTAPI_SERVICE_URL = os.environ.get('FASTAPI_SERVICE_URL')
FASTAPI_API_KEY = get_secret('FASTAPI_API_KEY')
GENERATION_SERVICE_URL = os.environ.get('GENERATION_SERVICE_URL')
GENERATION_API_KEY = os.environ.get('GENERATION_API_KEY')

# --- AWS S3 Settings ---
AWS_STORAGE_BUCKET_NAME = get_secret('AWS_STORAGE_BUCKET_NAME')
AWS_S3_REGION_NAME = get_secret('AWS_S3_REGION_NAME')
AWS_S3_SIGNATURE_VERSION = get_secret('AWS_S3_SIGNATURE_VERSION', default_if_not_essential='s3v4')
AWS_S3_ADDRESSING_STYLE = get_secret('AWS_S3_ADDRESSING_STYLE', default_if_not_essential="virtual")

# --- Application definition ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'rest_framework',
    'corsheaders',
    'apps.users',
    'apps.storage',
    'apps.ai',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware', # Typically not needed for token-based APIs
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'k7_Guru.urls' 

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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

# --- Database Settings ---
DATABASES = {
    'default': {
        'ENGINE': get_secret('DATABASE_ENGINE', default_if_not_essential='django.db.backends.postgresql'),
        'NAME': get_secret('DATABASE_NAME'),
        'USER': get_secret('DATABASE_USER'),
        'PASSWORD': get_secret('DATABASE_PASSWORD'),
        'HOST': get_secret('DATABASE_HOST'),
        'PORT': get_secret('DATABASE_PORT', is_int=True, default_if_not_essential='5432'),
    }
}

# --- Authentication ---
AUTH_USER_MODEL = 'users.CustomUser'
AUTHENTICATION_BACKENDS = [
    'apps.users.backends.CognitoAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apps.users.authentication.CognitoAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# --- Password validation ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- OpenSearch Settings ---
OPENSEARCH_HOST = get_secret('OPENSEARCH_HOST')
OPENSEARCH_PORT = get_secret('OPENSEARCH_PORT', is_int=True, default_if_not_essential=443)
OPENSEARCH_USER = get_secret('OPENSEARCH_USER')
OPENSEARCH_PASSWORD = get_secret('OPENSEARCH_PASSWORD')
OPENSEARCH_AUTH = (OPENSEARCH_USER, OPENSEARCH_PASSWORD) # Construct tuple after fetching

CHUNK_SIZE = os.environ.get('CHUNK_SIZE')
CHUNK_OVERLAP = os.environ.get('CHUNK_OVERLAP')

LANGUAGE_CODE = get_secret('LANGUAGE_CODE', default_if_not_essential='en-us')
TIME_ZONE = get_secret('TIME_ZONE', default_if_not_essential='UTC')
USE_I18N = get_secret('USE_I18N', is_bool=True, default_if_not_essential=True)
USE_TZ = get_secret('USE_TZ', is_bool=True, default_if_not_essential=True)

# --- Default primary key field type ---
DEFAULT_AUTO_FIELD = get_secret('DEFAULT_AUTO_FIELD', default_if_not_essential='django.db.models.BigAutoField')

# --- CORS Headers Settings ---
CORS_ALLOWED_ORIGINS_STRING = os.environ.get('CORS_ALLOWED_ORIGINS')
CORS_ALLOWED_ORIGINS = [origin.strip() for origin in CORS_ALLOWED_ORIGINS_STRING.split(',') if origin.strip()]
# If you want to allow all origins (e.g. for development or public API), you'd set CORS_ALLOW_ALL_ORIGINS=True
# CORS_ALLOW_ALL_ORIGINS = get_secret('CORS_ALLOW_ALL_ORIGINS', is_bool=True, default_if_not_essential=False)
# if CORS_ALLOW_ALL_ORIGINS:
#     logger.warning("CORS_ALLOW_ALL_ORIGINS is True. This allows requests from any origin.")
# elif not CORS_ALLOWED_ORIGINS:
#     logger.warning("CORS_ALLOWED_ORIGINS is not set and CORS_ALLOW_ALL_ORIGINS is False. CORS might block requests.")

CORS_ALLOW_CREDENTIALS = os.environ.get("CORS_ALLOW_CREDENTIALS", "False").lower() == "true"

# --- Logging Configuration (Full) ---
# Ensure this is after DEBUG is set, as it might influence default log levels
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple', # Or 'verbose'
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO', # Base level
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.environ.get('DJANGO_LOG_LEVEL').upper(),
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': os.environ.get('APP_LOG_LEVEL').upper(),
            'propagate': True,
        },
        'boto3': {
            'handlers': ['console'],
            'level': os.environ.get('BOTO3_LOG_LEVEL').upper(),
            'propagate': True,
        },
        'botocore': {
            'handlers': ['console'],
            'level': os.environ.get('BOTOCORE_LOG_LEVEL').upper(),
            'propagate': True,
        },
        __name__: {
            'handlers': ['console'],
            'level': 'INFO', 
            'propagate': False,
        }
    },
}

# Reconfigure logging with the full settings
import logging.config
logging.config.dictConfig(LOGGING)
logger.info("Full logging configuration applied.")

# Sanity check after all settings are loaded
logger.info(f"DEBUG mode is: {DEBUG}")
if not ALLOWED_HOSTS and not DEBUG:
    logger.error("CRITICAL: ALLOWED_HOSTS is empty in a production (non-DEBUG) environment!")
    # Consider raising ImproperlyConfigured here if this is a strict production requirement
    raise ImproperlyConfigured("ALLOWED_HOSTS cannot be empty in production.")
