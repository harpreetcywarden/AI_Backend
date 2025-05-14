# apps/users/authentication.py
from django.contrib.auth import authenticate, get_user_model
from rest_framework.authentication import BaseAuthentication
from django.contrib.auth.backends import BaseBackend as DjangoCoreBackend
from django.db import transaction
import logging
from rest_framework import exceptions
from .utils import *
User = get_user_model()
logger = logging.getLogger(__name__)

class CognitoAuthentication(BaseAuthentication, DjangoCoreBackend):
    """
    Custom authentication class handling DRF Bearer tokens AND session get_user.
    Includes JIT Provisioning.
    """
    keyword = 'Bearer'

    # --- DRF Authentication Method (with JIT) ---
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        logger.debug("Attempting DRF authentication via CognitoAuthentication.")

        if not auth_header:
            logger.debug("No Authorization header found.")
            return None

        try:
            auth_type, token = auth_header.split()
            if auth_type.lower() != 'bearer':
                return None
        except ValueError:
            raise exceptions.AuthenticationFailed('Invalid Authorization header format.')

        if not token:
             raise exceptions.AuthenticationFailed('No token provided.')

        try:
            logger.debug("Verifying Cognito token...")
            claims = verify_cognito_token(token) 

            if not claims:
                logger.warning("Cognito token verification failed.")
                raise exceptions.AuthenticationFailed('Cognito token verification failed.')

            cognito_sub = claims.get('sub')
            if not cognito_sub:
                 logger.warning("Token verified but missing 'sub' claim.")
                 raise exceptions.AuthenticationFailed('Token invalid: Missing required \'sub\' claim.')

            # --- JIT Provisioning Logic ---
            try:
                with transaction.atomic():
                    
                    defaults = {
                        'email': claims.get('email'),
                        'full_name': claims.get('name', ''), 
                        'email_verified': claims.get('email_verified', False),
                        'is_active': True,
                    }
                    logger.debug(f"JIT: Calling get_or_create for sub {cognito_sub} with defaults: {defaults}")

                    user, created = User.objects.get_or_create(
                        cognito_sub=cognito_sub,
                        defaults=defaults
                    )

                    if created:
                        user.set_unusable_password() 
                        logger.info(f"JIT created user {user.email} (sub: {cognito_sub})")
                    else:
                        updated = False
                        if user.email != defaults.get('email'):
                             user.email = defaults.get('email')
                             updated = True
                        if user.email_verified != defaults.get('email_verified', False):
                             user.email_verified = defaults.get('email_verified', False)
                             updated = True
                        if user.full_name != defaults.get('full_name', ''):
                             user.full_name = defaults.get('full_name', '')
                             updated = True
                        # Add other fields as needed

                        if updated:
                             user.save(update_fields=['email', 'email_verified', 'full_name']) # Optimize update
                             logger.info(f"JIT updated user {user.email} (sub: {cognito_sub})")

                    # Check if user account is active now (after potential creation/update)
                    if not user.is_active:
                        logger.warning(f"User {user.email} (sub: {cognito_sub}) is inactive.")
                        raise exceptions.AuthenticationFailed('User account is disabled.')

                    # --- JIT Provisioning End ---

                    logger.info(f"DRF Authentication successful for user {user.email} (sub: {cognito_sub})")
                    return (user, None) # Return the local user object

            except Exception as e:
                # Catch errors during JIT process
                logger.error(f"Error during JIT provisioning for sub {cognito_sub}: {e}", exc_info=True)
                raise exceptions.AuthenticationFailed(f'Error processing user profile: {e}')

        except exceptions.AuthenticationFailed as e:
             logger.warning(f"Authentication failed: {e}")
             raise e # Re-raise DRF auth exceptions
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {e}", exc_info=True)
            raise exceptions.AuthenticationFailed(f'Error during authentication process.')


    # --- Django Core Session Authentication Method ---
    def get_user(self, user_id):
        """
        Standard Django method to retrieve a user by primary key (user_id).
        Used by Django's session authentication middleware.
        """
        try:
            user = User.objects.get(pk=user_id)
            logger.debug(f"Django Core get_user: Found user {user_id}")
            return user
        except User.DoesNotExist:
            logger.debug(f"Django Core get_user: User {user_id} does not exist.")
            return None
        except Exception as e:
            # Log other potential errors (e.g., database connection issue)
            logger.error(f"Error in Django Core get_user for ID {user_id}: {e}", exc_info=True)
            return None

    def authenticate_header(self, request):
        return 'Bearer realm="api"'