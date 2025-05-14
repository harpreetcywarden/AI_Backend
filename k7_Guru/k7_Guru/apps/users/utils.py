# apps/users/utils.py
import boto3, jwt
from jwt import PyJWKClient
from django.conf import settings
from .models import CustomUser
from django.core.exceptions import PermissionDenied

# Initialize the Cognito client
cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)
def verify_cognito_token(id_token):
    region = settings.COGNITO_REGION
    userpool_id = settings.COGNITO_USERPOOL_ID

    jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{userpool_id}/.well-known/jwks.json"
    jwk_client = PyJWKClient(jwks_url)

    signing_key = jwk_client.get_signing_key_from_jwt(id_token)

    data = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.COGNITO_APP_CLIENT_ID,
    )
    return data

def sync_user_data_from_cognito(user, access_token):
    """
    Sync user attributes from Cognito to Django user model.

    Args:
    - user (CustomUser): The user object in Django
    - access_token (str): The Cognito access token for the user

    Updates:
    - Updates user profile data based on Cognito information.
    """
    try:
        # Call Cognito API to get user info
        response = cognito_client.get_user(AccessToken=access_token)
        
        for attribute in response['UserAttributes']:
            if attribute['email'] == 'email':
                user.full_name = attribute['Value']
            
        user.save()  # Save the updated user data

    except Exception as e:
        raise PermissionDenied(f"Failed to sync user data from Cognito: {str(e)}")

