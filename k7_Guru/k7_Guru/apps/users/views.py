import json
import logging
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.contrib.auth import login, logout, get_user_model
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.core.exceptions import FieldError 
from .models import CustomUser
from .utils import verify_cognito_token

logger = logging.getLogger(__name__)

User = get_user_model() 

@require_http_methods(["POST"])
def register(request):
    cognito_sub_for_log = 'N/A' 
    email_for_log = 'N/A'
    try:
        data = json.loads(request.body)
        id_token = data.get('id_token')
        # Get profile data provided during registration
        full_name = data.get('full_name', '').strip()
        address = data.get('address', '').strip()
        # Add other fields if needed: phone_number = data.get('phone_number', '')

    except json.JSONDecodeError:
        logger.warning("Register attempt with invalid JSON")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format in request body.'}, status=400)
    except Exception as e:
        logger.error(f"Error processing request body during registration: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'Error processing request body.'}, status=400)

    if not id_token:
        return JsonResponse({'status': 'error', 'message': 'ID Token is missing.'}, status=400)

    try:
        # Step 1: Verify Cognito ID Token
        user_info = verify_cognito_token(id_token)
        if not user_info:
             logger.warning(f"Invalid Cognito Token received during registration.")
             return JsonResponse({'status': 'error', 'message': 'Invalid ID Token.'}, status=401)

        # Step 2: Extract Cognito User info
        email = user_info.get('email')
        cognito_sub = user_info.get('sub')
        email_verified = user_info.get('email_verified', False)

        # Update logging variables
        cognito_sub_for_log = cognito_sub or 'MISSING_SUB'
        email_for_log = email or 'MISSING_EMAIL'

        # Basic validation
        if not email or not cognito_sub:
             logger.error(f"Cognito token verification successful but missing required claims (email/sub). Token claims: {user_info}")
             return JsonResponse({'status': 'error', 'message': 'Token verification succeeded but missing required user information.'}, status=400)

        # Step 3: Prepare defaults using ONLY valid fields from CustomUser model
        defaults = {
            'email': email,                
            'email_verified': email_verified, 
            'full_name': full_name,
            'address': address,    
            # Add any OTHER valid fields from CustomUser model here if needed
            # e.g., 'phone_number': phone_number,
        }

        # Step 4: Get or Create the Django user using cognito_sub
        user, created = CustomUser.objects.get_or_create(
            cognito_sub=cognito_sub,
            defaults=defaults  
        )

        # Step 5: If user already existed, update profile data if provided
        update_needed = False
        fields_to_update = [] 
        if not created:
            logger.info(f"Existing user found for Cognito SUB {cognito_sub}. Attempting login/update.")

            # Update VALID fields only if new data was provided AND different
            if full_name and user.full_name != full_name:
                user.full_name = full_name
                fields_to_update.append('full_name') # VALID
                update_needed = True
                
            # --- REMOVED user.first_name/last_name updates ---
            if address and user.address != address:
                user.address = address
                fields_to_update.append('address')
                update_needed = True

            # Always sync email and verification status from Cognito token
            if user.email != email:
                 user.email = email
                 fields_to_update.append('email') # VALID
                 update_needed = True
                 # --- REMOVED user.username update ---

            if user.email_verified != email_verified:
                 user.email_verified = email_verified
                 fields_to_update.append('email_verified') # VALID
                 update_needed = True

            if update_needed:
                try:
                    # Save only the fields that actually changed
                    user.save(update_fields=fields_to_update)
                    logger.info(f"Updated profile data for user {email} (SUB: {cognito_sub}). Fields: {fields_to_update}")
                except IntegrityError as ie:
                    # Catch potential issues like duplicate email if constraints exist elsewhere
                    logger.error(f"IntegrityError updating user {email}: {ie}", exc_info=True)
                    return JsonResponse({'status': 'error', 'message': 'Failed to update user profile due to data conflict (e.g., email already exists).'}, status=409) # 409 Conflict

        # Step 6: Log the user into the Django session
        login(request, user, backend='apps.users.authentication.CognitoAuthentication')
        logger.info(f"{'Registered and logged in' if created else 'Logged in'} user {email} (SUB: {cognito_sub}).")

        # Step 7: Return success JSON response with VALID fields
        user_data = {
            'id': user.pk,
            'email': user.email,               
            'cognito_sub': user.cognito_sub,    
            'full_name': user.full_name,      
            'address': user.address,         
            'email_verified': user.email_verified, 
        }
        status_code = 201 if created else 200
        message = 'Registration successful!' if created else 'Login successful (existing user updated)!' if update_needed else 'Login successful (existing user)!'

        return JsonResponse({
            'status': 'success',
            'message': message,
            'user': user_data
        }, status=status_code)

    except IntegrityError as ie:
        logger.error(f"IntegrityError during user registration/lookup for sub {cognito_sub_for_log} / email {email_for_log}: {ie}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'Registration failed due to a data conflict (e.g., email or Cognito ID already exists for another account).'}, status=409) # 409 Conflict
    except FieldError as fe:
         logger.error(f"FieldError during get_or_create for sub {cognito_sub_for_log}: {fe}", exc_info=True)
         return JsonResponse({'status': 'error', 'message': 'Internal configuration error related to user fields.'}, status=500)
    except Exception as e:
        logger.error(f"Unexpected error during registration for sub {cognito_sub_for_log}: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': f'An unexpected error occurred during registration.'}, status=500)

@require_http_methods(["POST"])
def login_view(request):
    sub_for_log = 'N/A'
    try:
        data = json.loads(request.body)
        id_token = data.get('id_token')
    except json.JSONDecodeError:
        logger.warning("Login attempt with invalid JSON")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format.'}, status=400)
    except Exception as e:
        logger.error(f"Error processing request body during login: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'Error processing request body.'}, status=400)

    if not id_token:
        return JsonResponse({'status': 'error', 'message': 'ID Token is missing.'}, status=400)

    try:
        user_info = verify_cognito_token(id_token)
        if not user_info:
             logger.warning(f"Invalid Cognito Token received during login.")
             return JsonResponse({'status': 'error', 'message': 'Invalid ID Token.'}, status=401)

        sub = user_info.get('sub')
        email = user_info.get('email')
        sub_for_log = sub or 'MISSING_SUB'

        if not sub:
             logger.error(f"Cognito token verification successful but missing required claim (sub). Token claims: {user_info}")
             return JsonResponse({'status': 'error', 'message': 'Token verification succeeded but missing required user information.'}, status=400)

        user = User.objects.filter(cognito_sub=sub).first()

        if user:
            email_verified = user_info.get('email_verified', user.email_verified)
            current_email_from_token = user_info.get('email', user.email)

            update_fields_on_login = []
            if user.email_verified != email_verified:
                user.email_verified = email_verified
                update_fields_on_login.append('email_verified') 
            if user.email != current_email_from_token:
                user.email = current_email_from_token
                update_fields_on_login.append('email')

            if update_fields_on_login:
                try:
                    user.save(update_fields=update_fields_on_login)
                    logger.info(f"Synced basic info for user {user.email} during login. Fields: {update_fields_on_login}")
                except IntegrityError as ie:
                     logger.error(f"IntegrityError syncing user info on login for {user.email}: {ie}", exc_info=True)

            login(request, user, backend='apps.users.authentication.CognitoAuthentication')
            logger.info(f"Logged in user {user.email} (SUB: {sub}).")

            user_data = {
                'id': user.pk,
                'email': user.email,
                'cognito_sub': user.cognito_sub,
                'full_name': user.full_name,
                'address': user.address,
                'email_verified': user.email_verified,
            }
            return JsonResponse({
                'status': 'success',
                'message': 'Login successful!',
                'user': user_data
            }, status=200)
        else:
            logger.warning(f"Login attempt failed for verified Cognito SUB {sub} (Email: {email}): User not found in local DB.")
            return JsonResponse({
                'status': 'error',
                'message': 'Login failed: User account not found in our system. Please complete registration.'
            }, status=404)

    except Exception as e:
        logger.error(f"Unexpected error during login for sub {sub_for_log}: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': f'An unexpected error occurred during login.'}, status=500)


@require_POST
@login_required
def logout_view(request):
    user_email = request.user.email if request.user.is_authenticated else 'anonymous'
    try:
        logout(request) # Clears the Django session
        logger.info(f"Logged out user {user_email}.")
        return JsonResponse({'status': 'success', 'message': 'Logout successful.'}, status=200)
    except Exception as e:
        logger.error(f"Error during logout for user {user_email}: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'An error occurred during logout.'}, status=500)



@login_required
@require_http_methods(["POST", "PUT", "PATCH"])
def update_profile(request):
    user = request.user

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        logger.warning(f"Profile update attempt with invalid JSON by user {user.email}")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format.'}, status=400)
    except Exception as e:
        logger.error(f"Error processing request body during profile update for user {user.email}: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'Error processing request body.'}, status=400)

    full_name_data = data.get('full_name')
    address_data = data.get('address')     

    fields_to_update = []
    updated = False

    if full_name_data is not None:
        full_name_stripped = full_name_data.strip()
        if user.full_name != full_name_stripped:
            user.full_name = full_name_stripped
            fields_to_update.append('full_name') 
            updated = True

    if address_data is not None:
        address_stripped = address_data.strip()
        if user.address != address_stripped:
            user.address = address_stripped
            fields_to_update.append('address')
            updated = True

    if not updated:
         logger.info(f"Profile update requested by user {user.email}, but no changes detected.")
         user_data = {
            'id': user.pk, 'email': user.email, 'cognito_sub': user.cognito_sub,
            'full_name': user.full_name, 'address': user.address,
            'email_verified': user.email_verified,
         }
         return JsonResponse({
             'status': 'success',
             'message': 'No changes detected in profile data provided.',
             'user': user_data
         }, status=200)

    try:
        user.save(update_fields=fields_to_update)
        logger.info(f"Profile updated successfully for user {user.email}. Fields: {fields_to_update}")
        user_data = {
            'id': user.pk,
            'email': user.email,
            'cognito_sub': user.cognito_sub,
            'full_name': user.full_name,
            'address': user.address,
            'email_verified': user.email_verified,
        }

        return JsonResponse({
            'status': 'success',
            'message': 'Profile updated successfully!',
            'user': user_data
        }, status=200)

    except IntegrityError as ie:
        logger.error(f"IntegrityError updating profile for user {user.email}: {ie}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'Profile update failed due to data conflict.'}, status=409)
    except Exception as e:
        logger.error(f"Unexpected error updating profile for user {user.email}: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': 'Profile update failed due to an unexpected error.'}, status=500)
