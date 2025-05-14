# apps/users/models.py
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _
import logging # Import logging

logger = logging.getLogger(__name__)

class CustomUserManager(BaseUserManager):
    """
    Custom manager for CustomUser. Needed primarily for createsuperuser
    when username field is removed.
    """
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        Handles normalization and basic validation.
        Password setting is handled based on whether it's provided.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password) 
        else:
            user.set_unusable_password() 

        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """
        Creates a regular user.
        Use set_unusable_password if password is not provided (typical for JIT).
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        if password is None:
             return self._create_user(email, None, **extra_fields)
        else:
             return self._create_user(email, password, **extra_fields)


    def create_superuser(self, email, password, **extra_fields):
        """
        Creates a superuser. Requires a password for admin/shell access.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('cognito_sub', None)
        extra_fields.setdefault('email_verified', True) 

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        if not password:
            raise ValueError(_('Superuser must have a password.'))

        return self._create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom User Model using Email as username field, linked to AWS Cognito.
    Removes default username, first_name, last_name fields.
    Adds local profile fields and Cognito link.
    """
    username = None
    first_name = None 
    last_name = None  

    # Core identification fields
    email = models.EmailField(
        _('email address'),
        unique=True,
        help_text=_("Required. Used for login and communication.")
    )
    cognito_sub = models.CharField(
        _('Cognito Subject ID'),
        max_length=255,
        unique=True, 
        blank=True,  
        null=True,  
        db_index=True,
        help_text=_("Unique identifier from AWS Cognito.")
    )

    # Status fields potentially synced from Cognito
    email_verified = models.BooleanField(
        _('email verified'),
        default=False,
        help_text=_("Designates whether the user's email is verified in Cognito.")
    )

    full_name = models.CharField(
        _('full name'),
        max_length=255,
        blank=True,
        help_text=_("User's full name (potentially synced from Cognito 'name' claim).")
    )
    address = models.TextField(
        _('address'),
        blank=True,
        help_text=_("User's address information.")
    )
    # Add other local fields if needed
    # phone_number = models.CharField(max_length=25, blank=True)

    # --- Django required settings ---
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # Use the custom manager
    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def update_profile(self, **kwargs):
        """ Safely updates allowed local profile fields. """
        allowed_fields = ['full_name', 'address'] # Add any other custom local profile fields here
        updated = False
        fields_to_update = []
        logger.debug(f"Updating profile for {self.email} with data: {kwargs}")
        for field, value in kwargs.items():
            if field in allowed_fields:
                current_value = getattr(self, field, None)
                # Check if value is different (handle None comparison)
                if current_value != value:
                    setattr(self, field, value)
                    updated = True
                    fields_to_update.append(field)
                else:
                     logger.debug(f"Field '{field}' value unchanged ('{value}').")
            else:
                 logger.warning(f"Attempted to update disallowed/unknown field '{field}' on user {self.email}")

        if updated:
            logger.info(f"Saving updated profile fields for {self.email}: {fields_to_update}")
            # Only save if there are fields to update
            if fields_to_update:
                 self.save(update_fields=fields_to_update)
        else:
             logger.info(f"No profile fields changed for {self.email}. Skipping save.")
        return updated