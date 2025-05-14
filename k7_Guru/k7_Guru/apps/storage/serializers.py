# k7_Guru/apps/storage/serializers.py
import uuid
import os
import logging
from rest_framework import serializers
# UploadedFile is needed as 'file' is in validated_data or accessed
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction, IntegrityError # Import if needed for complex logic
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from .models import Entry, EntryType
from .utils import check_name_conflict # Import helper

logger = logging.getLogger(__name__)

# --- Output Serializer (Includes user_id and user_email) ---
class EntrySerializer(serializers.ModelSerializer):
    """Serializer for listing/retrieving entries."""
    parent_uuid = serializers.UUIDField(source='parent.uuid', allow_null=True, read_only=True)
    user_id = serializers.IntegerField(source='user.id', read_only=True) # User ID (PK)
    user_email = serializers.EmailField(source='user.email', read_only=True) # User email

    class Meta:
        model = Entry
        fields = [
            'uuid',
            'user_id',
            'user_email',
            'name',
            's3_key',
            'entry_type',
            'parent_uuid',
            'upload_time',
        ]
        read_only_fields = fields


# --- Input/Update Serializer (Corrected Indentation and Logic) ---
class EntryCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating entries AND updating the name.
    Handles setting user, parent (via UUID), and validates file/folder specifics.
    Allows internal setting of uuid and s3_key via save() kwargs from the view.
    Includes custom create method to handle non-model fields like 'file'.
    """
    # Automatically set user from the request context
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    # Helper field to accept parent UUID during creation
    parent_uuid = serializers.UUIDField(
        write_only=True, required=False, allow_null=True, format='hex_verbose',
        help_text="UUID of parent folder, null for root."
    )
    # Helper field to accept file upload during creation
    # Must be write_only=True because 'file' is not a field on the Entry model itself
    file = serializers.FileField(write_only=True, required=False, allow_null=True)

    class Meta:
        model = Entry
        # List all model fields potentially involved + helper fields
        fields = [
            'uuid',         
            'user',         
            'name',
            'entry_type',
            'parent',       
            's3_key',       
            'upload_time',  
            'parent_uuid',
            'file',
        ]
        # Fields managed automatically or via lookup
        read_only_fields = ['upload_time', 'parent']
        extra_kwargs = {
            'entry_type': {'required': True, 'allow_null': False},
            'name': {'required': False, 'allow_null': True}, 
            'uuid': {'required': False},
            's3_key': {'required': False, 'allow_null': True}, 
        }

    def validate(self, data):
        """Validate input based on action (create/update) and entry type."""
        user = data['user']
        # Check if we are updating an existing instance
        is_update = self.instance is not None
        # Determine the entry type being processed
        entry_type = data.get('entry_type', getattr(self.instance, 'entry_type', None))
        # Get potential file object and name input
        file_obj = data.get('file')
        name_input = data.get('name')
        # Get potential parent UUID input
        parent_uuid = data.get('parent_uuid')

        if is_update:
            # --- Update Validations ---
            # Typically, only 'name' should be updatable via this serializer
            if 'entry_type' in data and data['entry_type'] != self.instance.entry_type:
                raise serializers.ValidationError({"entry_type": "Cannot change entry type after creation."})
            if 'parent_uuid' in data:
                raise serializers.ValidationError({"parent_uuid": "Use the 'move' action to change parent."})
            if file_obj is not None: # Check if file key exists, even if None
                raise serializers.ValidationError({"file": "File content update not supported via PATCH/PUT."})
            if name_input is not None and not name_input.strip(): # Check if name provided but empty
                raise serializers.ValidationError({"name": "Name cannot be empty on update."})
            existing_parent = self.instance.parent
            new_name = name_input if name_input is not None else self.instance.name
            if check_name_conflict(user, new_name, existing_parent, exclude_uuid=self.instance.uuid):
                 folder_desc = ...
                 raise serializers.ValidationError(...)

        else:
            # --- Create Validations ---
            if not entry_type:
                raise serializers.ValidationError({"entry_type": "Entry type is required."})

            # Find the parent entry object if parent_uuid is provided
            parent_entry = None
            if parent_uuid:
                try:
                    parent_entry = Entry.objects.get(uuid=parent_uuid, user=user, entry_type=EntryType.FOLDER)
                except Entry.DoesNotExist:
                    raise serializers.ValidationError({"parent_uuid": "Parent folder not found, not a folder, or not accessible."})
                except ValueError: # Handle invalid UUID format
                    raise serializers.ValidationError({"parent_uuid": "Invalid UUID format."})

            # Store the looked-up parent object (or None) in validated_data
            # The 'parent' field on the model will be set using this later
            data['parent'] = parent_entry

            # Validate based on entry type
            if entry_type == EntryType.FILE:
                if not file_obj:
                    raise serializers.ValidationError({"file": "File upload is required for type 'file'."})
            elif entry_type == EntryType.FOLDER:
                if file_obj:
                    raise serializers.ValidationError({"file": "Cannot upload a file for type 'folder'."})

            # Determine and validate the final name
            final_name = name_input.strip() if name_input else None
            if entry_type == EntryType.FILE:
                if not final_name: # If name wasn't provided, derive from filename
                    if not file_obj or not hasattr(file_obj, 'name') or not file_obj.name:
                        raise serializers.ValidationError({"name": "Cannot determine filename for upload. Provide 'name' or ensure file has a name."})
                    final_name = os.path.basename(file_obj.name)
            elif entry_type == EntryType.FOLDER:
                if not final_name: # Folders must have a name
                    raise serializers.ValidationError({"name": "Name is required for folders."})

            # Store the validated/derived name back into data
            data['name'] = final_name

            # Check for name conflict within the same parent
            if check_name_conflict(user, data['name'], data['parent']):
                folder_desc = "root folder" if not data['parent'] else f"folder '{data['parent'].name}'"
                raise serializers.ValidationError(
                    {"name": f"An entry named '{data['name']}' already exists in the {folder_desc}."}
                )

        # No need to pop helper fields here, 'create' method handles that.
        return data

    def create(self, validated_data):
        """
        Handle creation, removing non-model helper fields before calling model create.
        Ensures uuid and s3_key passed via save() kwargs from the view are included.
        """
        validated_data.pop('file', None)        
        validated_data.pop('parent_uuid', None) 

        logger.debug(f"Calling Entry.objects.create with cleaned validated_data: {validated_data}")
        try:
            # Create the model instance using the remaining keyword arguments
            instance = Entry.objects.create(**validated_data)
            return instance
        except TypeError as e:
            logger.error(f"TypeError during Entry.objects.create: {e}. Kwargs used: {validated_data}", exc_info=True)
            raise serializers.ValidationError(f"Internal error creating entry: Mismatched arguments. {e}")
        except Exception as e:
            # Catch other potential database errors
            logger.error(f"Unexpected error during Entry.objects.create: {e}. Kwargs used: {validated_data}", exc_info=True)
            raise serializers.ValidationError(f"Failed to create entry due to an unexpected error: {e}")


# --- Serializers for Move/Copy Actions (Corrected Indentation) ---
class MoveSerializer(serializers.Serializer):
    """Serializer for validating the target parent for a move operation."""
    target_parent_uuid = serializers.UUIDField(
        required=False, allow_null=True, format='hex_verbose',
        help_text="UUID of the target folder. Null to move to root."
    )

class CopySerializer(serializers.Serializer):
    """Serializer for validating the target parent and optional new name for a copy operation."""
    target_parent_uuid = serializers.UUIDField(
        required=False, allow_null=True, format='hex_verbose',
        help_text="UUID of the target folder. Null to copy to root."
    )
    new_name = serializers.CharField(
        required=False, allow_blank=True, max_length=255,
        help_text="Optional new name for the copied item."
    )