import uuid as uuid_lib
import logging, requests,json
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.db import transaction, IntegrityError
from rest_framework import viewsets, status, permissions, serializers as drf_serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from botocore.exceptions import ClientError
from django.views.decorators.csrf import csrf_exempt
# No need for duplicate requests import
import threading
from django.http import Http404 # Import Http404 for get_object_or_404 handling

from .models import Entry, EntryType
from .serializers import (
    EntrySerializer, EntryCreateUpdateSerializer,
    MoveSerializer, CopySerializer
)
from .permissions import IsOwner
from .s3_utils import upload_to_s3, copy_s3_object, generate_presigned_download_url, delete_multiple_from_s3
from .utils import check_name_conflict, get_unique_name, is_descendant

logger = logging.getLogger(__name__)

def call_api_background_task(url, payload, headers, task_description="API call"):
    """
    Sends a POST request to a specified API endpoint in a separate thread.
    Generic helper for background API calls.
    """
    entry_uuid_for_log = payload.get('entry_uuid', 'N/A') 
    try:
        logger.info(f"Thread: Starting background {task_description} to {url} for entry/context {entry_uuid_for_log}")
        logger.debug(f"Thread: Sending payload for {task_description}: {payload}")

        response = requests.post(url, headers=headers, json=payload, timeout=45) 
        response.raise_for_status() # Raises HTTPError for 4xx/5xx responses
        logger.info(f"Thread: Background {task_description} successful for {entry_uuid_for_log}. Status: {response.status_code}, Response: {response.text[:200]}")
    except requests.exceptions.Timeout:
        logger.error(f"Thread: Timeout during background {task_description} for {entry_uuid_for_log} at {url}", exc_info=False)
    except requests.exceptions.ConnectionError:
        logger.error(f"Thread: Connection error during background {task_description} for {entry_uuid_for_log} at {url}", exc_info=False)
    except requests.exceptions.RequestException as e:
        error_details = f"Status: {e.response.status_code}, Response: {e.response.text}" if e.response is not None else str(e)
        logger.error(f"Thread: Failed background {task_description} for {entry_uuid_for_log}: {error_details}", exc_info=True)
    except Exception as e:
        logger.error(f"Thread: Unexpected error during background {task_description} for {entry_uuid_for_log}: {e}", exc_info=True)



class EntryViewSet(viewsets.ModelViewSet):
    """
    API endpoint for CRUD, move, and copy operations on Entries (files/folders).
    """
    serializer_class = EntrySerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter entries by the current authenticated user."""
        user = self.request.user
        queryset = Entry.objects.filter(user=user).select_related('parent', 'user')

        parent_uuid_str = self.request.query_params.get('parent_uuid', None)
        if parent_uuid_str is not None:
            if parent_uuid_str.lower() == 'null':
                queryset = queryset.filter(parent__isnull=True)
            else:
                try:
                    parent_uuid = uuid_lib.UUID(parent_uuid_str)
                    queryset = queryset.filter(parent__uuid=parent_uuid)
                except ValueError:
                    logger.warning(f"Invalid parent_uuid format received: {parent_uuid_str}. Returning empty queryset.")
                    return Entry.objects.none()

        return queryset.order_by('entry_type', 'name')

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action in ['create', 'update', 'partial_update']:
            return EntryCreateUpdateSerializer
        elif self.action == 'move':
            return MoveSerializer
        elif self.action == 'copy':
            return CopySerializer
        return EntrySerializer

    def get_serializer_context(self):
        """Add request to the serializer context."""
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    @transaction.atomic
    def perform_create(self, serializer):
        """
        Handles creation of a new Entry.
        If it's a file, uploads to S3 first. Saves the entry using the serializer.
        If file creation is successful, triggers a background call to an external processing API if configured.
        """
        validated_data = serializer.validated_data
        entry_type = validated_data.get('entry_type')
        file_obj = validated_data.get('file')
        name = validated_data.get('name') # Name should be validated/derived by serializer
        user = self.request.user

        entry_uuid = uuid_lib.uuid4()
        s3_key = None

        # Handle S3 Upload ONLY for files
        if entry_type == EntryType.FILE:
            if not file_obj:
                logger.error(f"File object missing for file creation attempt by user {user.id}. Serializer validation should prevent this.")
                raise drf_serializers.ValidationError("Internal error: File object expected but not found after validation.")

            s3_key = f"{entry_uuid}/{entry_uuid}-{name}"
            print(f"Calculated S3 key: {s3_key}")
            logger.info(f"Attempting S3 upload for new entry {entry_uuid} to key {s3_key} by user {user.id}")
            try:
                success = upload_to_s3(file_obj, s3_key)
                if not success:
                    logger.error(f"S3 upload failed for key {s3_key} (user {user.id}). Check s3_utils logs.")
                    raise drf_serializers.ValidationError("Failed to upload file to S3.")
            except ClientError as e:
                logger.error(f"S3 ClientError during upload for {s3_key} (user {user.id}): {e}", exc_info=True)
                raise drf_serializers.ValidationError(f"Failed to upload file to S3: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during S3 upload for {s3_key} (user {user.id}): {e}", exc_info=True)
                raise drf_serializers.ValidationError(f"An unexpected error occurred during file upload: {e}")

        print(f"s3 key before save: {s3_key}") 
        try:
            instance = serializer.save(
                uuid=entry_uuid,
                s3_key=s3_key
            )
            print(f"instance s3_key after save: {instance.s3_key}")
            logger.info(f"Successfully created DB Entry {instance.uuid} ('{instance.name}') for user {user.id} via serializer.save")

            if entry_type == EntryType.FILE and instance.s3_key:
                logger.debug(f"Checking for external API configuration for file entry {instance.uuid}...")
                external_api_url_base = getattr(settings, 'EXTERNAL_API_URL', None)

                if external_api_url_base:
                    processing_url = f"{external_api_url_base.rstrip('/')}/process-file"
                    logger.info(f"EXTERNAL_API_URL base found: {external_api_url_base}. Preparing processing call to {processing_url} for entry {instance.uuid}.")
                    payload = {
                        "user_id": str(user.id),
                        "user_email": user.email,
                        "original_filename": instance.name,
                        "entry_uuid": str(instance.uuid),
                        "s3_key": instance.s3_key,
                        "status": "upload_complete"
                    }
                    
                    headers = {'Content-Type': 'application/json'}
                    api_key = getattr(settings, 'EXTERNAL_API_KEY', None)
                    if api_key:
                        headers['X-Api-Key'] = api_key
                        logger.debug("EXTERNAL_API_KEY found and added to headers for processing.")
                    else:
                        logger.warning("EXTERNAL_API_KEY not set. Sending processing request without API key.")

                    logger.info(f"Scheduling background HTTP POST to {processing_url} for entry {instance.uuid}")
                    thread = threading.Thread(
                        target=call_api_background_task, 
                        args=(processing_url, payload, headers, "file processing"),
                        daemon=True
                    )
                    thread.start()
                    logger.info(f"Background file processing API call thread for entry {instance.uuid} started.")
                else:
                    logger.warning(f"EXTERNAL_API_URL not configured. Skipping processing call for entry {instance.uuid}.")

        except IntegrityError as e:
             logger.warning(f"IntegrityError during Entry create for user {user.id}: {e}", exc_info=True)
             if 'storage_entry_parent_id_name_user_id' in str(e):
                 raise drf_serializers.ValidationError({"name": f"An entry named '{name}' already exists in this folder."})
             elif 'storage_entry_s3_key_key' in str(e):
                 raise drf_serializers.ValidationError({"s3_key": f"An entry with this S3 key already exists (should be unique)." })
             else:
                raise drf_serializers.ValidationError(f"Database integrity error: {e}")
        except Exception as e:
             logger.error(f"Unexpected error saving Entry via serializer for user {user.id}: {e}", exc_info=True)
             raise drf_serializers.ValidationError(f"An unexpected error occurred while saving the entry: {e}")

    @transaction.atomic
    def perform_update(self, serializer):
        """Handles updates, primarily for renaming."""
        instance = self.get_object()
        try:
             updated_instance = serializer.save()
             logger.info(f"Successfully updated Entry {updated_instance.uuid} name to '{updated_instance.name}' for user {self.request.user.id}")
        except IntegrityError as e:
             logger.warning(f"IntegrityError during Entry update {instance.uuid} by user {self.request.user.id}: {e}", exc_info=True)
             raise drf_serializers.ValidationError(f"Database integrity error during update: {e}")
        except Exception as e:
             logger.error(f"Unexpected error updating Entry {instance.uuid} by user {self.request.user.id}: {e}", exc_info=True)
             raise drf_serializers.ValidationError(f"An unexpected error occurred while updating entry: {e}")

    @transaction.atomic
    def perform_destroy(self, instance):
        """
        Handle deletion. Deletes from DB, S3 (via model's delete),
        and then triggers background deletion of embeddings if it's a file.
        """
        entry_uuid_str = str(instance.uuid) 
        entry_name = instance.name
        user_id_str = str(instance.user.id)
        is_file_type = instance.entry_type == EntryType.FILE
        s3_key_original = instance.s3_key 

        logger.info(f"Attempting deletion of Entry {entry_uuid_str} ('{entry_name}') by user {user_id_str}")
        try:
            # Step 1: Perform DB and S3 deletion (assuming instance.delete() handles S3)
            instance.delete()
            logger.info(f"Successfully processed DB/S3 deletion for former Entry {entry_uuid_str} ('{entry_name}') by user {user_id_str}")

            # --- Step 2: Trigger Embedding Deletion for Files (only if DB/S3 delete succeeded) ---
            if is_file_type and s3_key_original: # Check it *was* a file and *had* an s3_key
                logger.info(f"Entry {entry_uuid_str} was a file with s3_key. Attempting to trigger embedding deletion.")
                external_api_url_base = getattr(settings, 'EXTERNAL_API_URL', None)

                if external_api_url_base:
                    deletion_url = f"{external_api_url_base.rstrip('/')}/delete-embeddings-by-entry"
                    logger.info(f"Preparing embedding deletion call to {deletion_url} for entry {entry_uuid_str}.")

                    payload = {
                        "user_id": user_id_str,
                        "entry_uuid": entry_uuid_str
                    }

                    headers = {'Content-Type': 'application/json'}
                    api_key = getattr(settings, 'EXTERNAL_API_KEY', None)
                    if api_key:
                        headers['X-Api-Key'] = api_key
                        logger.debug("EXTERNAL_API_KEY found and added to headers for embedding deletion.")
                    else:
                        logger.warning("EXTERNAL_API_KEY not set. Sending embedding deletion request without API key.")

                    logger.info(f"Scheduling background HTTP POST to {deletion_url} for entry {entry_uuid_str} (embedding deletion)")
                    thread = threading.Thread(
                        target=call_api_background_task,
                        args=(deletion_url, payload, headers, "embedding deletion"),
                        daemon=True 
                    )
                    thread.start()
                    logger.info(f"Background embedding deletion API call thread for entry {entry_uuid_str} started.")
                else:
                    logger.warning(f"EXTERNAL_API_URL not configured. Skipping embedding deletion call for entry {entry_uuid_str}.")
            elif is_file_type:
                # Log if it was a file but had no s3_key (unlikely if created correctly, but good to note)
                logger.info(f"Entry {entry_uuid_str} was a file type but had no s3_key recorded. No embedding deletion triggered.")
            else:
                 logger.info(f"Entry {entry_uuid_str} was not a file type. No embedding deletion triggered.")


        except ClientError as e:
            # Handle S3 errors during the instance.delete() call if it raises them directly
            logger.error(f"S3 ClientError during deletion of Entry {entry_uuid_str} ('{entry_name}') by user {user_id_str}: {e}", exc_info=True)
            # If the instance.delete() failed due to S3, the embedding deletion wouldn't have been triggered yet.
            # Re-raise to signal failure to the client.
            raise drf_serializers.ValidationError(f"S3 error during deletion: {e}")
        except Exception as e:
            # Handle other errors during instance.delete() (e.g., DB constraints if not atomic)
            logger.error(f"Deletion failed for Entry {entry_uuid_str} ('{entry_name}') by user {user_id_str}: {e}", exc_info=True)
            # Re-raise the original exception for DRF to handle appropriately
            raise


    @action(detail=True, methods=['get'], url_path='contents')
    def contents(self, request, uuid=None):
        """List the contents (child entries) of a specific folder entry."""
        folder = self.get_object()
        if folder.entry_type != EntryType.FOLDER:
            return Response({"detail": "This entry is not a folder."}, status=status.HTTP_400_BAD_REQUEST)

        children_queryset = folder.children.select_related('user').order_by('entry_type', 'name')
        page = self.paginate_queryset(children_queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(children_queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='move')
    @transaction.atomic
    def move(self, request, uuid=None):
        """Moves an entry (file or folder) to a new parent folder."""
        entry_to_move = self.get_object()
        user = request.user
        serializer = MoveSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        target_parent_uuid = serializer.validated_data.get('target_parent_uuid')

        target_parent = None
        if target_parent_uuid:
            try:
                target_parent = get_object_or_404(
                    Entry, uuid=target_parent_uuid, user=user, entry_type=EntryType.FOLDER
                )
            except Http404:
                 raise drf_serializers.ValidationError({"target_parent_uuid": "Target folder not found or you do not have permission."})
            except ValueError:
                 raise drf_serializers.ValidationError({"target_parent_uuid": "Invalid UUID format."})

        if entry_to_move.entry_type == EntryType.FOLDER:
            if entry_to_move == target_parent:
                raise drf_serializers.ValidationError({"detail": "Cannot move a folder into itself."})
            if target_parent and is_descendant(entry_to_move, target_parent):
                raise drf_serializers.ValidationError({"detail": "Cannot move a folder into one of its own subfolders."})

        # Use the utility function for checking name conflict, excluding the entry itself if target is the same parent
        exclude_entry = entry_to_move if entry_to_move.parent == target_parent else None
        if check_name_conflict(user, entry_to_move.name, target_parent, exclude_entry=exclude_entry):
            raise drf_serializers.ValidationError({
                "name": f"An entry named '{entry_to_move.name}' already exists in the target folder."
            })

        original_parent_uuid = entry_to_move.parent.uuid if entry_to_move.parent else None
        logger.info(f"Moving Entry {entry_to_move.uuid} ('{entry_to_move.name}') from parent {original_parent_uuid} to {target_parent_uuid} by user {user.id}")
        entry_to_move.parent = target_parent
        try:
            entry_to_move.save(update_fields=['parent', 'modified_at'])
        except IntegrityError as e:
             logger.warning(f"IntegrityError during move of {entry_to_move.uuid} by user {user.id}: {e}", exc_info=True)
             raise drf_serializers.ValidationError(f"Database integrity error during move: {e}")
        except Exception as e:
            logger.error(f"Unexpected error saving moved entry {entry_to_move.uuid} by user {user.id}: {e}", exc_info=True)
            raise drf_serializers.ValidationError(f"An unexpected error occurred while moving the entry: {e}")

        response_serializer = self.get_serializer(entry_to_move)
        return Response(response_serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='copy')
    @transaction.atomic
    def copy(self, request, uuid=None):
        """Copies an entry (recursively for folders) to a new parent folder."""
        entry_to_copy = self.get_object()
        user = request.user
        serializer = CopySerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        target_parent_uuid = serializer.validated_data.get('target_parent_uuid')
        new_name_input = serializer.validated_data.get('new_name')

        target_parent = None
        if target_parent_uuid:
            try:
                target_parent = get_object_or_404(
                    Entry, uuid=target_parent_uuid, user=user, entry_type=EntryType.FOLDER
                )
            except Http404:
                 raise drf_serializers.ValidationError({"target_parent_uuid": "Target folder not found or you do not have permission."})
            except ValueError:
                 raise drf_serializers.ValidationError({"target_parent_uuid": "Invalid UUID format."})

        if entry_to_copy.entry_type == EntryType.FOLDER and entry_to_copy == target_parent:
             raise drf_serializers.ValidationError({"detail": "Cannot copy a folder directly into itself."})

        base_name = new_name_input if new_name_input else entry_to_copy.name
        try:
            final_name = get_unique_name(user, base_name, target_parent)
        except Exception as e:
             logger.warning(f"Could not determine unique name for copy of '{base_name}' by user {user.id}: {e}")
             raise drf_serializers.ValidationError({"detail": f"Could not determine a unique name for the copy: {e}"})

        logger.info(f"Starting recursive copy of Entry {entry_to_copy.uuid} ('{entry_to_copy.name}') to parent {target_parent_uuid} with name '{final_name}' by user {user.id}")
        copied_s3_keys = []
        try:
            new_entry = self._copy_entry_recursive(
                source_entry=entry_to_copy,
                target_parent=target_parent,
                new_name=final_name,
                user=user,
                copied_s3_keys_tracker=copied_s3_keys
            )
            logger.info(f"Successfully completed recursive copy for user {user.id}. New top-level entry UUID: {new_entry.uuid}")

        except ClientError as e:
             logger.error(f"S3 ClientError during copy operation initiated by user {user.id}: {e}", exc_info=True)
             self._attempt_s3_cleanup(copied_s3_keys, f"ClientError during copy by user {user.id}")
             raise drf_serializers.ValidationError(f"S3 Error during copy operation: {e.code} - {e.response.get('Error', {}).get('Message', 'Unknown S3 error')}")
        except IntegrityError as e:
            logger.warning(f"IntegrityError during copy operation by user {user.id}: {e}", exc_info=True)
            self._attempt_s3_cleanup(copied_s3_keys, f"IntegrityError during copy by user {user.id}")
            raise drf_serializers.ValidationError(f"Database integrity error during copy: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during copy operation initiated by user {user.id}: {e}", exc_info=True)
            self._attempt_s3_cleanup(copied_s3_keys, f"Unexpected error during copy by user {user.id}")
            raise drf_serializers.ValidationError(f"An unexpected error occurred during the copy operation: {e}")

        response_serializer = self.get_serializer(new_entry)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    # --- Private Helper Methods ---

    def _attempt_s3_cleanup(self, s3_keys_to_delete, reason=""):
        """Attempts to delete a list of S3 keys, logging success or failure."""
        if s3_keys_to_delete:
            logger.warning(f"Attempting S3 cleanup for {len(s3_keys_to_delete)} partially copied keys due to: {reason}")
            try:
                 delete_multiple_from_s3(s3_keys_to_delete)
                 logger.info(f"S3 cleanup successful for keys: {s3_keys_to_delete}")
            except Exception as cleanup_exc:
                 logger.error(f"S3 cleanup failed for keys {s3_keys_to_delete}: {cleanup_exc}", exc_info=True)
        else:
            logger.debug(f"No S3 keys to clean up for operation ending with: {reason}")

    def _copy_entry_recursive(self, source_entry, target_parent, new_name, user, copied_s3_keys_tracker):
        """Internal recursive helper for copying an entry and its children (if a folder)."""
        new_uuid = uuid_lib.uuid4()
        new_s3_key = None
        logger.debug(f"Recursively copying source {source_entry.uuid} ('{source_entry.name}', type {source_entry.entry_type}) to parent {target_parent.uuid if target_parent else 'root'} as '{new_name}' with new UUID {new_uuid} for user {user.id}")

        if source_entry.entry_type == EntryType.FILE and source_entry.s3_key:
            new_s3_key = f"{new_uuid}/{new_uuid}-{new_name}"
            logger.debug(f"Attempting S3 copy from '{source_entry.s3_key}' to '{new_s3_key}'")
            try:
                success = copy_s3_object(source_entry.s3_key, new_s3_key)
                if not success:
                    logger.error(f"S3 copy_s3_object function returned False for {source_entry.s3_key} -> {new_s3_key}")
                    raise ClientError({'Error': {'Code': 'CopyFailed', 'Message': 'Copy operation failed internally'}}, 'CopyObject')
                copied_s3_keys_tracker.append(new_s3_key)
                logger.debug(f"S3 copy successful: '{source_entry.s3_key}' -> '{new_s3_key}'")
            except ClientError as e:
                 logger.error(f"S3 ClientError during recursive copy {source_entry.s3_key} -> {new_s3_key}: {e}", exc_info=True)
                 raise
            except Exception as e:
                 logger.error(f"Unexpected error during S3 copy {source_entry.s3_key} -> {new_s3_key}: {e}", exc_info=True)
                 raise

        try:
            new_entry = Entry(
                uuid=new_uuid,
                user=user,
                name=new_name,
                entry_type=source_entry.entry_type,
                s3_key=new_s3_key,
                parent=target_parent,
                # size=source_entry.size # Optionally copy size if needed
            )
            new_entry.save()
            logger.debug(f"Created new DB entry {new_uuid} ('{new_name}') in transaction session")
        except IntegrityError as e:
             logger.warning(f"IntegrityError saving new entry '{new_name}' (UUID {new_uuid}) for user {user.id}: {e}", exc_info=True)
             raise
        except Exception as e:
             logger.error(f"Unexpected error saving new entry '{new_name}' (UUID {new_uuid}) for user {user.id}: {e}", exc_info=True)
             raise

        if source_entry.entry_type == EntryType.FOLDER:
             logger.debug(f"Recursively copying children of source folder {source_entry.uuid} ('{source_entry.name}') into new folder {new_entry.uuid} ('{new_entry.name}')")
             children_to_copy = source_entry.children.all().order_by('name')
             for child in children_to_copy:
                 try:
                     child_final_name = get_unique_name(user, child.name, new_entry)
                     self._copy_entry_recursive(
                         source_entry=child,
                         target_parent=new_entry,
                         new_name=child_final_name,
                         user=user,
                         copied_s3_keys_tracker=copied_s3_keys_tracker
                     )
                 except Exception as e:
                     logger.error(f"Failure during recursive copy of child {child.uuid} ('{child.name}') into {new_entry.uuid} ('{new_entry.name}'): {e}", exc_info=True)
                     raise

        return new_entry

    @action(detail=True, methods=['get'], url_path='download')
    def download(self, request, uuid=None):
        """Generates a temporary, presigned URL for downloading a file entry from S3."""
        entry = self.get_object()
        if entry.entry_type != EntryType.FILE:
            return Response({"detail": "Cannot download a folder."}, status=status.HTTP_400_BAD_REQUEST)

        if not entry.s3_key:
            logger.error(f"Attempt to download Entry {entry.uuid} ('{entry.name}') which is a FILE but has no s3_key (user {request.user.id}).")
            return Response({"detail": "File data not found or is missing."}, status=status.HTTP_404_NOT_FOUND)

        expiration_seconds = getattr(settings, 'PRESIGNED_URL_EXPIRATION', 300)
        try:
            download_url = generate_presigned_download_url(entry.s3_key, expiration=expiration_seconds)
            if not download_url:
                logger.error(f"Failed to generate presigned URL for entry {entry.uuid}, s3_key {entry.s3_key} (user {request.user.id}). generate_presigned_download_url returned None.")
                return Response({"detail": "Could not generate download URL."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ClientError as e:
             logger.error(f"S3 ClientError generating presigned URL for {entry.s3_key} (user {request.user.id}): {e}", exc_info=True)
             return Response({"detail": "Could not generate download URL due to an S3 error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
             logger.error(f"Unexpected error generating presigned URL for {entry.s3_key} (user {request.user.id}): {e}", exc_info=True)
             return Response({"detail": "An unexpected error occurred while generating the download URL."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info(f"Generated download URL for Entry {entry.uuid} ('{entry.name}'), key '{entry.s3_key}' for user {request.user.id}")
        return Response({"download_url": download_url}, status=status.HTTP_200_OK)