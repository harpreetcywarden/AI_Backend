import uuid
import logging
from django.db import models, transaction
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from .s3_utils import delete_multiple_from_s3

logger = logging.getLogger(__name__)

class EntryType(models.TextChoices):
    FILE = 'file', _('File')
    FOLDER = 'folder', _('Folder')

class Entry(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='entries'
    )
    name = models.CharField(max_length=255, help_text="Original filename or folder name")
    s3_key = models.TextField(
    null=True,
    blank=True,
    unique=True,
    help_text="S3 key (e.g., 'uuid/uuid-filename.ext'). Null for folders."
    )
    entry_type = models.CharField(
        max_length=10,
        choices=EntryType.choices,
        db_index=True
    )
    parent = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='children',
        limit_choices_to={'entry_type': EntryType.FOLDER},
        help_text="Parent folder entry. Null for root level items."
    )
    upload_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Entry"
        verbose_name_plural = "Entries"
        ordering = ['name']
        indexes = [
            models.Index(fields=['parent']),
            models.Index(fields=['user']),
            models.Index(fields=['entry_type']),
            models.Index(fields=['s3_key']),
        ]
        # Unique constraint for items under the same parent for the same user
        unique_together = ('parent', 'name', 'user')

    def __str__(self):
        parent_info = f" (in {self.parent.name})" if self.parent else " (root)"
        return f"{self.entry_type.capitalize()}: {self.name}{parent_info} [{self.user.email}]"

    def get_s3_keys_recursive(self):
        """Recursively collects S3 keys for this entry and all its descendants."""
        keys_to_delete = set()
        if self.entry_type == EntryType.FILE and self.s3_key:
            keys_to_delete.add(self.s3_key)
        elif self.entry_type == EntryType.FOLDER:
            for child in self.children.all():
                keys_to_delete.update(child.get_s3_keys_recursive())
        return list(keys_to_delete)

    def delete(self, *args, **kwargs):
        """Override delete to handle S3 cleanup before database deletion."""
        s3_keys_to_delete = []
        is_successful_db_delete = False

        # This ensures that S3 deletion and DB deletion are attempted atomically
        # from the perspective of the database transaction. S3 is still external.
        try:
            # Need to collect keys BEFORE the db delete cascade removes children
            s3_keys_to_delete = self.get_s3_keys_recursive()
            logger.debug(f"Found keys to delete for {self.uuid}: {s3_keys_to_delete}")

            # Perform DB deletion first within the transaction
            # The CASCADE will happen here when super().delete() is called
            super().delete(*args, **kwargs)
            is_successful_db_delete = True # Mark DB delete as successful

            # If DB deletion was successful, attempt S3 deletion
            if s3_keys_to_delete:
                logger.info(f"Attempting to delete S3 keys for entry {self.uuid}: {s3_keys_to_delete}")
                success = delete_multiple_from_s3(s3_keys_to_delete)
                if not success:
                    # Log the failure. DB changes are already committed or will be.
                    # This leaves S3 objects potentially orphaned. Needs monitoring/cleanup strategy.
                    logger.error(f"S3 deletion failed for keys {s3_keys_to_delete} associated with deleted entry {self.uuid}. S3 objects may be orphaned.")
                    # Raising an exception here would rollback the DB delete, which might
                    # not be desired if we prefer the DB to be consistent even if S3 fails.
                    # Choice: Log error and accept potential S3 orphans.
            else:
                 logger.debug(f"No S3 keys to delete for entry {self.uuid}")


        except Exception as e:
             # Log any exception during DB delete or key collection
            logger.error(f"Error during deletion process for Entry {self.uuid}: {e}", exc_info=True)
            # Re-raise the exception so the transaction rolls back if not already committed
            # and the calling view knows about the failure.
            raise e