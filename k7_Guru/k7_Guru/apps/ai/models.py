# apps/ai/models.py
import uuid
from django.db import models
from django.conf import settings # To link to your CustomUser model

class ChatSession(models.Model):
    """Represents a single chat conversation session."""
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='chat_sessions'
    )
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Optional user-defined name for the session (e.g., derived from first query)."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Chat Session"
        verbose_name_plural = "Chat Sessions"
        ordering = ['-created_at']
        
    def __str__(self):
        session_name = self.name if self.name else f"Session {self.uuid}"
        return f"{session_name} by {self.user.email}"