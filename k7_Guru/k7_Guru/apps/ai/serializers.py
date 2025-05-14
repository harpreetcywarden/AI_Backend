# apps/ai/serializers.py
import uuid
from rest_framework import serializers
from .models import ChatSession
from django.utils.translation import gettext_lazy as _


# --- Serializer for Managing Sessions ---
class ChatSessionSerializer(serializers.ModelSerializer):
    """Serializer for ChatSession list/retrieve/create."""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = ChatSession
        fields = [
            'uuid',
            'user',         
            'user_email',  
            'name',        
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['uuid', 'user_email', 'created_at', 'updated_at']
        extra_kwargs = {
            'name': {'required': False, 'allow_blank': True, 'allow_null': True},
        }

# --- Serializer for Chat Input Validation ---
class ChatInputSerializer(serializers.Serializer):
    """Serializer for validating input to the main chat endpoint (ChatView)."""
    # Basic validation for query and session_uuid format
    query = serializers.CharField(required=True, allow_blank=False, max_length=4000)
    session_uuid = serializers.UUIDField(required=True, format='hex_verbose')

    # Use the main validate method for cross-field validation and object fetching
    def validate(self, data):
        """
        Check that the session exists, belongs to the current user,
        and add the validated session object to the data dictionary.
        """
        session_uuid = data.get('session_uuid')
        query = data.get('query') # query is already validated for type/presence by field definition

        # Retrieve the request object from the context passed by the view
        request = self.context.get('request')
        if not request or not hasattr(request, 'user') or not request.user.is_authenticated:
             # This check ensures we have an authenticated user, which permissions should also guarantee
             raise serializers.ValidationError("Authentication required.", code='authentication_required')

        user = request.user

        try:
            # Fetch the session using the validated UUID
            session = ChatSession.objects.get(uuid=session_uuid)
        except ChatSession.DoesNotExist:
            # Raise validation error associated specifically with the session_uuid field
            raise serializers.ValidationError(
                {"session_uuid": _("Chat session not found.")},
                code='not_found'
            )

        # Check if the fetched session belongs to the requesting user
        if session.user != user:
            # Raise validation error, again associated with session_uuid
            raise serializers.ValidationError(
                {"session_uuid": _("You do not have permission for this chat session.")},
                code='permission_denied'
            )

        # *** IMPORTANT: Add the validated session object to the data dictionary ***
        # This dictionary becomes `serializer.validated_data` in the view.
        data['session'] = session

        # Return the full validated data dictionary (including the added 'session' object)
        return data

