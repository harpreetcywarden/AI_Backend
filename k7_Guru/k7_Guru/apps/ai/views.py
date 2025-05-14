# apps/ai/views.py
import logging
from rest_framework import viewsets, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from .models import ChatSession
from .serializers import ChatSessionSerializer, ChatInputSerializer
from .utils import (
    call_vector_search, call_history_retrieve, call_history_store,
    call_llm
)

logger = logging.getLogger(__name__)

# --- ChatSessionViewSet remains the same ---
class ChatSessionViewSet(viewsets.ModelViewSet):
    """
    API endpoints for managing user Chat Sessions (Create, List, Retrieve, Delete).
    """
    serializer_class = ChatSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter sessions to only those owned by the requesting user."""
        return ChatSession.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Ensure the session is saved with the requesting user."""
        # The serializer's HiddenField handles setting the user
        session = serializer.save()
        logger.info(f"Created ChatSession {session.uuid} for user {self.request.user.id}")

    def perform_destroy(self, instance):
        """Log before deleting."""
        logger.info(f"Deleting ChatSession {instance.uuid} for user {self.request.user.id}")
        # TODO: Delete related history from OpenSearch?
        instance.delete()


class ChatView(APIView):
    """
    Main endpoint for handling user chat queries within a session.
    Retrieves context, calls LLM, stores history, returns response.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Handle incoming chat message."""
        # Pass context={'request': request} so serializer can access the user
        serializer = ChatInputSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            logger.warning(f"Invalid chat input received: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # validated_data contains the clean input AND the validated session object
        validated_data = serializer.validated_data
        user = request.user
        user_id_str = str(user.id)
        query = validated_data['query']
        session = validated_data.get('session')

        if not session:
             logger.error(f"Session object not found in validated_data for user {user_id_str} after successful validation. Serializer issue?")
             return Response({"detail": "Internal server error: Session processing failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        session_uuid = session.uuid

        logger.info(f"Processing chat query for user={user_id_str}, session={session_uuid}, query='{query[:50]}...'")

        # --- Step 1: Retrieve Context ---
        vector_context = call_vector_search(user_id=user_id_str, query=query, top_k=3)
        history_context = call_history_retrieve(user_id=user_id_str, session_id=str(session_uuid), limit=10, sort_order='desc')
        vector = []
        history = []
        
        if vector_context:
            vector.append("## Relevant Information Retrieved from Documents:")
            for i, item in enumerate(vector_context):
                content = item.get('content', '*Missing content*').strip()
                vector.append(f"[{i+1}]\n{content}")
                
        if history_context:
            history.append("## Chat History (Oldest first):")
            # Reverse the list to process oldest first for chronological order
            for entry in reversed(history_context):
                human_msg = entry.get('human_message', '').strip()
                ai_msg = entry.get('ai_message', '').strip() # Assumes this is CLEAN
                if human_msg:
                    history.append(f"Human: {human_msg}")
                if ai_msg:
                    # Prevent saving excessively long AI messages from history? (Optional)
                    # max_hist_len = 500
                    # prompt_parts.append(f"AI: {ai_msg[:max_hist_len]}{'...' if len(ai_msg) > max_hist_len else ''}")
                    history.append(f"AI: {ai_msg}")
        
        ai_response,graph = call_llm(query,vector,history)
        
        # --- Step 4: Store History ---
        history_stored = call_history_store(
            user_id=user_id_str,
            session_id=str(session_uuid),
            human_message=query,
            ai_message=ai_response
        )
        if not history_stored:
             logger.error(f"Failed to store chat history for user={user_id_str}, session={session_uuid}")

        # --- Step 5: Return Response ---
        if graph is None:
            response_data = {
                "ai_response": ai_response,
                "session_uuid": session_uuid,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        
        response_data = {
                "ai_response": ai_response,
                "session_uuid": session_uuid,
                "graph":graph,
                
            }
        return Response(response_data, status=status.HTTP_200_OK)