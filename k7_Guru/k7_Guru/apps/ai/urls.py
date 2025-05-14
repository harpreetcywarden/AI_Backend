# apps/ai/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ChatSessionViewSet, ChatView


app_name = "ai_api"

router = DefaultRouter()
router.register(r'sessions', ChatSessionViewSet, basename='chatsession')
# Usage:
# /api/ai/sessions/ -> List (GET), Create (POST)
# /api/ai/sessions/{uuid}/ -> Retrieve (GET), Delete (DELETE)

# Define URL patterns
urlpatterns = [
    # Include the router-generated URLs
    path('', include(router.urls)),
    # Add the specific path for the chat interaction view
    path('chat/', ChatView.as_view(), name='chat_query'),
    # Example: /api/ai/chat/ -> (POST)
]