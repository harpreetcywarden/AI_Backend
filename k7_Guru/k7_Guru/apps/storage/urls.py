from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import EntryViewSet

app_name = 'storage'

router = DefaultRouter()
# Use basename because we customize get_queryset
router.register(r'entries', EntryViewSet, basename='entry')

urlpatterns = [
    path('', include(router.urls)),
    # The router handles standard CRUD URLs and the custom actions:
    # GET/POST       /api/storage/entries/
    # GET/PUT/PATCH/DELETE /api/storage/entries/{uuid}/
    # GET            /api/storage/entries/{uuid}/contents/
    # POST           /api/storage/entries/{uuid}/move/
    # POST           /api/storage/entries/{uuid}/copy/
]