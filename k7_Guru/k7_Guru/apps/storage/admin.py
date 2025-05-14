from django.contrib import admin
from .models import Entry

@admin.register(Entry)
class EntryAdmin(admin.ModelAdmin):
    list_display = ('name', 'entry_type', 'user_email', 'parent_name', 'uuid', 'upload_time')
    list_filter = ('entry_type', 'user__email')
    search_fields = ('name', 'uuid', 'user__email', 'parent__name')
    readonly_fields = ('uuid', 'upload_time', 's3_key')
    list_select_related = ('user', 'parent')
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'

    def parent_name(self, obj):
        return obj.parent.name if obj.parent else '--- ROOT ---'
    parent_name.short_description = 'Parent Folder'
    parent_name.admin_order_field = 'parent__name'


    fieldsets = (
        (None, {'fields': ('uuid', 'name', 'entry_type', 'user')}),
        ('Hierarchy', {'fields': ('parent',)}),
        ('Storage', {'fields': ('s3_key',)}),
        ('Timestamps', {'fields': ('upload_time',)}),
    )