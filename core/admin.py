# # -- coding: UTF-8 --
from datetime import timedelta

from django.contrib.admin.sites import AlreadyRegistered
from django.contrib.auth.models import Permission
from django.utils import timezone

from import_export.admin import ImportExportModelAdmin
from import_export import resources

from django.contrib import admin

from core.models import Member, Profile


class PermissionAdmin(ImportExportModelAdmin, admin.ModelAdmin):
    class Meta:
        model = Permission
        fields = '__all__'
        readonly_fields = ('email', 'password',)


class MemberAdmin(ImportExportModelAdmin, admin.ModelAdmin):
    class Meta:
        model = Member
        fields = '__all__'
        search_fields = ('first_name', 'last_name')


class ProfileAdmin(ImportExportModelAdmin, admin.ModelAdmin):
    class Meta:
        model = Profile
        fields = '__all__'
        search_fields = ('first_name', 'last_name')

admin.site.register(Permission, PermissionAdmin)
admin.site.register(Member, MemberAdmin)
admin.site.register(Profile, ProfileAdmin)

# try:
#     admin.site.register(Member, MemberAdmin)
# except AlreadyRegistered:
#     pass
