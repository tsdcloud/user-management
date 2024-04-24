from rest_framework.permissions import BasePermission

class IsAdminAuth(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated )