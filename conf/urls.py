"""
URL configuration for conf project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include

from rest_framework_simplejwt.views import (TokenObtainPairView, TokenRefreshView, TokenVerifyView)

from core.router import OptionalSlashRouter
from core.views import Logout, MemberViewSet, GroupViewSet, ProfileViewSet, ChangePasswordView

router = OptionalSlashRouter()


admin.autodiscover()

router.register(r'users', MemberViewSet)
router.register(r'groups', GroupViewSet)
router.register(r'profiles', ProfileViewSet)

urlpatterns = [
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('i18n/', include('django.conf.urls.i18n')),
    path('venus/', admin.site.urls),

    path('logout/', Logout.as_view(), name='auth_logout'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('api/password-reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('', include(router.urls)),
    
    # Get users token and Refresh token
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]
