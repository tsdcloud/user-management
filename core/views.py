import logging
from datetime import datetime, timedelta, timezone
from threading import Thread
import json

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import Group, Permission
from django.db import transaction, DatabaseError
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.urls import reverse, NoReverseMatch
from django.conf import settings
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.template.loader import get_template
from django.template.loader import render_to_string
from django.dispatch import receiver

from rest_framework import permissions
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.generics import UpdateAPIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import action
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.models import TokenUser
from rest_framework_simplejwt.utils import aware_utcnow, datetime_from_epoch, datetime_to_epoch, format_lazy

from django_rest_passwordreset.signals import reset_password_token_created

from core.permissions import IsAdminAuth
from core.models import Member, Profile
from core.serializers import MemberSerializer, ProfileSerializer, GroupSerializer, ProfileDetailSerializer, \
    PermissionUpdateSerializer, PermissionSerializer, ChangePasswordSerializer, ProfileCreateSerializer, \
    MemberDetailSerializer
from core.serializers import ChangePasswordSerializer


logger = logging.getLogger('user_management')


class MemberViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = Member.objects.all().order_by("-id")
    serializer_class = MemberSerializer
    detail_serializer_class = ProfileSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.action == 'create':
            self.permission_classes = []
        elif self.action in ['list', 'retrieve']:
            try:
                if self.request.user == self.get_object().member:
                    self.permission_classes = [permissions.IsAuthenticated]
                else:
                    self.permission_classes = [permissions.IsAdminUser]
            except:
                self.permission_classes = [permissions.IsAdminUser]
        else:
            self.permission_classes = [permissions.IsAuthenticated]
        return super().get_permissions()

    def get_queryset(self):
        if self.action in ["list", "retrieve"]:
            return Profile.objects.all()
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == "list":
            return ProfileSerializer
        elif self.action == "retrieve":
            return ProfileDetailSerializer
        elif self.action == ["partial_update", "update"]:
            return MemberSerializer

        return super().get_serializer_class()

    def get_object(self):
        """ defini l'object utilise sur l'url de detail """
        r = Profile.objects.filter(id=self.kwargs['pk'])
        obj = get_object_or_404(r, id=self.kwargs["pk"])
        return obj

    def create(self, request, *args, **kwargs):
        email = request.POST.get("email", '')
        first_name = request.POST.get("first_name", '')
        last_name = request.POST.get("last_name", '')
        with transaction.atomic():
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            instance = serializer.instance
            instance.set_password(
                serializer.validated_data["password"])
            now = datetime.now()
            instance.last_login = now
            instance.email = email
            instance.first_name = first_name
            instance.last_name = last_name
            full_name = u'%s' % (instance.first_name.split(' ')[0])
            if instance.last_name:
                full_name = u'%s %s' % (instance.first_name.split(' ')[0], instance.last_name.split(' ')[0])
                instance.full_name = full_name
            instance.save()
            data = serializer.validated_data
            profile = Profile(member=instance)
            try:
                profile_serializer = ProfileCreateSerializer(profile, data=serializer.initial_data)
                profile_serializer.is_valid(raise_exception=True)
                ProfileViewSet.perform_create(self, profile_serializer)
                data["profile_id"] = instance.profile.id
                headers = self.get_success_headers(serializer.data)
                return Response(data=data, status=status.HTTP_201_CREATED, headers=headers)
            except:
                headers = self.get_success_headers(serializer.data)
                return Response({"error": _("User's profile has not been created"),
                                 "data": data}, status=status.HTTP_500_INTERNAL_SERVER_ERROR, headers=headers)

    def partial_update(self, request, *args, **kwargs, ):
        kwargs['partial'] = True
        partial = kwargs.pop('partial', False)
        try:
            instance = Member.objects.get(id=self.get_object().member.id)
        except:
            raise ValidationError({"authorize": _("You dont have permission for this user.")})
        try:
            # This prevent to update user's password
            request.POST.pop('password')
        except:
            pass
        serializer = MemberDetailSerializer(instance, data=request.POST, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        profile_serializer = ProfileSerializer(self.get_object(), data=request.POST, partial=partial)
        profile_serializer.is_valid(raise_exception=True)
        profile_serializer.save()
        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}
        return Response(profile_serializer.data)

    def destroy(self, request, *args, **kwargs):
        """
         This function delete a user passed in parameter
         """
        user = request.user
        # Thread(target=delete_related_member_models, args=(user,)).start()
        now = datetime.now()
        # Profile.objects.filter(member_id=self.request.user.id).delete()
        deleted_username = '__deleted__%s_%s' % (
            now.strftime("%y-%m-%d_%H:%M:%S"), user.username)
        user.is_active = False
        user.username = deleted_username
        user.save()
        OutstandingToken.objects.filter(user=TokenUser.id).delete()
        return Response({"success": True, "message": _("User successfully deleted")}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['GET'])
    def account(self, request):
        profile = request.user.profile
        return Response(ProfileDetailSerializer(profile).data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['PATCH'])
    def grant_permission(self, request):
        # Obtenir l'ID utilisateur depuis les données de la requête
        id = request.data.get('id')
        # Obtenir le nom de la permission depuis les données de la requête
        permission_name = request.data.get('permission_name')
        # Obtenir le code de permission depuis les données de la requête
        permission_code = request.data.get('permission_code')

        try:
            # Récupérer l'objet utilisateur à partir de l'ID
            profile = Profile.objects.get(id=id)
            user = profile.member
            # Récupérer l'objet permission à partir du copermission_code
            permission = Permission.objects.get(codename=permission_code)

            # Ajouter la permission à l'utilisateur
            user.user_permissions.add(permission)

            # # Set Admin user's token to no expiring date
            # if user.user_permissions == [perm for perm in Permission.objects.all()] or TokenUser.is_superuser:
            #     exp = datetime.now() + timedelta(days=365)
            #     OutstandingToken.objects.filter(user=TokenUser.id).update(expires_at=exp)

            if user.has_perm(permission):
                return Response({"message": "Permission already exist"}, status=404)
            # Code de succès avec un message de réussite
            return Response({'message': f"La permission {permission_name} a été attribuée à l'utilisateur {user.username}."})

        except Member.DoesNotExist:
            # Gérer l'erreur si l'utilisateur n'existe pas
            return Response({'message': 'L\'utilisateur spécifié n\'existe pas.'}, status=404)

        except Permission.DoesNotExist:
            # Gérer l'erreur si la permission n'existe pas
            return Response({'message': 'La permission spécifiée n\'existe pas.'}, status=404)


class ProfileViewSet(viewsets.ModelViewSet):
    """
        API endpoint that allows profiles management.
        """
    queryset = Profile.objects.all().order_by("-id")
    serializer_class = ProfileSerializer
    authentication_classes = [JWTAuthentication]
    http_method_names = ["GET"]


class GroupViewSet(viewsets.ModelViewSet):
    """
        API endpoint that allows groups management.
        """
    queryset = Group.objects.all().order_by("-id")
    serializer_class = GroupSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]


class Logout(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response("User Logged out successfully /205/ ", status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response("BAD REQUEST /400/ ", status=status.HTTP_400_BAD_REQUEST)

# def inspect_logs(request):
#     path = "/home/silatchom/MEGA/PycharmProjects/ESKA"
#     if getattr(settings, "DEBUG", False):
#         path = "/var/log/apache2"
#     f = open(extract_log_info(path), 'r')
#     file_content = f.read()
#     f.close()
#     return HttpResponse(file_content, content_type="text/plain")


class ChangePasswordView(UpdateAPIView):
        """
        This endpoint intend to change user's password.
        """
        serializer_class = ChangePasswordSerializer
        model = Member
        permission_classes = (IsAuthenticated,)

        def get_object(self, queryset=None):
            obj = self.request.user
            return obj

        @action(detail=True, methods=['PATCH'])
        def update(self, request, *args, **kwargs):
            self.object = self.get_object()
            serializer = self.get_serializer(data=request.data)
            print(serializer)

            if serializer.is_valid():
                if serializer.data.get("new_password") != serializer.data.get("confirmed_password"):
                    return Response({"new_password": _("Password mismatched")}, status=status.HTTP_409_CONFLICT)
                # Check old password
                if not self.object.check_password(serializer.data.get("old_password")):
                    return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
                # set_password also hashes the password that the user will get
                self.object.set_password(serializer.data.get("new_password"))
                self.object.save()
                response = {
                    'status': 'success',
                    'code': status.HTTP_200_OK,
                    'message': 'Password updated successfully',
                    'data': []
                }
                # # Set Admin user's token to no expiring date
                # if TokenUser.is_superuser:
                #     exp = datetime.now() + timedelta(days=365)
                #     OutstandingToken.objects.filter(user=TokenUser.id).update(expires_at=exp)

                return Response(response)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    """
        Handles password reset tokens
        When a token is created, an e-mail needs to be sent to the user
        :param sender: View Class that sent the signal
        :param instance: View Instance that sent the signal
        :param reset_password_token: Token Model Object
        :param args:
        :param kwargs:
        :return:
    """
    subject = _("Reset your password")
    project_name = getattr(settings, "PROJECT_NAME", "TSD")
    domain = getattr(settings, "DOMAIN", "bfclimited.com")
    sender = getattr(settings, "EMAIL_HOST_USER", '%s <no-reply@%s>' % (project_name, domain))

    # send an e-mail to the user
    context = {
        'company_name': "TSD",
        'service_url': domain,
        'logo_url': "https://rh_support.dpws.bfc.cam/images/bfc_logo.png",
        'current_user': reset_password_token.user,
        'username': reset_password_token.user.username,
        'email': reset_password_token.user.email,
        'reset_password_url': "{}?token={}".format(
            instance.request.build_absolute_uri(reverse('password_reset:reset-password-confirm')),
            reset_password_token.key),
        'protocol': 'https',
        'domain': domain
    }
    template_name = "core/mails/password_reset_email.html"
    html_template = get_template(template_name)
    # render email text
    html_content = html_template.render(context)
    msg = EmailMessage(subject, html_content, sender, [reset_password_token.user.email], bcc=[
                                                       "siltchomsiaka@gmail.com", "jboumte@bfclimited.com",
                                                       "amani@bfclimited.com"])
    msg.content_subtype = "html"
    if getattr(settings, 'UNIT_TESTING', False):
        msg.send()
    else:
        Thread(target=lambda m: m.send(), args=(msg, )).start()