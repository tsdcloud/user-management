from django.contrib.auth.models import Permission
from django.contrib.auth.models import Group

from rest_framework import serializers

from core.models import Profile, Member


class MemberSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100, write_only=True)
    password = serializers.CharField(max_length=100, write_only=True)
    last_name = serializers.CharField(max_length=100, required=True)
    first_name = serializers.CharField(max_length=100, read_only=True)
    email = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = Member
        fields = ['username', 'password', 'first_name', 'last_name', 'email']


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['name', 'codename']


class PermissionUpdateSerializer(serializers.ModelSerializer):
    # member_id = MemberSerializer(many=False, write_only=True)

    class Meta:
        model = Member
        fields = ["id", "codename"]


class MemberDetailSerializer(serializers.ModelSerializer):
    user_permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Member
        fields = ['username', 'first_name', 'last_name', 'email', 'is_staff',
                  'is_active', 'is_superuser', 'last_login', 'date_joined', 'user_permissions']


class ProfileSerializer(serializers.ModelSerializer):
    member = MemberSerializer(many=False, read_only=True)

    class Meta:
        model = Profile
        fields = ["id", "member", "gender", "verify", "phone", "logo"]


class ProfileCreateSerializer(serializers.ModelSerializer):
    dob = serializers.DateField(required=False)

    class Meta:
        model = Profile
        fields = ["id", "gender", "verify", "phone",  "dob", "logo"]


class ProfileDetailSerializer(serializers.ModelSerializer):
    member = MemberDetailSerializer(many=False, read_only=True)

    class Meta:
        model = Profile
        fields = ["id", "member", "gender", "verify",
                  "phone", "logo", "description", "dob"]


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ["name", "permission"]
        

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirmed_password = serializers.CharField(required=True)