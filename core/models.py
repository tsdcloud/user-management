# -- coding: UTF-8 --
# encoding: utf-8
# reload(sys)
# sys.setdefaultencoding('utf-8')

import uuid
from datetime import datetime, timedelta

from django.db import models
from django.db.models import Model
from django.contrib.auth.models import AbstractUser, Permission, Group, Permission
from django.utils.translation import gettext_lazy as _


from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.models import TokenUser

from core.constants import GENDER_CHOICES, NOTIFICATION_METHODS
from core.utils import to_dict


class BaseModel(models.Model):
    """
    Helper base Model that defines two fields: created_on and updated_on.
    Both are DateTimeField. updated_on automatically receives the current
    datetime whenever the model is updated in the database
    """
    created_on = models.DateTimeField(auto_now_add=True, null=True, editable=False, db_index=True)
    updated_on = models.DateTimeField(auto_now=True, null=True, db_index=True)

    class Meta:
        abstract = True

    # def save(self, **kwargs):
    #     for field in self._meta.fields:
    #         if type(field) == JSONField and isinstance(self.__getattribute__(field.name), models.Model):
    #             self.__setattr__(field.name, to_dict(self.__getattribute__(field.name), False))
    #     super(BaseModel, self).save(**kwargs)

    def to_dict(self):
        return to_dict(self)


class BaseUUIDModel(models.Model):
    """
    Base UUID model that represents a unique identifier for a given model.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, db_index=True, editable=False)
    class Meta:
        abstract = True


class Member(BaseUUIDModel, AbstractUser):
    class Meta:
        ordering = ["last_name", "first_name"]


class Profile(BaseUUIDModel, Model):
    member = models.OneToOneField(Member, related_name='profile', on_delete=models.CASCADE)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    verify = models.BooleanField(default=False, help_text=_("Ensure email or phone is verified"))
    phone = models.TextField(help_text=_("Phone"), editable=True)
    dob = models.DateField(blank=True, null=True, db_index=True, help_text=_("Date of birth"), editable=True)
    photo = models.TextField(null=True, blank=True)
    picture = models.FileField(upload_to="Uploads", null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    notification_method = models.CharField(max_length=150, choices=NOTIFICATION_METHODS, blank=True,
                                           null=True, default="email")

    class Meta:
        permissions = [
            ("view_all_profile", "View all the profiles in the database")
        ]
        
    def __str__(self):
        return self.member.username + "(" + str(self.id) + ")"
    




