# -*- coding: utf-8 -*-
from copy import deepcopy
from datetime import datetime, timedelta, date

from django.db.models import F, Model
from django.db.models.fields.files import ImageFieldFile as DjangoImageFieldFile, FieldFile, ImageFieldFile
from rest_framework.authentication import TokenAuthentication
# from rest_framework_simplejwt.authentication impor


class BearerAuthentication(TokenAuthentication):
    keyword = 'Bearer'


def to_dict(var, generate_file_url_keys=True):
    try:
        dict_var = deepcopy(var).__dict__
    except AttributeError:
        return var
    keys_to_remove = []
    updates = {}
    for key in dict_var.keys():
        if key[0] == '_':
            keys_to_remove.append(key)
            continue
        elif type(dict_var[key]) is datetime:
            dict_var[key] = dict_var[key].strftime('%Y-%m-%d %H:%M:%S')
        elif type(dict_var[key]) is date:
            dict_var[key] = dict_var[key].strftime('%Y-%m-%d')
        elif type(dict_var[key]) is list:
            try:
                dict_var[key] = [item.to_dict() for item in dict_var[key]]
            except AttributeError:
                dict_var[key] = [to_dict(item) for item in dict_var[key]]
        elif isinstance(var.__getattribute__(key), DjangoImageFieldFile)\
                or isinstance(var.__getattribute__(key), ImageFieldFile)\
                or isinstance(var.__getattribute__(key), FieldFile):
            if generate_file_url_keys:
                if var.__getattribute__(key).name:
                    updates[key + '_url'] = var.__getattribute__(key).url
                else:
                    updates[key + '_url'] = ''
                keys_to_remove.append(key)
            elif var.__getattribute__(key).name:
                updates[key] = var.__getattribute__(key).name
            else:
                updates[key] = ''
        elif isinstance(dict_var[key], Model):
            try:
                dict_var[key] = dict_var[key].to_dict()
            except AttributeError:
                dict_var[key] = to_dict(dict_var[key])
        elif isinstance(dict_var[key], object) \
                and not (dict_var[key] is None or isinstance(dict_var[key], int) or isinstance(dict_var[key], float)
                         or isinstance(dict_var[key], bool) or isinstance(dict_var[key], dict)):
            dict_var[key] = str(dict_var[key])
    for key in keys_to_remove:
        del(dict_var[key])
    dict_var.update(updates)
    return dict_var