from django.utils.translation import gettext_lazy as _, get_language

GENDER_CHOICES = (
    ("M", _("Male")),
    ("F", _("Female")),
    ("O", _("Other")),
)


NOTIFICATION_METHODS = (
    ("whatsapp", "Whatsapp"),
    ("sms", "SMS"),
    ("email", "Email"),
)
