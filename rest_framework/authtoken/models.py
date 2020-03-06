import binascii
import os
import hmac
import hashlib

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class Token(models.Model):
    """
    The default authorization token model.
    """
    key = models.CharField(_("Key"), max_length=130, primary_key=True)
    # user = models.OneToOneField(
    #     settings.AUTH_USER_MODEL, related_name='auth_token',
    #     on_delete=models.CASCADE, verbose_name=_("User")
    # )

    """
    Cause multi login for one user.
    On delete record with key field for logout...
    WARNING! Make workers garbage services work on frequently for can't log outed sessions.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='auth_token',
        on_delete=models.CASCADE
    )
    created = models.DateTimeField(_("Created"), auto_now_add=True)
    session = models.CharField(max_length=2048, verbose_name="Session", null=True)

    class Meta:
        # Work around for a bug in Django:
        # https://code.djangoproject.com/ticket/19422
        #
        # Also see corresponding ticket:
        # https://github.com/encode/django-rest-framework/issues/705
        abstract = 'rest_framework.authtoken' not in settings.INSTALLED_APPS
        verbose_name = _("Token")
        verbose_name_plural = _("Tokens")

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    def generate_key(self):
        # return binascii.hexlify(os.urandom(20)).decode()
        return hmac.new(str(settings.SECRET_KEY).encode(), os.urandom(20), hashlib.sha3_512).hexdigest()

    def __str__(self):
        return self.key
