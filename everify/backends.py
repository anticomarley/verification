from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model

User = get_user_model()

"""
class EmailAuthBackend(object):

    def authenticate(self, email=None, password=None):
        if email is not None:
            username = email.lower()
        try:
            user = User.objects.get(email=username)
            if user.check_password(password):
                return user
            else:
                return None
        except User.DoesNotExist:
            # No user was found, return None - triggers default login failed
            return None

    # Required for your backend to work properly - unchanged in most scenarios
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
"""



        """
        try:
            user = User.objects.get(pk=user_id)
            if user.is_active:
                return user
            return None
        except User.DoesNotExist:
            return None
        """