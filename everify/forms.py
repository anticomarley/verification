import django
from django import forms
from django.contrib.auth import get_user_model, login, logout, authenticate
from django.contrib.auth.hashers import identify_hasher
from django.contrib.auth.forms import ReadOnlyPasswordHashField, ReadOnlyPasswordHashWidget, AuthenticationForm as DjangoAuthenticationForm, PasswordResetForm as OldPasswordResetForm
from django.utils.translation import ugettext_lazy as _, ugettext
from django.utils.html import format_html


User = get_user_model()



"""
class AuthenticationForm(forms.Form):
    #Login form
    email = forms.EmailField(widget=forms.widgets.TextInput)
    password = forms.CharField(widget=forms.widgets.PasswordInput)

    class Meta:
        fields = ['email', 'password']
"""