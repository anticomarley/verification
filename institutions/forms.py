import django
from django import forms
from django.contrib.auth import get_user_model, login, logout, authenticate
from django.contrib.auth.hashers import identify_hasher
from django.contrib.auth.forms import ReadOnlyPasswordHashField, ReadOnlyPasswordHashWidget, AuthenticationForm as DjangoAuthenticationForm, PasswordResetForm as OldPasswordResetForm
from django.utils.translation import ugettext_lazy as _, ugettext
from django.utils.html import format_html
from django.forms import formset_factory

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Div, Submit, HTML, Button, Row, Field, Fieldset, ButtonHolder
from crispy_forms.bootstrap import AppendedText, PrependedText, FormActions

from everify.models import UniversityInfo

User = get_user_model()


class UserLoginForm(forms.Form):
    email = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self, *args, **kwargs):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
       
        # user_qs = User.objects.filter(username=username)
        # if user_qs.count() == 1:
        #     user = user_qs.first()
        if email and password:
            user = authenticate(email=email, password=password)
            if not user:
                raise forms.ValidationError("This user does not exist")
            if not user.check_password(password):
                raise forms.ValidationError("Incorrect passsword")
            if not user.is_active:
                raise forms.ValidationError("This user is no longer active.")
        return super(UserLoginForm, self).clean(*args, **kwargs)

    helper = FormHelper()
    helper.form_class = 'form-horizontal'
    helper.label_class = 'col-lg-2'
    helper.field_class = 'col-lg-8'
    helper.layout = Layout(
        Field('email', css_class='form-control'),
        Field('password', css_class='form-control'),
        HTML("<hr>"),
        FormActions(
            Submit('register', 'Regster', css_class="btn btn-template-main"),
        )
    )



class UserRegisterForm(forms.ModelForm):
    email = forms.EmailField(label='Email')
    email2 = forms.EmailField(label='Confirm Email')
    password = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')

    class Meta:
        model = User
        fields = [
            'name',
            'email',
            'email2',
            'password',
            'password2'
        ]

    def clean_email2(self, *args, **kwargs):
        email = self.cleaned_data.get('email')
        email2 = self.cleaned_data.get('email2')
        if email != email2:
            raise forms.ValidationError("Emails must match")
        email_qs = User.objects.filter(email=email)
        if email_qs.exists():
            raise forms.ValidationError("This email has already been registered")
        return email

    def clean_password2(self, *args, **kwargs):
        password = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password2')
        if password != password2:
            raise forms.ValidationError("Passwords must match")
        return password

    helper = FormHelper()
    helper.form_class = 'form-horizontal'
    helper.label_class = 'col-lg-2'
    helper.field_class = 'col-lg-8'
    helper.layout = Layout(
        Field('name', css_class='form-control'),
        Field('email', css_class='form-control'),
        Field('email2', css_class='form-control'),
        Field('password', css_class='form-control'),
        Field('password2', css_class='form-control'),
        #HTML("<hr>"),
        #FormActions(
        #    Submit('register', 'Regster', css_class="btn btn-template-main"),
        #)
    )

class UserProfileForm(forms.ModelForm):
    name = forms.CharField(label='Full Name')
    institute_name = forms.CharField(label='Name of Institution')
    category = forms.CharField(label='Institution Category')
    url = forms.URLField(label='Website')
    contact = forms.CharField(label='Contact Number')
    address = forms.CharField(label='Address')
    region = forms.CharField(label='Region')
    location = forms.CharField(label='Location')
    country = forms.CharField(label='Country')
    verification_amount = forms.IntegerField(label="Verification Amount")
    photo = forms.ImageField(label="Institutiion Logo")

    class Meta:
        model = UniversityInfo
        fields = [
            'institute_name',
            'category',
            'url',
            'contact',
            'address',
            'region',
            'location',
            'country',
            'verification_amount',
            'photo'
        ]

    """
    def clean_email2(self, *args, **kwargs):
        email = self.cleaned_data.get('email')
        email2 = self.cleaned_data.get('email2')
        if email != email2:
            raise forms.ValidationError("Emails must match")
        email_qs = User.objects.filter(email=email)
        if email_qs.exists():
            raise forms.ValidationError("This email has already been registered")
        return email

    def clean_password2(self, *args, **kwargs):
        password = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password2')
        if password != password2:
            raise forms.ValidationError("Passwords must match")
        return password
    """


    helper = FormHelper()
    helper.form_class = 'form-horizontal'
    helper.label_class = 'col-lg-2'
    helper.field_class = 'col-lg-8'
    helper.layout = Layout(
        Field('institute_name', css_class='form-control'),
        Field('category', css_class='form-control'),
        Field('url', css_class='form-control'),
        Field('contact', css_class='form-control'),
        Field('address', css_class='form-control'),
        Field('region', css_class='form-control'),
        Field('location', css_class='form-control'),
        Field('country', css_class='form-control'),
        Field('verification_amount', css_class='form-control'),
        Field('photo', css_class='form-control'),
        #HTML("<hr>"),
        #FormActions(
        #    Submit('register', 'Regster', css_class="btn btn-template-main"),
        #)
    )

RegisterFormSet = formset_factory(UserRegisterForm)
ProfileFormSet = formset_factory(UserProfileForm)