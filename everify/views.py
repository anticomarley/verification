import json
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import resolve, reverse
from django.shortcuts import redirect, render
from django.views import generic

from authtools.forms import UserCreationForm
from authtools.views import LoginView, LogoutView

User = get_user_model()


"""
def login_view(request):
    print(request.user.is_authenticated())
    next = request.GET.get('next')
    title = "Login"
    form = UserLoginForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        password = form.cleaned_data.get('password')
        user = authenticate(username=username, password=password)
        login(request, user)
        if next:
            return redirect(next)
        return redirect("/")
    return render(request, "form.html", {"form":form, "title": title})


def register_view(request):
    print(request.user.is_authenticated())
    next = request.GET.get('next')
    title = "Register"
    form = UserRegisterForm(request.POST or None)
    if form.is_valid():
        user = form.save(commit=False)
        password = form.cleaned_data.get('password')
        user.set_password(password)
        user.save()
        new_user = authenticate(username=user.username, password=password)
        login(request, new_user)
        if next:
            return redirect(next)
        return redirect("/")

    context = {
        "form": form,
        "title": title
    }
    return render(request, "form.html", context)


def logout_view(request):
    logout(request)
    return redirect("/")

"""



class HomeView(generic.TemplateView):
    model = None
    template_name = 'everify/index.html'


"""
class EmailUserLoginView(LoginView):
    def get_queryset(self):
        try:
            queryset = User.objects.get(user_id=self.request.user.id)
        except ObjectDoesNotExist:
            queryset = None
        return queryset
    def get_success_url(self, *args, **kwargs):
        queryset =self.get_queryset()
        if queryset != None:
            success_url = reverse('view_list', args=[queryset.id])
        else:
            success_url = reverse('new_list')
        return success_url


class EmailUserLogoutView(LoginView):
    template_name = 'logout.html'

def register(request):
    form = UserCreationForm()
    if request.method == 'POST':
        form = UserCreationForm(data=request.POST)
        if form.is_valid():
            user = form.save()
            return redirect('login')
        else:
            return render(request, 'register.html', {'form: form'})
    else:
        return render(request, 'register.html', {'form: form'})

@login_required(login_url='/login')
def home_page(request):
    return render(request, 'home.html', {'form': ItemForm()})

@login_required(login_url='/login')
def view_list()
"""



   
"""
from django.views.generic import TemplateView
from rest_framework import generics
from django.http import HttpResponseRedirect, HttpResponse
from django.template import loader, RequestContext
from .models import SiteUser, SiteUserSerializer
from django.shortcuts import render_to_response, redirect, get_object_or_404, render
from django.contrib.auth import login as django_login, authenticate, logout as django_logout

from .forms import AuthenticationForm, EmailUserCreationForm

def login(request):
    #Log in view
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = authenticate(email=request.POST['email'], password=request.POST['password'])
            if user is not None:
                if user.is_active:
                    django_login(request, user)
                    return redirect('/')
    else:
        form = AuthenticationForm()
    return render_to_response('accounts/login.html', {
        'form': form,
    }, context_instance=RequestContext(request))

def register(request):
    #User registration view.
    if request.method == 'POST':
        form = RegistrationForm(data=request.POST)
        if form.is_valid():
            user = form.save()
            return redirect('/')
    else:
        form = RegistrationForm()
    return render_to_response('accounts/register.html', {
        'form': form,
    }, context_instance=RequestContext(request))

def logout(request):
    #Log out view
    django_logout(request)
    return redirect('/')
"""


"""
class SiteUserViewSet(viewsets.ModelViewSet):
    serializers_class = SiteUserSerializer

    def get_queryset(self):
        return User.objects.filter(self.request.user)
"""