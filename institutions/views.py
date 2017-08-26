import json
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout, authenticate
from django.contrib.auth.decorators import login_required, permission_required
from django.utils.decorators import method_decorator
from django.core.urlresolvers import resolve, reverse, reverse_lazy
from django.shortcuts import redirect, render
from django.views import generic
from django.views.generic import FormView, TemplateView, RedirectView
from django.views.generic.edit import CreateView, UpdateView, DeleteView

from .forms import UserLoginForm, UserRegisterForm, UserProfileForm

User = get_user_model()


class LoginView(FormView):
    template_name = 'institutions/institution_login.html'
    form_class = UserLoginForm
    
    def form_valid(self, form):
        if self.request.method == 'POST':
            form = UserLoginForm(self.request.POST)
            if form.is_valid():
                username = form.cleaned_data.get("email")
                password = form.cleaned_data.get('password')
                user = authenticate(email=username, password=password)
                if user is not None:
                    login(self.request, user)

        return super(LoginView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        #context['form'] = self.get_form()
        context.update({
            'form': self.get_form(),
        })
        return context
    
    def get_success_url(self):
        return reverse('institutions:dashboard')

    def dispatch(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            return redirect(self.get_success_url())
        return super(LoginView, self).dispatch(*args, **kwargs)

class LogoutView(RedirectView):
    template_name = None
    permanent = False
    
    def get_redirect_url(self, *args, **kwargs):
        super(LogoutView, self).get_redirect_url(*args, **kwargs)
        return reverse('everify:home')

    def get(self, *args, **kwargs):
        logout(self.request)
        # If we have a url to redirect to, do it. Otherwise render the logged-out template.
        if self.get_redirect_url(**kwargs):
            return RedirectView.get(self, *args, **kwargs)
        
        return redirect("/")

class RegisterView(FormView, TemplateView):
    template_name = 'everify/institution_register.html'
    form_class = UserRegisterForm
    second_form_class = UserProfileForm
    
    def form_valid(self, request, *args, **kwargs):
        if self.request.method == 'POST':
            register_formset = RegisterFormSet(self.request.POST, self.request.FILES, prefix='register')
            profile_formset = ProfileFormSet(self.request.POST, self.request.FILES, prefix='profile')
            if register_formset.is_valid() and profile_formset.is_valid():
                user = register_formset.save(commit=False)
                profile = profile_formset.save()
                password = register_formset.cleaned_data.get('password')
                user.set_password(password)
                user.save()
                new_user = authenticate(username=user.email, password=password)
                login(self.request, new_user)
            else:
                register_formset = RegisterFormSet(prefix='register')
                profile_formset = ProfileFormSet(prefix='profile')
            
        return super(RegisterView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(RegisterView, self).get_context_data(**kwargs)
        context.update({
            'register_formset': register_formset,
            'profile_formset':  profile_formset,
        })
        return context

    def get_success_url(self):
        return reverse('institutions:dashboard')

    def dispatch(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            return redirect(self.get_success_url())
        return super(RegisterView, self).dispatch(*args, **kwargs)



#@login_required
#@permission_required('polls.can_vote', raise_exception=True)

#@login_required(login_url='/institutions/login/')  #redirect_field_name='my_redirect_field'
@method_decorator(login_required(login_url='/institutions/login/'), name='dispatch')
class DashboardView(generic.TemplateView):
    model = None
    template_name = 'institutions/dashboard_institutions.html'


