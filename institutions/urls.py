from django.conf.urls import url, include
from django.contrib.auth.decorators import login_required, permission_required
from . import views

app_name = 'institutions'

urlpatterns = [
   url(r'^login/$', views.LoginView.as_view(), name='login'),
   url(r'^logout/$', views.LogoutView.as_view(), name='logout'),
   url(r'^register/$', views.RegisterView.as_view(), name='register'),
   url(r'^dashboard/$', views.DashboardView.as_view(), name='dashboard'),
]