# urls.py in accounts app

from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('login/tiktok/', views.tiktok_login, name='tiktok_login'),
    path('login/tiktok/callback/', views.tiktok_callback, name='tiktok_callback'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
]

# urls.py in main project

from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('', lambda request: redirect('login'), name='home'),
]