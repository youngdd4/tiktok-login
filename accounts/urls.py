# urls.py in accounts app

from django.urls import path
from . import views

app_name = 'accounts'  # Add namespace for URL naming

urlpatterns = [
    path('', views.login_view, name='login'),  # Make login the root URL
    path('login/tiktok/', views.tiktok_login, name='tiktok_login'),
    path('login/tiktok/callback/', views.tiktok_callback, name='tiktok_callback'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
]