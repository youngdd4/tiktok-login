# views.py in accounts app

import os
import requests
import json
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from django.http import HttpResponse
from .models import TikTokProfile

def login_view(request):
    """Display login page with TikTok OAuth button"""
    return render(request, 'accounts/login.html')

def tiktok_login(request):
    """Redirect user to TikTok for authorization"""
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI')
    
    # TikTok OAuth authorization URL
    auth_url = (
        f"https://www.tiktok.com/auth/authorize/"
        f"?client_key={client_key}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=user.info.basic"
        f"&state={request.session.session_key}"
    )
    
    return redirect(auth_url)

def tiktok_callback(request):
    """Handle callback from TikTok OAuth"""
    code = request.GET.get('code')
    
    if not code:
        return HttpResponse("Authentication failed - no code received", status=400)
    
    # Exchange code for access token
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')
    redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI')
    
    token_url = "https://open.tiktokapis.com/v2/oauth/token/"
    token_data = {
        'client_key': client_key,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri
    }
    
    token_response = requests.post(token_url, data=token_data)
    
    if token_response.status_code != 200:
        return HttpResponse("Failed to exchange code for token", status=400)
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    refresh_token = token_json.get('refresh_token')
    expires_in = token_json.get('expires_in')
    
    # Fetch user info using the access token
    user_info_url = "https://open.tiktokapis.com/v2/user/info/"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    data = {
        'fields': ['open_id', 'union_id', 'avatar_url', 'display_name']
    }
    
    user_response = requests.post(user_info_url, headers=headers, json=data)
    
    if user_response.status_code != 200:
        return HttpResponse("Failed to retrieve user info", status=400)
    
    user_data = user_response.json().get('data', {})
    tiktok_id = user_data.get('open_id')
    username = user_data.get('display_name', '')
    profile_picture = user_data.get('avatar_url', '')
    
    # Check if user exists, create if not
    try:
        tiktok_profile = TikTokProfile.objects.get(tiktok_id=tiktok_id)
        user = tiktok_profile.user
        
        # Update profile info
        tiktok_profile.username = username
        tiktok_profile.profile_picture = profile_picture
        tiktok_profile.access_token = access_token
        tiktok_profile.refresh_token = refresh_token
        tiktok_profile.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        tiktok_profile.save()
        
    except TikTokProfile.DoesNotExist:
        # Create new user and profile
        user = User.objects.create_user(
            username=f"tiktok_{tiktok_id}",
            email=""
        )
        
        tiktok_profile = TikTokProfile.objects.create(
            user=user,
            tiktok_id=tiktok_id,
            username=username,
            profile_picture=profile_picture,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=datetime.now() + timedelta(seconds=expires_in)
        )
    
    # Log the user in
    login(request, user)
    
    return redirect('dashboard')

@login_required
def dashboard(request):
    """Display user dashboard with TikTok profile info"""
    try:
        tiktok_profile = request.user.tiktokprofile
        context = {
            'username': tiktok_profile.username,
            'profile_picture': tiktok_profile.profile_picture
        }
    except TikTokProfile.DoesNotExist:
        context = {
            'username': request.user.username,
            'profile_picture': None
        }
    
    return render(request, 'accounts/dashboard.html', context)

@login_required
def logout_view(request):
    """Log out user"""
    logout(request)
    return redirect('login')

def refresh_token(tiktok_profile):
    """Refresh TikTok access token if expired"""
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')
    
    token_url = "https://open.tiktokapis.com/v2/oauth/token/"
    token_data = {
        'client_key': client_key,
        'client_secret': client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': tiktok_profile.refresh_token
    }
    
    token_response = requests.post(token_url, data=token_data)
    
    if token_response.status_code == 200:
        token_json = token_response.json()
        tiktok_profile.access_token = token_json.get('access_token')
        tiktok_profile.refresh_token = token_json.get('refresh_token')
        tiktok_profile.token_expires_at = datetime.now() + timedelta(seconds=token_json.get('expires_in'))
        tiktok_profile.save()
        return True
    
    return False

    def home(request):
    """Simple home page view to test routing"""
    return render(request, 'accounts/home.html')