# views.py in accounts app

import os
import requests
import json
import sys  # For printing to stderr for debugging
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from django.http import HttpResponse
from .models import TikTokProfile
from urllib.parse import urlparse, urlunparse

def login_view(request):
    """Display login page with TikTok OAuth button"""
    # Debug environment variables - only logs to server, not browser
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI')
    print("Environment check in login_view:", file=sys.stderr)
    print(f"TIKTOK_CLIENT_KEY set: {bool(client_key)}", file=sys.stderr)
    print(f"TIKTOK_REDIRECT_URI set: {bool(redirect_uri)}", file=sys.stderr)
    print(f"TIKTOK_REDIRECT_URI value: {redirect_uri}", file=sys.stderr)
    
    return render(request, 'accounts/login.html')

def tiktok_login(request):
    """Redirect user to TikTok for authorization"""
    print("=== INSIDE TIKTOK_LOGIN VIEW ===", file=sys.stderr)
    
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI')
    
    print(f"Environment variables:", file=sys.stderr)
    print(f"TIKTOK_CLIENT_KEY: {'SET' if client_key else 'NOT SET'}", file=sys.stderr)
    print(f"TIKTOK_REDIRECT_URI: {redirect_uri}", file=sys.stderr)
    
    # Check if required environment variables are set
    if not client_key:
        print("ERROR: TIKTOK_CLIENT_KEY environment variable is not set", file=sys.stderr)
        return HttpResponse('TikTok login failed: Client key not configured on the server.', status=500)
    
    if not redirect_uri:
        print("ERROR: TIKTOK_REDIRECT_URI environment variable is not set", file=sys.stderr)
        return HttpResponse('TikTok login failed: Redirect URI not configured on the server.', status=500)
    
    # Ensure session exists before using session_key as CSRF state token
    if not request.session.session_key:
        request.session.create()
    
    # Generate a secure CSRF state token and store it in the session
    csrf_state = request.session.session_key
    print(f"Using state token: {csrf_state}", file=sys.stderr)
    
    # Clean the redirect URI according to TikTok's requirements:
    # 1. Must be absolute and begin with https
    # 2. Must be static (no parameters)
    # 3. No fragment or hash character
    from urllib.parse import urlparse, urlunparse
    
    parsed_uri = urlparse(redirect_uri)
    clean_redirect_uri = urlunparse((
        parsed_uri.scheme,
        parsed_uri.netloc,
        parsed_uri.path.rstrip('/'),  # Remove trailing slash
        '',  # params
        '',  # query - must be empty per TikTok docs
        ''   # fragment - must be empty per TikTok docs
    ))
    
    print(f"Original redirect_uri: {redirect_uri}", file=sys.stderr)
    print(f"Cleaned redirect_uri: {clean_redirect_uri}", file=sys.stderr)
    
    # TikTok OAuth authorization URL - following exact format from documentation
    # According to TikTok docs:
    # https://www.tiktok.com/v2/auth/authorize/?client_key=<client_key>&response_type=code&scope=<scope>&redirect_uri=<redirect_uri>&state=<state>
    auth_url = 'https://www.tiktok.com/v2/auth/authorize/'
    auth_url += f'?client_key={client_key}'
    auth_url += '&response_type=code'
    auth_url += '&scope=user.info.basic'
    auth_url += f'&redirect_uri={clean_redirect_uri}'
    auth_url += f'&state={csrf_state}'
    
    print(f"Redirecting to TikTok auth URL: {auth_url}", file=sys.stderr)
    return redirect(auth_url)

def tiktok_callback(request):
    """Handle callback from TikTok OAuth"""
    print("=== INSIDE TIKTOK CALLBACK VIEW ===", file=sys.stderr)
    print(f"Request method: {request.method}", file=sys.stderr)
    print(f"Request GET params: {request.GET}", file=sys.stderr)
    
    # Get parameters from the callback
    code = request.GET.get('code')
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')
    state = request.GET.get('state')
    scopes = request.GET.get('scopes')
    
    print(f"Received code: {code}", file=sys.stderr)
    print(f"Received error: {error}", file=sys.stderr)
    print(f"Received error_description: {error_description}", file=sys.stderr)
    print(f"Received state: {state}", file=sys.stderr)
    print(f"Received scopes: {scopes}", file=sys.stderr)
    print(f"Current session key: {request.session.session_key}", file=sys.stderr)
    
    # If error is present, authorization failed
    if error:
        print(f"TikTok returned an error: {error} - {error_description}", file=sys.stderr)
        return HttpResponse(f"TikTok returned an error: {error} - {error_description}", status=400)
    
    # Check if code was returned
    if not code:
        print("ERROR: No code received from TikTok", file=sys.stderr)
        return HttpResponse("Authentication failed: No authorization code received from TikTok.", status=400)
    
    # Validate state to prevent CSRF attacks - critical security check
    if not state:
        print("ERROR: No state parameter received from TikTok", file=sys.stderr)
        return HttpResponse("Authentication failed: Missing state parameter in callback.", status=400)
    
    # Strict state validation - must match exactly
    if state != request.session.session_key:
        print(f"ERROR: State mismatch. Received: {state}, Expected: {request.session.session_key}", file=sys.stderr)
        return HttpResponse("Authentication failed: Invalid state parameter. This could be a CSRF attack attempt.", status=400)
    
    # Get environment variables for token exchange
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')
    redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI')
    
    print(f"Environment variables:", file=sys.stderr)
    print(f"TIKTOK_CLIENT_KEY: {'SET' if client_key else 'NOT SET'}", file=sys.stderr)
    print(f"TIKTOK_CLIENT_SECRET: {'SET' if client_secret else 'NOT SET'}", file=sys.stderr)
    print(f"TIKTOK_REDIRECT_URI: {redirect_uri}", file=sys.stderr)
    
    # Check for required environment variables
    if not client_key or not client_secret or not redirect_uri:
        print("ERROR: Missing required environment variables", file=sys.stderr)
        return HttpResponse("Authentication failed: Server configuration issue.", status=500)
    
    # Process redirect_uri to match exactly what was used in the initial request
    parsed_uri = urlparse(redirect_uri)
    clean_redirect_uri = urlunparse((
        parsed_uri.scheme,
        parsed_uri.netloc,
        parsed_uri.path.rstrip('/'),  # Remove trailing slash
        '',  # params
        '',  # query - must be empty per TikTok docs
        ''   # fragment - must be empty per TikTok docs
    ))
    
    print(f"Original redirect_uri: {redirect_uri}", file=sys.stderr)
    print(f"Cleaned redirect_uri for token exchange: {clean_redirect_uri}", file=sys.stderr)
    
    # Use the correct token endpoint from docs
    token_url = "https://open.tiktokapis.com/v2/oauth/token/"
    token_data = {
        'client_key': client_key,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': clean_redirect_uri  # Must match the authorization request exactly
    }
    
    print("Attempting token exchange with data:", file=sys.stderr)
    print(f"client_key: {client_key[:5]}...{client_key[-5:] if client_key else ''}", file=sys.stderr)
    print(f"client_secret: {'[REDACTED]'}", file=sys.stderr)  # Don't log the secret
    print(f"code: {code[:5]}...{code[-5:] if code and len(code) > 10 else code}", file=sys.stderr)
    print(f"redirect_uri: {redirect_uri}", file=sys.stderr)
    
    try:
        token_response = requests.post(token_url, data=token_data)
        
        print(f"Token exchange response code: {token_response.status_code}", file=sys.stderr)
        print(f"Token exchange response headers: {token_response.headers}", file=sys.stderr)
        print(f"Token exchange response content: {token_response.text}", file=sys.stderr)
        
        if token_response.status_code != 200:
            print(f"ERROR: Failed to exchange code for token. Status: {token_response.status_code}", file=sys.stderr)
            return HttpResponse(f"Failed to exchange code for token. Status: {token_response.status_code}. Response: {token_response.text}", status=400)
        
        # Parse token response
        token_json = token_response.json()
        
        # Extract data from token response
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in', 86400)  # Default to 24 hours if not provided
        
        if not access_token:
            print("ERROR: No access token in response", file=sys.stderr)
            return HttpResponse("Authentication failed: No access token received.", status=400)
        
        # Calculate expiration time
        token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        # Fetch user info using the access token with v2 endpoint
        user_info_url = "https://open.tiktokapis.com/v2/user/info/"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        data = {
            'fields': ['open_id', 'union_id', 'avatar_url', 'display_name']
        }
        
        print("Attempting to fetch user info with access token", file=sys.stderr)
        user_response = requests.post(user_info_url, headers=headers, json=data)
        
        print(f"User info response code: {user_response.status_code}", file=sys.stderr)
        print(f"User info response headers: {user_response.headers}", file=sys.stderr)
        print(f"User info response content: {user_response.text}", file=sys.stderr)
        
        if user_response.status_code != 200:
            print(f"ERROR: Failed to retrieve user info. Status: {user_response.status_code}", file=sys.stderr)
            return HttpResponse(f"Failed to retrieve user info. Status: {user_response.status_code}. Response: {user_response.text}", status=400)
        
        # Extract user data from response
        user_data = user_response.json().get('data', {})
        tiktok_id = user_data.get('open_id')
        username = user_data.get('display_name', '')
        profile_picture = user_data.get('avatar_url', '')
        
        if not tiktok_id:
            print("ERROR: No open_id in TikTok response", file=sys.stderr)
            return HttpResponse("Authentication failed: Could not retrieve TikTok user ID.", status=400)
        
        # Check if user exists, create if not
        try:
            print(f"Looking up TikTok profile for ID: {tiktok_id}", file=sys.stderr)
            tiktok_profile = TikTokProfile.objects.get(tiktok_id=tiktok_id)
            user = tiktok_profile.user
            
            print(f"Found existing user: {user.username}", file=sys.stderr)
            
            # Update profile info
            tiktok_profile.username = username
            tiktok_profile.profile_picture = profile_picture
            tiktok_profile.access_token = access_token
            tiktok_profile.refresh_token = refresh_token
            tiktok_profile.token_expires_at = token_expires_at
            tiktok_profile.save()
            
        except TikTokProfile.DoesNotExist:
            # Create new user and profile
            try:
                print(f"Creating new user for TikTok ID: {tiktok_id}", file=sys.stderr)
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
                    token_expires_at=token_expires_at
                )
                print(f"Created new user: {user.username} with profile", file=sys.stderr)
            except Exception as e:
                print(f"ERROR: Exception during user creation: {str(e)}", file=sys.stderr)
                return HttpResponse(f"Authentication failed: Error creating user profile - {str(e)}", status=500)
        
        # Log the user in
        print(f"Logging in user: {user.username}", file=sys.stderr)
        login(request, user)
        
        print("Login successful, redirecting to dashboard", file=sys.stderr)
        return redirect('accounts:dashboard')
        
    except Exception as e:
        print(f"ERROR: Exception during OAuth process: {str(e)}", file=sys.stderr)
        return HttpResponse(f"Authentication failed: An error occurred during the login process - {str(e)}", status=500)

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
    return redirect('accounts:login')

def refresh_token(tiktok_profile):
    """Refresh TikTok access token if expired"""
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')
    
    # Check if token needs refreshing
    if datetime.now() < tiktok_profile.token_expires_at - timedelta(minutes=5):
        # Token still valid for at least 5 more minutes
        return True
        
    print(f"Refreshing token for user: {tiktok_profile.user.username}", file=sys.stderr)
    
    # Use the v2 token endpoint
    token_url = "https://open.tiktokapis.com/v2/oauth/token/"
    token_data = {
        'client_key': client_key,
        'client_secret': client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': tiktok_profile.refresh_token
    }
    
    try:
        token_response = requests.post(token_url, data=token_data)
        
        print(f"Token refresh response code: {token_response.status_code}", file=sys.stderr)
        print(f"Token refresh response content: {token_response.text}", file=sys.stderr)
        
        if token_response.status_code != 200:
            print(f"Failed to refresh token: {token_response.text}", file=sys.stderr)
            return False
        
        token_json = token_response.json()
        
        # Update the profile with new tokens
        tiktok_profile.access_token = token_json.get('access_token')
        tiktok_profile.refresh_token = token_json.get('refresh_token')  # TikTok provides a new refresh token
        expires_in = token_json.get('expires_in', 86400)  # Default to 24 hours if not provided
        tiktok_profile.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        tiktok_profile.save()
        
        print(f"Successfully refreshed token for user: {tiktok_profile.user.username}", file=sys.stderr)
        return True
        
    except Exception as e:
        print(f"Error refreshing token: {str(e)}", file=sys.stderr)
        return False