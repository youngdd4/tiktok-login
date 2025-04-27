# views.py in accounts app

import os
import requests
import json
import sys  # For printing to stderr for debugging
from datetime import datetime, timedelta
import uuid
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from urllib.parse import urlparse, urlunparse
from .models import ScheduledPost, PostAnalytics, Notification

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
    auth_url = 'https://www.tiktok.com/v2/auth/authorize/'
    auth_url += f'?client_key={client_key}'
    auth_url += '&response_type=code'
    auth_url += '&scope=user.info.basic,user.info.profile,user.info.stats,video.list'
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
        open_id = token_json.get('open_id')
        
        if not access_token:
            print("ERROR: No access token in response", file=sys.stderr)
            return HttpResponse("Authentication failed: No access token received.", status=400)
            
        # Store access token in session
        request.session['tiktok_access_token'] = access_token
        request.session['tiktok_open_id'] = open_id
        
        # Try to fetch user info with the access token
        success = False
        username = None
        profile_picture = None
        
        # Try TikTok v2 user info endpoint with different approach
        try:
            # Using the user.info endpoint without /v2/ prefix first
            user_info_url = "https://open.tiktokapis.com/user/info/"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Simplified fields request
            data = {
                'fields': ['open_id', 'avatar_url', 'display_name', 'profile_deep_link']
            }
            
            print("Attempting to fetch user info with alternative endpoint", file=sys.stderr)
            print(f"User info URL: {user_info_url}", file=sys.stderr)
            print(f"User info headers: {headers}", file=sys.stderr)
            print(f"User info data: {data}", file=sys.stderr)
            
            user_response = requests.post(user_info_url, headers=headers, json=data)
            
            print(f"User info response code: {user_response.status_code}", file=sys.stderr)
            print(f"User info response headers: {user_response.headers}", file=sys.stderr)
            print(f"User info response content: {user_response.text}", file=sys.stderr)
            
            if user_response.status_code == 200:
                user_data = user_response.json().get('data', {})
                username = user_data.get('display_name', '')
                profile_picture = user_data.get('avatar_url', '')
                profile_deep_link = user_data.get('profile_deep_link', '')
                
                if username:
                    success = True
                    print(f"Successfully retrieved user info from alternative endpoint", file=sys.stderr)
        
        except Exception as e:
            print(f"Error accessing alternative user info endpoint: {str(e)}", file=sys.stderr)

        # If first attempt failed, try the v2 endpoint again with minimal fields
        if not success:
            try:
                user_info_url = "https://open.tiktokapis.com/v2/user/info/"
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                # Request more comprehensive user data
                fields = "open_id,avatar_url,avatar_large_url,display_name,profile_deep_link,bio_description,is_verified,username,follower_count,following_count,likes_count,video_count"
                
                print("Attempting to fetch user info with v2 endpoint (comprehensive fields)", file=sys.stderr)
                user_info_url += f"?fields={fields}"
                
                user_response = requests.get(user_info_url, headers=headers)
                
                print(f"User info response code: {user_response.status_code}", file=sys.stderr)
                print(f"User info response content: {user_response.text}", file=sys.stderr)
                
                if user_response.status_code == 200:
                    response_data = user_response.json()
                    if 'data' in response_data and 'user' in response_data['data']:
                        user_data = response_data['data']['user']
                        
                        # Extract basic profile info
                        username = user_data.get('display_name', '')
                        profile_picture = user_data.get('avatar_large_url', '') or user_data.get('avatar_url', '')
                        profile_deep_link = user_data.get('profile_deep_link', '')
                        
                        # Extract additional profile info
                        bio = user_data.get('bio_description', '')
                        is_verified = user_data.get('is_verified', False)
                        tiktok_username = user_data.get('username', '')
                        
                        # Extract stats
                        follower_count = user_data.get('follower_count', 0)
                        following_count = user_data.get('following_count', 0)
                        likes_count = user_data.get('likes_count', 0)
                        video_count = user_data.get('video_count', 0)
                        
                        # If we have the display name, consider it a success
                        if username:
                            success = True
                            print(f"Successfully retrieved user info from v2 endpoint", file=sys.stderr)
            
            except Exception as e:
                print(f"Error accessing v2 user info endpoint: {str(e)}", file=sys.stderr)
        
        # If both attempts failed, use fallback with data from token response
        if not success:
            print("API endpoints failed, using token response data", file=sys.stderr)
            
            # Get scope and other info from token response
            scope = token_json.get('scope', '')
            token_type = token_json.get('token_type', '')
            
            # Try to extract a more user-friendly identifier from open_id
            if open_id:
                # Use first part of open_id for username to make it more readable
                # Remove any leading hyphens or special characters
                clean_id = open_id.lstrip('-')
                
                # Create a more user-friendly display name
                username = f"TikTok User {clean_id[:8]}"
                
                # Log the data we're working with
                print(f"Using token data - open_id: {open_id}, scope: {scope}", file=sys.stderr)
            else:
                username = "TikTok User"
            
            # No profile picture available when using fallback
            profile_picture = ""
        
        # Store user info in session instead of database
        request.session['tiktok_username'] = username
        request.session['tiktok_profile_picture'] = profile_picture
        request.session['tiktok_authenticated'] = True
        # Store additional TikTok data that might be useful
        request.session['tiktok_scope'] = token_json.get('scope', '')
        
        # Store profile deep link if available
        if 'profile_deep_link' in locals() and profile_deep_link:
            request.session['tiktok_profile_deep_link'] = profile_deep_link
            
        # Store additional profile data if available
        if 'bio' in locals() and bio:
            request.session['tiktok_bio'] = bio
        
        if 'is_verified' in locals():
            request.session['tiktok_is_verified'] = is_verified
            
        if 'tiktok_username' in locals() and tiktok_username:
            request.session['tiktok_handle'] = tiktok_username
            
        # Store stats if available
        if 'follower_count' in locals():
            request.session['tiktok_follower_count'] = follower_count
            request.session['tiktok_following_count'] = following_count
            request.session['tiktok_likes_count'] = likes_count
            request.session['tiktok_video_count'] = video_count
        
        print(f"Stored in session - Username: {username}", file=sys.stderr)
        print("Login successful, redirecting to dashboard", file=sys.stderr)
        return redirect('accounts:dashboard')
        
    except Exception as e:
        print(f"ERROR: Exception during OAuth process: {str(e)}", file=sys.stderr)
        return HttpResponse(f"Authentication failed: An error occurred during the login process - {str(e)}", status=500)

def dashboard(request):
    """Display user dashboard with TikTok profile info and videos from session"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
    
    # Get profile info from session
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
        'profile_deep_link': request.session.get('tiktok_profile_deep_link', None),
        'bio': request.session.get('tiktok_bio', None),
        'is_verified': request.session.get('tiktok_is_verified', False),
        'tiktok_handle': request.session.get('tiktok_handle', None),
        'follower_count': request.session.get('tiktok_follower_count', 0),
        'following_count': request.session.get('tiktok_following_count', 0),
        'likes_count': request.session.get('tiktok_likes_count', 0),
        'video_count': request.session.get('tiktok_video_count', 0)
    }
    
    # Check if we have an access token to fetch videos
    if 'tiktok_access_token' in request.session:
        access_token = request.session.get('tiktok_access_token')
        
        # Try to fetch TikTok videos
        try:
            # API endpoint for videos
            videos_url = "https://open.tiktokapis.com/v2/video/list/"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Request data - get up to 6 recent videos with specific fields
            data = {
                'max_count': 6,
                'fields': ['id', 'title', 'video_description', 'duration', 'cover_image_url', 'embed_link', 'share_url']
            }
            
            print("Attempting to fetch TikTok videos", file=sys.stderr)
            videos_response = requests.post(videos_url, headers=headers, json=data)
            
            print(f"Videos response code: {videos_response.status_code}", file=sys.stderr)
            print(f"Videos response content: {videos_response.text}", file=sys.stderr)
            
            if videos_response.status_code == 200:
                videos_data = videos_response.json()
                videos = videos_data.get('data', {}).get('videos', [])
                
                # Add videos to context if available
                if videos:
                    context['videos'] = videos
                    print(f"Successfully fetched {len(videos)} TikTok videos", file=sys.stderr)
        
        except Exception as e:
            print(f"Error fetching TikTok videos: {str(e)}", file=sys.stderr)
            # Continue without videos
    
    # Get recent notifications
    if request.session.get('user_id'):
        try:
            user_id = request.session.get('user_id')
            notifications = Notification.objects.filter(user_id=user_id, read=False)[:5]
            context['notifications'] = notifications
        except Exception as e:
            print(f"Error fetching notifications: {str(e)}", file=sys.stderr)
    
    # Get scheduled posts
    if request.session.get('user_id'):
        try:
            user_id = request.session.get('user_id')
            scheduled_posts = ScheduledPost.objects.filter(user_id=user_id, status='scheduled')[:3]
            context['scheduled_posts'] = scheduled_posts
        except Exception as e:
            print(f"Error fetching scheduled posts: {str(e)}", file=sys.stderr)
    
    return render(request, 'accounts/dashboard.html', context)

def logout_view(request):
    """Log out user by clearing session data"""
    # Clear TikTok session data
    if 'tiktok_access_token' in request.session:
        access_token = request.session.get('tiktok_access_token')
        # Optionally revoke token on TikTok side
        revoke_token(access_token)
        
    # Clear all TikTok related session data
    keys_to_remove = [
        'tiktok_access_token', 
        'tiktok_open_id', 
        'tiktok_username', 
        'tiktok_profile_picture',
        'tiktok_authenticated',
        'tiktok_scope',
        'tiktok_profile_deep_link',
        'tiktok_bio',
        'tiktok_is_verified',
        'tiktok_handle',
        'tiktok_follower_count',
        'tiktok_following_count',
        'tiktok_likes_count',
        'tiktok_video_count'
    ]
    
    for key in keys_to_remove:
        if key in request.session:
            del request.session[key]
    
    return redirect('accounts:login')

def revoke_token(access_token):
    """Revoke a TikTok access token"""
    if not access_token:
        return False
        
    client_key = os.environ.get('TIKTOK_CLIENT_KEY')
    client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')
    
    if not client_key or not client_secret:
        print("ERROR: Missing client credentials for token revocation", file=sys.stderr)
        return False
    
    # Use the token revocation endpoint
    revoke_url = "https://open.tiktokapis.com/v2/oauth/revoke/"
    
    revoke_data = {
        'client_key': client_key,
        'client_secret': client_secret,
        'token': access_token
    }
    
    try:
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cache-Control': 'no-cache'
        }
        
        print(f"Attempting to revoke token", file=sys.stderr)
        revoke_response = requests.post(revoke_url, data=revoke_data, headers=headers)
        
        print(f"Token revocation response code: {revoke_response.status_code}", file=sys.stderr)
        print(f"Token revocation response content: {revoke_response.text}", file=sys.stderr)
        
        # A successful revocation returns an empty response with a 200 status
        if revoke_response.status_code == 200:
            print("Successfully revoked TikTok access token", file=sys.stderr)
            return True
        else:
            print(f"Failed to revoke token: {revoke_response.text}", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"Error revoking token: {str(e)}", file=sys.stderr)
        return False

def post_photo_view(request):
    """Display photo posting form and handle submissions"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
        
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
    }
    
    # Handle form submission
    if request.method == 'POST':
        # Get form data
        title = request.POST.get('title', '')
        description = request.POST.get('description', '')
        photo_urls = request.POST.get('photo_urls', '').split('\n')
        photo_urls = [url.strip() for url in photo_urls if url.strip()]
        privacy_level = request.POST.get('privacy_level', 'PUBLIC_TO_EVERYONE')
        disable_comment = request.POST.get('disable_comment', '') == 'on'
        auto_add_music = request.POST.get('auto_add_music', '') == 'on'
        
        # Basic validation
        if not photo_urls:
            context['error'] = 'Please provide at least one photo URL'
            return render(request, 'accounts/post_photo.html', context)
            
        if not title:
            context['error'] = 'Please provide a title for your post'
            return render(request, 'accounts/post_photo.html', context)
        
        # Attempt to post photos
        try:
            result = post_photos_to_tiktok(
                request.session.get('tiktok_access_token'),
                title,
                description,
                photo_urls,
                privacy_level,
                disable_comment,
                auto_add_music
            )
            
            if result.get('success'):
                context['success'] = 'Your photos have been posted to TikTok!'
                context['publish_id'] = result.get('publish_id')
            else:
                context['error'] = result.get('error', 'An unknown error occurred')
        
        except Exception as e:
            print(f"Error posting photos: {str(e)}", file=sys.stderr)
            context['error'] = f"Error: {str(e)}"
    
    # Query creator info to get available privacy levels
    access_token = request.session.get('tiktok_access_token')
    if access_token:
        try:
            privacy_levels = get_creator_privacy_levels(access_token)
            if privacy_levels:
                context['privacy_levels'] = privacy_levels
        except Exception as e:
            print(f"Error fetching creator info: {str(e)}", file=sys.stderr)
    
    return render(request, 'accounts/post_photo.html', context)

def get_creator_privacy_levels(access_token):
    """Get available privacy levels for the creator"""
    creator_info_url = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json; charset=UTF-8'
    }
    
    try:
        response = requests.post(creator_info_url, headers=headers)
        print(f"Creator info response code: {response.status_code}", file=sys.stderr)
        print(f"Creator info response content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('privacy_level_options', [])
        return []
    except Exception as e:
        print(f"Error fetching creator info: {str(e)}", file=sys.stderr)
        return []

def post_photos_to_tiktok(access_token, title, description, photo_urls, privacy_level, disable_comment, auto_add_music):
    """Post photos to TikTok using the Content Posting API"""
    if not access_token:
        return {'success': False, 'error': 'No access token available'}
    
    # Prepare API request
    content_init_url = "https://open.tiktokapis.com/v2/post/publish/content/init/"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Create request payload
    payload = {
        'post_info': {
            'title': title,
            'description': description,
            'disable_comment': disable_comment,
            'privacy_level': privacy_level,
            'auto_add_music': auto_add_music
        },
        'source_info': {
            'source': 'PULL_FROM_URL',
            'photo_cover_index': 0,  # Use first image as cover
            'photo_images': photo_urls
        },
        'post_mode': 'DIRECT_POST',
        'media_type': 'PHOTO'
    }
    
    try:
        print("Posting photos to TikTok with payload:", file=sys.stderr)
        print(json.dumps(payload, indent=2), file=sys.stderr)
        
        response = requests.post(content_init_url, headers=headers, json=payload)
        print(f"Photo post response code: {response.status_code}", file=sys.stderr)
        print(f"Photo post response content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('error', {}).get('code') == 'ok':
                publish_id = data.get('data', {}).get('publish_id')
                return {'success': True, 'publish_id': publish_id}
            else:
                error = data.get('error', {})
                error_msg = f"{error.get('code')}: {error.get('message')}"
                return {'success': False, 'error': error_msg}
        
        return {'success': False, 'error': f"API error: {response.status_code} - {response.text}"}
    
    except Exception as e:
        print(f"Error in post_photos_to_tiktok: {str(e)}", file=sys.stderr)
        return {'success': False, 'error': str(e)}

def check_post_status(request, publish_id):
    """AJAX endpoint to check the status of a post"""
    if not request.session.get('tiktok_authenticated'):
        return JsonResponse({'success': False, 'error': 'Not authenticated'})
    
    access_token = request.session.get('tiktok_access_token')
    if not access_token:
        return JsonResponse({'success': False, 'error': 'No access token'})
    
    status_url = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json; charset=UTF-8'
    }
    
    payload = {
        'publish_id': publish_id
    }
    
    try:
        response = requests.post(status_url, headers=headers, json=payload)
        print(f"Status check response: {response.status_code}", file=sys.stderr)
        print(f"Status check content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            return JsonResponse({
                'success': True,
                'status': data.get('data', {}).get('status'),
                'error': data.get('error', {})
            })
        
        return JsonResponse({
            'success': False,
            'error': f"Status check failed: {response.status_code}"
        })
    
    except Exception as e:
        print(f"Error checking post status: {str(e)}", file=sys.stderr)
        return JsonResponse({'success': False, 'error': str(e)})

def schedule_video_view(request):
    """Display video scheduling form and handle submissions"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
        
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
    }
    
    # Query creator info to get available privacy levels
    access_token = request.session.get('tiktok_access_token')
    if access_token:
        try:
            privacy_levels = get_creator_privacy_levels(access_token)
            if privacy_levels:
                context['privacy_levels'] = privacy_levels
                
            # Get creator info for duet, stitch settings
            creator_info = get_creator_info(access_token)
            if creator_info:
                context['comment_disabled'] = creator_info.get('comment_disabled', False)
                context['duet_disabled'] = creator_info.get('duet_disabled', False)
                context['stitch_disabled'] = creator_info.get('stitch_disabled', False)
                context['max_video_duration'] = creator_info.get('max_video_post_duration_sec', 180)
        except Exception as e:
            print(f"Error fetching creator info: {str(e)}", file=sys.stderr)
    
    # Handle form submission
    if request.method == 'POST':
        # Get form data
        title = request.POST.get('title', '')
        description = request.POST.get('description', '')
        video_url = request.POST.get('video_url', '')
        scheduled_time_str = request.POST.get('scheduled_time', '')
        privacy_level = request.POST.get('privacy_level', 'PUBLIC_TO_EVERYONE')
        disable_comment = request.POST.get('disable_comment', '') == 'on'
        disable_duet = request.POST.get('disable_duet', '') == 'on'
        disable_stitch = request.POST.get('disable_stitch', '') == 'on'
        hashtags = request.POST.get('hashtags', '')
        
        # Basic validation
        if not video_url:
            context['error'] = 'Please provide a video URL'
            return render(request, 'accounts/schedule_video.html', context)
            
        if not title:
            context['error'] = 'Please provide a title for your post'
            return render(request, 'accounts/schedule_video.html', context)
        
        if not scheduled_time_str:
            context['error'] = 'Please provide a scheduled time for your post'
            return render(request, 'accounts/schedule_video.html', context)
        
        try:
            # Parse scheduled time
            scheduled_time = datetime.strptime(scheduled_time_str, '%Y-%m-%dT%H:%M')
            scheduled_time = timezone.make_aware(scheduled_time)
            
            # Check if scheduled time is in the past
            if scheduled_time < timezone.now():
                context['error'] = 'Scheduled time cannot be in the past'
                return render(request, 'accounts/schedule_video.html', context)
            
            # Create the scheduled post
            user_id = request.session.get('user_id')
            if not user_id:
                # If no user_id in session, create a user record
                from django.contrib.auth.models import User
                username = f"tiktok_{request.session.get('tiktok_open_id', uuid.uuid4().hex)}"
                user, created = User.objects.get_or_create(username=username)
                user_id = user.id
                request.session['user_id'] = user_id
            
            # Create scheduled post
            post = ScheduledPost.objects.create(
                user_id=user_id,
                title=title,
                description=description,
                media_type='video',
                media_url=video_url,
                privacy_level=privacy_level,
                disable_comment=disable_comment,
                disable_duet=disable_duet,
                disable_stitch=disable_stitch,
                hashtags=hashtags,
                scheduled_time=scheduled_time
            )
            
            # Create a notification
            Notification.objects.create(
                user_id=user_id,
                message=f"Video '{title}' has been scheduled for {scheduled_time_str}",
                type='info',
                post=post
            )
            
            context['success'] = 'Your video has been scheduled!'
            return redirect('accounts:scheduled_posts')
            
        except Exception as e:
            print(f"Error scheduling video: {str(e)}", file=sys.stderr)
            context['error'] = f"Error: {str(e)}"
    
    return render(request, 'accounts/schedule_video.html', context)

def scheduled_posts_view(request):
    """Display a list of scheduled posts"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
    
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
    }
    
    # Get scheduled posts
    user_id = request.session.get('user_id')
    if user_id:
        posts = ScheduledPost.objects.filter(user_id=user_id)
        context['posts'] = posts
    
    return render(request, 'accounts/scheduled_posts.html', context)

def edit_scheduled_post(request, post_id):
    """Edit a scheduled post"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
    
    # Get the post
    user_id = request.session.get('user_id')
    post = get_object_or_404(ScheduledPost, id=post_id, user_id=user_id)
    
    # Only allow editing of scheduled posts
    if not post.is_scheduled:
        return redirect('accounts:scheduled_posts')
    
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
        'post': post
    }
    
    # Query creator info to get available privacy levels
    access_token = request.session.get('tiktok_access_token')
    if access_token:
        try:
            privacy_levels = get_creator_privacy_levels(access_token)
            if privacy_levels:
                context['privacy_levels'] = privacy_levels
        except Exception as e:
            print(f"Error fetching creator info: {str(e)}", file=sys.stderr)
    
    # Handle form submission
    if request.method == 'POST':
        # Get form data
        title = request.POST.get('title', '')
        description = request.POST.get('description', '')
        video_url = request.POST.get('video_url', '')
        scheduled_time_str = request.POST.get('scheduled_time', '')
        privacy_level = request.POST.get('privacy_level', 'PUBLIC_TO_EVERYONE')
        disable_comment = request.POST.get('disable_comment', '') == 'on'
        disable_duet = request.POST.get('disable_duet', '') == 'on'
        disable_stitch = request.POST.get('disable_stitch', '') == 'on'
        hashtags = request.POST.get('hashtags', '')
        
        # Basic validation
        if not video_url:
            context['error'] = 'Please provide a video URL'
            return render(request, 'accounts/edit_scheduled_post.html', context)
            
        if not title:
            context['error'] = 'Please provide a title for your post'
            return render(request, 'accounts/edit_scheduled_post.html', context)
        
        if not scheduled_time_str:
            context['error'] = 'Please provide a scheduled time for your post'
            return render(request, 'accounts/edit_scheduled_post.html', context)
        
        try:
            # Parse scheduled time
            scheduled_time = datetime.strptime(scheduled_time_str, '%Y-%m-%dT%H:%M')
            scheduled_time = timezone.make_aware(scheduled_time)
            
            # Check if scheduled time is in the past
            if scheduled_time < timezone.now():
                context['error'] = 'Scheduled time cannot be in the past'
                return render(request, 'accounts/edit_scheduled_post.html', context)
            
            # Update the post
            post.title = title
            post.description = description
            post.media_url = video_url
            post.privacy_level = privacy_level
            post.disable_comment = disable_comment
            post.disable_duet = disable_duet
            post.disable_stitch = disable_stitch
            post.hashtags = hashtags
            post.scheduled_time = scheduled_time
            post.save()
            
            # Create a notification
            Notification.objects.create(
                user_id=user_id,
                message=f"Video '{title}' has been updated",
                type='info',
                post=post
            )
            
            return redirect('accounts:scheduled_posts')
            
        except Exception as e:
            print(f"Error updating post: {str(e)}", file=sys.stderr)
            context['error'] = f"Error: {str(e)}"
    
    return render(request, 'accounts/edit_scheduled_post.html', context)

def delete_scheduled_post(request, post_id):
    """Delete a scheduled post"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
    
    # Get the post
    user_id = request.session.get('user_id')
    post = get_object_or_404(ScheduledPost, id=post_id, user_id=user_id)
    
    # Only allow deletion of scheduled posts
    if not post.is_scheduled:
        return redirect('accounts:scheduled_posts')
    
    if request.method == 'POST':
        post_title = post.title
        post.delete()
        
        # Create a notification
        Notification.objects.create(
            user_id=user_id,
            message=f"Video '{post_title}' has been deleted",
            type='info'
        )
        
        return redirect('accounts:scheduled_posts')
    
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
        'post': post
    }
    
    return render(request, 'accounts/delete_scheduled_post.html', context)

def analytics_dashboard(request):
    """Display analytics dashboard"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
    
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
    }
    
    # Get published posts with analytics
    user_id = request.session.get('user_id')
    if user_id:
        published_posts = ScheduledPost.objects.filter(
            user_id=user_id, 
            status='published'
        ).select_related('analytics')
        
        context['published_posts'] = published_posts
    
    return render(request, 'accounts/analytics.html', context)

def get_creator_info(access_token):
    """Get comprehensive creator info from TikTok"""
    creator_info_url = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json; charset=UTF-8'
    }
    
    try:
        response = requests.post(creator_info_url, headers=headers)
        print(f"Creator info response code: {response.status_code}", file=sys.stderr)
        print(f"Creator info response content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {})
        return {}
    except Exception as e:
        print(f"Error fetching creator info: {str(e)}", file=sys.stderr)
        return {}

def process_scheduled_posts():
    """Process scheduled posts that are due to be published"""
    now = timezone.now()
    due_posts = ScheduledPost.objects.filter(
        status='scheduled',
        scheduled_time__lte=now
    )
    
    for post in due_posts:
        try:
            # Update status to processing
            post.status = 'processing'
            post.save()
            
            # Post to TikTok
            if post.media_type == 'video':
                result = post_video_to_tiktok(
                    # Get access token for user
                    user_id=post.user_id,
                    title=post.title,
                    video_url=post.media_url,
                    privacy_level=post.privacy_level,
                    disable_comment=post.disable_comment,
                    disable_duet=post.disable_duet,
                    disable_stitch=post.disable_stitch
                )
            else:  # photo
                photo_urls = [post.media_url]
                if ',' in post.media_url:
                    photo_urls = [url.strip() for url in post.media_url.split(',')]
                
                result = post_photos_to_tiktok(
                    # Get access token for user
                    user_id=post.user_id,
                    title=post.title,
                    description=post.description,
                    photo_urls=photo_urls,
                    privacy_level=post.privacy_level,
                    disable_comment=post.disable_comment,
                    auto_add_music=post.auto_add_music
                )
            
            if result.get('success'):
                post.publish_id = result.get('publish_id')
                post.status = 'processing'  # Will be updated to published when confirmed
                
                # Create a notification
                Notification.objects.create(
                    user_id=post.user_id,
                    message=f"Your {post.media_type} '{post.title}' is being processed by TikTok",
                    type='info',
                    post=post
                )
            else:
                post.status = 'failed'
                post.error_message = result.get('error', 'Unknown error')
                
                # Create a notification
                Notification.objects.create(
                    user_id=post.user_id,
                    message=f"Failed to post {post.media_type} '{post.title}': {post.error_message}",
                    type='error',
                    post=post
                )
            
            post.save()
            
        except Exception as e:
            print(f"Error processing scheduled post {post.id}: {str(e)}", file=sys.stderr)
            post.status = 'failed'
            post.error_message = str(e)
            post.save()
            
            # Create a notification
            Notification.objects.create(
                user_id=post.user_id,
                message=f"Error processing {post.media_type} '{post.title}': {str(e)}",
                type='error',
                post=post
            )

def post_video_to_tiktok(access_token, title, video_url, privacy_level, disable_comment, disable_duet, disable_stitch):
    """Post a video to TikTok using the Direct Post API"""
    if not access_token:
        return {'success': False, 'error': 'No access token available'}
    
    # Prepare API request
    video_init_url = "https://open.tiktokapis.com/v2/post/publish/video/init/"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json; charset=UTF-8'
    }
    
    # Create request payload
    payload = {
        'post_info': {
            'title': title,
            'privacy_level': privacy_level,
            'disable_duet': disable_duet,
            'disable_comment': disable_comment,
            'disable_stitch': disable_stitch
        },
        'source_info': {
            'source': 'PULL_FROM_URL',
            'video_url': video_url
        }
    }
    
    try:
        print("Posting video to TikTok with payload:", file=sys.stderr)
        print(json.dumps(payload, indent=2), file=sys.stderr)
        
        response = requests.post(video_init_url, headers=headers, json=payload)
        print(f"Video post response code: {response.status_code}", file=sys.stderr)
        print(f"Video post response content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('error', {}).get('code') == 'ok':
                publish_id = data.get('data', {}).get('publish_id')
                return {'success': True, 'publish_id': publish_id}
            else:
                error = data.get('error', {})
                error_msg = f"{error.get('code')}: {error.get('message')}"
                return {'success': False, 'error': error_msg}
        
        return {'success': False, 'error': f"API error: {response.status_code} - {response.text}"}
    
    except Exception as e:
        print(f"Error in post_video_to_tiktok: {str(e)}", file=sys.stderr)
        return {'success': False, 'error': str(e)}

def notifications_view(request):
    """Display user notifications"""
    # Check if user is authenticated with TikTok
    if not request.session.get('tiktok_authenticated'):
        return redirect('accounts:login')
    
    context = {
        'username': request.session.get('tiktok_username', 'TikTok User'),
        'profile_picture': request.session.get('tiktok_profile_picture', None),
    }
    
    # Get notifications
    user_id = request.session.get('user_id')
    if user_id:
        notifications = Notification.objects.filter(user_id=user_id)
        context['notifications'] = notifications
    
    return render(request, 'accounts/notifications.html', context)

def mark_notification_read(request, notification_id):
    """Mark a notification as read"""
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        notification = get_object_or_404(Notification, id=notification_id, user_id=user_id)
        notification.read = True
        notification.save()
        return JsonResponse({'success': True})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})

def mark_all_notifications_read(request):
    """Mark all notifications as read"""
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        Notification.objects.filter(user_id=user_id, read=False).update(read=True)
        return JsonResponse({'success': True})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})

@login_required
def analytics_view(request):
    """
    View function for the TikTok analytics dashboard.
    Displays analytics data for the user's TikTok posts.
    """
    user = request.user
    tiktok_authenticated = hasattr(user, 'tiktok_profile') and user.tiktok_profile.is_authenticated
    
    context = {
        'tiktok_authenticated': tiktok_authenticated
    }
    
    if tiktok_authenticated:
        # Get user profile information
        tiktok_profile = user.tiktok_profile
        context.update({
            'username': tiktok_profile.username,
            'profile_picture': tiktok_profile.profile_picture,
        })
        
        # Get published posts for analytics
        published_posts = ScheduledPost.objects.filter(
            user=user, 
            status='published'
        ).order_by('-published_at')
        
        context['published_posts'] = published_posts
        
        # Calculate totals
        total_views = sum(post.analytics.views for post in published_posts if hasattr(post, 'analytics'))
        total_likes = sum(post.analytics.likes for post in published_posts if hasattr(post, 'analytics'))
        total_comments = sum(post.analytics.comments for post in published_posts if hasattr(post, 'analytics'))
        total_shares = sum(post.analytics.shares for post in published_posts if hasattr(post, 'analytics'))
        
        # Calculate engagement rate
        if total_views > 0:
            engagement_actions = total_likes + total_comments + total_shares
            engagement_rate = round((engagement_actions / total_views) * 100, 2)
        else:
            engagement_rate = 0
            
        context.update({
            'total_views': total_views,
            'total_likes': total_likes,
            'total_comments': total_comments,
            'total_shares': total_shares,
            'engagement_rate': engagement_rate
        })
    
    return render(request, 'accounts/analytics.html', context)