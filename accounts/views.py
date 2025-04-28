# views.py in accounts app

import os
import sys
import json
import uuid
import requests
from datetime import datetime, timedelta
import urllib.parse
from urllib.parse import urlencode, urlparse
import re
import time

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.contrib.auth.models import User
from django.utils.text import slugify
from django.core.files.uploadedfile import UploadedFile
from celery import shared_task
from functools import wraps
from .models import ScheduledPost, PostAnalytics, Notification, TikTokProfile
from .cloudinary_utils import upload_media, delete_media, extract_public_id_from_url

# TikTok authentication decorator
def tiktok_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('tiktok_authenticated'):
            return redirect('accounts:login')
        return view_func(request, *args, **kwargs)
    return wrapper

def login_view(request):
    """Display login page with TikTok OAuth button"""
    # If user is already authenticated, redirect to dashboard
    if request.session.get('tiktok_authenticated'):
        return redirect('accounts:dashboard')
        
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
    try:
        # Get settings from environment variables
        client_key = os.environ.get('TIKTOK_CLIENT_KEY')
        client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')  # Not used here but in callback
        redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI', 'https://emmanueltech.store/accounts/login/tiktok/callback/')
        
        if not client_key:
            print("Error: TIKTOK_CLIENT_KEY not found in environment variables", file=sys.stderr)
            return render(request, 'accounts/login.html', {'error': 'TikTok Client Key not configured'})
        
        # Generate random state to prevent CSRF
        csrf_state = uuid.uuid4().hex
        
        # Store state in session
        request.session['tiktok_csrf_state'] = csrf_state
        
        # Log information
        print(f"Environment variables:", file=sys.stderr)
        print(f"TIKTOK_CLIENT_KEY: {'SET' if client_key else 'NOT SET'}", file=sys.stderr)
        print(f"TIKTOK_CLIENT_SECRET: {'SET' if client_secret else 'NOT SET'}", file=sys.stderr)
        print(f"TIKTOK_REDIRECT_URI: {redirect_uri}", file=sys.stderr)
        
        # Clean the redirect URI 
        # Requirements for redirect_uri:
        # 1. Must be https (except for localhost)
        # 2. Must be static (no parameters)
        # 3. No fragment or hash character
        parsed_uri = urllib.parse.urlparse(redirect_uri)
        clean_redirect_uri = urllib.parse.urlunparse((
            parsed_uri.scheme,
            parsed_uri.netloc,
            parsed_uri.path,
            '',  # No params
            '',  # No query
            ''   # No fragment
        ))
        
        print(f"Original redirect_uri: {redirect_uri}", file=sys.stderr)
        print(f"Cleaned redirect_uri for token exchange: {clean_redirect_uri}", file=sys.stderr)
        
        # TikTok OAuth authorization URL - following exact format from documentation
        auth_url = 'https://www.tiktok.com/v2/auth/authorize/'
        auth_url += f'?client_key={client_key}'
        auth_url += '&response_type=code'
        auth_url += '&scope=user.info.basic,user.info.profile,user.info.stats,video.list,video.upload,video.publish'
        auth_url += f'&redirect_uri={clean_redirect_uri}'
        auth_url += f'&state={csrf_state}'
        
        print(f"Redirecting to TikTok auth URL: {auth_url}", file=sys.stderr)
        return redirect(auth_url)
        
    except Exception as e:
        print(f"Error in tiktok_login: {str(e)}", file=sys.stderr)
        return render(request, 'accounts/login.html', {'error': f'Error during TikTok login setup: {str(e)}'})

def tiktok_callback(request):
    """Handle callback from TikTok OAuth"""
    try:
        # Get settings from environment variables
        client_key = os.environ.get('TIKTOK_CLIENT_KEY')
        client_secret = os.environ.get('TIKTOK_CLIENT_SECRET')
        redirect_uri = os.environ.get('TIKTOK_REDIRECT_URI')
        
        # Get code and state from query parameters
        code = request.GET.get('code')
        state = request.GET.get('state')
        error = request.GET.get('error')
        error_description = request.GET.get('error_description')
        scopes = request.GET.get('scopes')
        
        # Debug info
        print(f"Received error: {error}", file=sys.stderr)
        print(f"Received error_description: {error_description}", file=sys.stderr)
        print(f"Received state: {state}", file=sys.stderr)
        print(f"Received scopes: {scopes}", file=sys.stderr)
        print(f"Current session key: {request.session.session_key}", file=sys.stderr)
        
        # Exit early if there was an error or no code
        if error or not code:
            error_msg = error_description or "Authorization failed or was cancelled by the user"
            return render(request, 'accounts/login.html', {'error': error_msg})
        
        # Clean redirect_uri as we did in the original request
        parsed_uri = urllib.parse.urlparse(redirect_uri)
        clean_redirect_uri = urllib.parse.urlunparse((
            parsed_uri.scheme,
            parsed_uri.netloc,
            parsed_uri.path,
            '',  # No params
            '',  # No query
            ''   # No fragment
        ))
        
        # Token exchange with TikTok
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        exchange_data = {
            'client_key': client_key,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': clean_redirect_uri
        }
        
        print("Attempting token exchange with data:", file=sys.stderr)
        print(f"client_key: {client_key[:5]}...{client_key[-5:]}", file=sys.stderr)
        print(f"client_secret: [REDACTED]", file=sys.stderr)
        print(f"code: {code[:5]}...{code[-5:]}", file=sys.stderr)
        print(f"redirect_uri: {clean_redirect_uri}", file=sys.stderr)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = requests.post(token_url, data=exchange_data, headers=headers)
        print(f"Token exchange response code: {response.status_code}", file=sys.stderr)
        print(f"Token exchange response headers: {response.headers}", file=sys.stderr)
        print(f"Token exchange response content: {response.text}", file=sys.stderr)
        
        # Process the token response
        if response.status_code == 200:
            token_data = response.json()
            
            # Store tokens in session
            access_token = token_data.get('access_token')
            refresh_token = token_data.get('refresh_token')
            open_id = token_data.get('open_id')
            
            if access_token and open_id:
                # Store in session for authenticated views
                request.session['tiktok_access_token'] = access_token
                request.session['tiktok_refresh_token'] = refresh_token
                request.session['tiktok_open_id'] = open_id
                request.session['tiktok_authenticated'] = True
                
                # Try to get user info
                success = False
                
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
                                    
                                    # Store profile info in session
                                    request.session['tiktok_username'] = username
                                    request.session['tiktok_profile_picture'] = profile_picture
                                    request.session['tiktok_profile_deep_link'] = profile_deep_link
                                    request.session['tiktok_bio'] = bio
                                    request.session['tiktok_is_verified'] = is_verified
                                    request.session['tiktok_handle'] = tiktok_username
                                    request.session['tiktok_follower_count'] = follower_count
                                    request.session['tiktok_following_count'] = following_count
                                    request.session['tiktok_likes_count'] = likes_count
                                    request.session['tiktok_video_count'] = video_count
                    
                    except Exception as e:
                        print(f"Error accessing v2 user info endpoint: {str(e)}", file=sys.stderr)
                
                if success:
                    print(f"Stored in session - Username: {username}", file=sys.stderr)
                    
                    # Handle user creation/linking
                    # Check if we already have a user with this TikTok ID
                    user_id = request.session.get('user_id')
                    
                    if not user_id:
                        # If no user_id in session, create a user record
                        username = f"tiktok_{request.session.get('tiktok_open_id', uuid.uuid4().hex)}"
                        user, created = User.objects.get_or_create(username=username)
                        user_id = user.id
                        request.session['user_id'] = user_id
                    
                    print(f"Login successful, redirecting to dashboard", file=sys.stderr)
                    return redirect('accounts:dashboard')
                else:
                    return render(request, 'accounts/login.html', {'error': 'Failed to retrieve user information from TikTok'})
            else:
                return render(request, 'accounts/login.html', {'error': 'TikTok login failed: Missing access token or open_id in response'})
        else:
            return render(request, 'accounts/login.html', {'error': f'TikTok authentication failed: {response.text}'})
    
    except Exception as e:
        print(f"Error in tiktok_callback: {str(e)}", file=sys.stderr)
        return render(request, 'accounts/login.html', {'error': f'TikTok login failed: {str(e)}'})

@tiktok_login_required
def dashboard(request):
    """Display user dashboard with TikTok profile info and videos from session"""
    try:
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

    except Exception as e:
        print(f"Error in dashboard view: {str(e)}", file=sys.stderr)
        # Show a user-friendly error page
        error_context = {
            'error_title': 'Dashboard Error',
            'error_message': 'There was a problem loading your dashboard. Please try logging in again.'
        }
        return render(request, 'accounts/error.html', error_context)

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

def proxy_media(request, media_id, filename):
    """
    Proxy endpoint to serve Cloudinary media through our domain
    """
    try:
        # Construct Cloudinary URL
        public_id = f"tiktok_media/{media_id}"
        
        # Get resource info from Cloudinary to check if it exists
        from cloudinary.api import resource
        try:
            resource_info = resource(public_id, resource_type="image")
            media_url = resource_info.get('secure_url')
        except Exception as e:
            print(f"Error fetching resource from Cloudinary: {str(e)}", file=sys.stderr)
            return HttpResponse("Media not found", status=404)
        
        # Redirect to the Cloudinary URL
        # This is more efficient than downloading and re-serving the file
        return redirect(media_url)
    except Exception as e:
        print(f"Error in proxy_media: {str(e)}", file=sys.stderr)
        return HttpResponse("Media not found", status=404)

@tiktok_login_required
def post_photo_view(request):
    """
    View for posting a photo directly to TikTok
    """
    try:
        context = {
            'section': 'post-photo',
            'title': 'Post Photo to TikTok'
        }
        
        # Handle form submission
        if request.method == 'POST':
            # Debug POST data
            print(f"POST data: {request.POST}", file=sys.stderr)
            print(f"FILES data: {request.FILES}", file=sys.stderr)
            
            # Get form data
            title = request.POST.get('title', '').strip()
            description = request.POST.get('description', '').strip()
            privacy_level = request.POST.get('privacy_level', 'PUBLIC_TO_EVERYONE')
            disable_comment = request.POST.get('disable_comment', '') == 'on'
            auto_add_music = request.POST.get('auto_add_music', '') == 'on'
            
            # Check for uploaded files first
            uploaded_file = None
            photo_urls = []
            cloudinary_public_id = ""
            
            if 'photos' in request.FILES and request.FILES['photos']:
                # Get the uploaded file (only one allowed)
                uploaded_file = request.FILES['photos']
                print(f"Received file: {uploaded_file.name}, size: {uploaded_file.size}, type: {uploaded_file.content_type}", file=sys.stderr)
                
                # Validate file type
                if not uploaded_file.content_type in ['image/jpeg', 'image/png', 'image/webp']:
                    context['error'] = f'Invalid file type: {uploaded_file.name}. Only JPEG, PNG, and WebP formats are supported.'
                    return render(request, 'accounts/post_photo.html', context)
                
                # Validate file size (20MB max)
                if uploaded_file.size > 20 * 1024 * 1024:
                    context['error'] = f'File too large: {uploaded_file.name}. Maximum size is 20MB.'
                    return render(request, 'accounts/post_photo.html', context)
                
                # Upload to Cloudinary
                try:
                    print(f"Uploading to Cloudinary: {uploaded_file.name}", file=sys.stderr)
                    upload_result = upload_media(uploaded_file, resource_type="image")
                    file_url = upload_result.get('secure_url')
                    cloudinary_public_id = upload_result.get('public_id')
                    
                    # Instead of using Cloudinary URL directly, create a proxy URL through our domain
                    # Extract the media ID from the public_id (after the last /)
                    media_id = cloudinary_public_id.split('/')[-1]
                    # Get file extension from original filename or from content_type
                    extension = uploaded_file.name.split('.')[-1].lower()
                    if extension not in ['jpg', 'jpeg', 'png', 'webp']:
                        if uploaded_file.content_type == 'image/jpeg':
                            extension = 'jpg'
                        elif uploaded_file.content_type == 'image/png':
                            extension = 'png'
                        elif uploaded_file.content_type == 'image/webp':
                            extension = 'webp'
                        else:
                            extension = 'jpg'  # Default to jpg if we can't determine
                    
                    # Create proxied URL through our domain
                    host = request.get_host()
                    scheme = request.scheme
                    proxied_url = f"{scheme}://{host}/accounts/media/{media_id}/{secure_filename(uploaded_file.name)}"
                    photo_urls.append(proxied_url)
                    
                    print(f"Cloudinary upload success: {file_url}, public_id: {cloudinary_public_id}", file=sys.stderr)
                    print(f"Proxied URL: {proxied_url}", file=sys.stderr)
                except Exception as e:
                    print(f"Cloudinary upload error: {str(e)}", file=sys.stderr)
                    context['error'] = f'Error uploading to cloud storage: {str(e)}'
                    return render(request, 'accounts/post_photo.html', context)
            else:
                print("No file uploaded, checking for URL", file=sys.stderr)
                # Fall back to URL-based uploads
                photo_url = request.POST.get('photo_url', '').strip()
                if photo_url:
                    # Basic URL validation
                    if not any(photo_url.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.webp']):
                        context['error'] = 'Invalid photo URL format. URL must end with .jpg, .jpeg, .png, or .webp'
                        return render(request, 'accounts/post_photo.html', context)
                    
                    # For URL cases, we need to first download and re-upload to Cloudinary
                    # Then serve via our proxy
                    try:
                        # Download and upload to Cloudinary
                        upload_result = upload_media(photo_url, resource_type="image")
                        cloudinary_public_id = upload_result.get('public_id')
                        
                        # Create proxied URL 
                        media_id = cloudinary_public_id.split('/')[-1]
                        filename = photo_url.split('/')[-1]
                        host = request.get_host()
                        scheme = request.scheme
                        proxied_url = f"{scheme}://{host}/accounts/media/{media_id}/{secure_filename(filename)}"
                        photo_urls.append(proxied_url)
                        
                        print(f"Downloaded and re-uploaded URL: {photo_url}", file=sys.stderr)
                        print(f"Proxied URL: {proxied_url}", file=sys.stderr)
                    except Exception as e:
                        context['error'] = f'Error processing external URL: {str(e)}'
                        return render(request, 'accounts/post_photo.html', context)
            
            # Basic validation
            if not title:
                context['error'] = 'Please provide a title for your post'
                return render(request, 'accounts/post_photo.html', context)
                
            if not photo_urls:
                context['error'] = 'Please provide a photo by uploading or entering a URL'
                return render(request, 'accounts/post_photo.html', context)
            
            # Attempt to post photo
            try:
                result = post_photos_to_tiktok(
                    request.session.get('user_id'),
                    title,
                    description,
                    photo_urls,
                    privacy_level,
                    disable_comment,
                    auto_add_music
                )
                
                if result.get('success'):
                    context['success'] = 'Your photo has been posted to TikTok!'
                    context['publish_id'] = result.get('publish_id')
                    
                    # Save as scheduled post (but mark as published)
                    if request.session.get('user_id'):
                        try:
                            user = User.objects.get(id=request.session.get('user_id'))
                            post = ScheduledPost(
                                user=user,
                                title=title,
                                description=description,
                                media_type='photo',
                                media_url=photo_urls[0],
                                cloudinary_public_id=cloudinary_public_id,
                                privacy_level=privacy_level,
                                disable_comment=disable_comment,
                                auto_add_music=auto_add_music,
                                scheduled_time=timezone.now(),
                                status='published',
                                publish_id=result.get('publish_id')
                            )
                            post.save()
                            
                            # Since the post was published successfully, we can delete the media from Cloudinary
                            if cloudinary_public_id:
                                delete_media(cloudinary_public_id, resource_type="image")
                                
                        except Exception as e:
                            print(f"Error saving post record: {str(e)}", file=sys.stderr)
                            # Continue without saving record
                else:
                    context['error'] = result.get('error', 'An unknown error occurred')
                    # If posting failed, delete the media from Cloudinary
                    if cloudinary_public_id:
                        delete_media(cloudinary_public_id, resource_type="image")
            
            except Exception as e:
                print(f"Error posting photo: {str(e)}", file=sys.stderr)
                context['error'] = f"Error: {str(e)}"
                
                # If posting failed, delete the media from Cloudinary
                if cloudinary_public_id:
                    delete_media(cloudinary_public_id, resource_type="image")
        
        # Query creator info to get available privacy levels
        access_token = request.session.get('tiktok_access_token')
        if access_token:
            try:
                privacy_levels = get_creator_privacy_levels(access_token)
                if privacy_levels:
                    context['privacy_levels'] = privacy_levels
            except Exception as e:
                print(f"Error fetching creator info: {str(e)}", file=sys.stderr)
                # Continue without privacy levels
        
        return render(request, 'accounts/post_photo.html', context)
    
    except Exception as e:
        print(f"Error in post_photo_view: {str(e)}", file=sys.stderr)
        error_context = {
            'error_title': 'Photo Posting Error',
            'error_message': 'There was a problem with the photo posting feature. Please try again later.'
        }
        return render(request, 'accounts/error.html', error_context)

# Helper function to secure filenames
def secure_filename(filename):
    """
    Sanitize a filename by removing potentially dangerous characters
    """
    # Replace non-alphanumeric characters with underscores, except for period and some common safe chars
    filename = re.sub(r'[^\w\.\-]', '_', filename)
    # Remove leading periods to prevent hidden files
    filename = filename.lstrip('.')
    return filename

# Celery task to clean up temporary files
@shared_task
def cleanup_temp_files(file_urls):
    """
    Clean up temporary files after they've been uploaded to TikTok
    """
    try:
        for url in file_urls:
            # Extract filename from URL
            filename = os.path.basename(urlparse(url).path)
            file_path = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', filename)
            
            # Remove file if it exists
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Removed temporary file: {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"Error cleaning up temporary files: {str(e)}", file=sys.stderr)

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

def post_photos_to_tiktok(user_id, title, description, photo_urls, privacy_level, disable_comment, auto_add_music):
    """Post photos to TikTok using the Content Posting API"""
    try:
        # Get user's access token
        profile = TikTokProfile.objects.get(user_id=user_id)
        access_token = profile.access_token
        
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
    
    except TikTokProfile.DoesNotExist:
        return {'success': False, 'error': 'TikTok profile not found for this user'}
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

@tiktok_login_required
def schedule_video_view(request):
    """Display video scheduling form and handle submissions"""
    try:
        context = {
            'section': 'schedule-video',
            'title': 'Schedule Video for TikTok'
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
                # Continue without creator info
        
        # Handle form submission
        if request.method == 'POST':
            # Debug form data
            print(f"POST data: {request.POST}", file=sys.stderr)
            print(f"FILES data: {request.FILES}", file=sys.stderr)
            
            # Get form data
            title = request.POST.get('title', '').strip()
            description = request.POST.get('description', '').strip()
            video_url = request.POST.get('video_url', '').strip()
            scheduled_time_str = request.POST.get('scheduled_time', '').strip()
            privacy_level = request.POST.get('privacy_level', 'PUBLIC_TO_EVERYONE')
            disable_comment = request.POST.get('disable_comment', '') == 'on'
            disable_duet = request.POST.get('disable_duet', '') == 'on'
            disable_stitch = request.POST.get('disable_stitch', '') == 'on'
            hashtags = request.POST.get('hashtags', '')
            
            # Handle file upload to Cloudinary
            uploaded_file = None
            cloudinary_public_id = ""
            
            if 'video_file' in request.FILES and request.FILES['video_file']:
                uploaded_file = request.FILES['video_file']
                
                # Validate file type
                valid_video_types = ['video/mp4', 'video/quicktime', 'video/x-msvideo', 'video/x-ms-wmv']
                if not uploaded_file.content_type in valid_video_types:
                    context['error'] = f'Invalid file type: {uploaded_file.name}. Only MP4, MOV, AVI, and WMV formats are supported.'
                    return render(request, 'accounts/schedule_video.html', context)
                
                # Validate file size (100MB max)
                if uploaded_file.size > 100 * 1024 * 1024:
                    context['error'] = f'File too large: {uploaded_file.name}. Maximum size is 100MB.'
                    return render(request, 'accounts/schedule_video.html', context)
                
                # Upload to Cloudinary
                try:
                    print(f"Uploading video to Cloudinary: {uploaded_file.name}", file=sys.stderr)
                    upload_result = upload_media(uploaded_file, resource_type="video")
                    video_url = upload_result.get('secure_url')
                    cloudinary_public_id = upload_result.get('public_id')
                    print(f"Cloudinary upload success: {video_url}, public_id: {cloudinary_public_id}", file=sys.stderr)
                except Exception as e:
                    print(f"Cloudinary upload error: {str(e)}", file=sys.stderr)
                    context['error'] = f'Error uploading to cloud storage: {str(e)}'
                    return render(request, 'accounts/schedule_video.html', context)
            elif video_url:
                # Validate video URL format
                if not any(video_url.lower().endswith(ext) for ext in ['.mp4', '.mov', '.avi', '.wmv']):
                    context['error'] = 'Invalid video URL format. URL must end with .mp4, .mov, .avi, or .wmv'
                    return render(request, 'accounts/schedule_video.html', context)
                
                print(f"Using provided video URL: {video_url}", file=sys.stderr)
            
            # Basic validation
            if not title:
                context['error'] = 'Please provide a title for your post'
                return render(request, 'accounts/schedule_video.html', context)
                
            if not video_url:
                context['error'] = 'Please provide a video URL or upload a video file'
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
                    cloudinary_public_id=cloudinary_public_id,
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
                
                # If there was an error and we uploaded to Cloudinary, delete the file
                if cloudinary_public_id:
                    try:
                        delete_media(cloudinary_public_id)
                    except Exception as del_error:
                        print(f"Error deleting failed upload from Cloudinary: {str(del_error)}", file=sys.stderr)
        
        return render(request, 'accounts/schedule_video.html', context)
    
    except Exception as e:
        print(f"Error in schedule_video_view: {str(e)}", file=sys.stderr)
        error_context = {
            'error_title': 'Video Scheduling Error',
            'error_message': 'There was a problem with the video scheduling feature. Please try again later.'
        }
        return render(request, 'accounts/error.html', error_context)

@tiktok_login_required
def scheduled_posts_view(request):
    """Display a list of scheduled posts"""
    try:
        context = {
            'username': request.session.get('tiktok_username', 'TikTok User'),
            'profile_picture': request.session.get('tiktok_profile_picture', None),
        }
        
        # Get scheduled posts
        user_id = request.session.get('user_id')
        if user_id:
            try:
                posts = ScheduledPost.objects.filter(user_id=user_id)
                context['posts'] = posts
            except Exception as e:
                error_msg = f"Error fetching scheduled posts: {str(e)}"
                print(error_msg, file=sys.stderr)
                context['error'] = "Could not retrieve your scheduled posts"
        
        return render(request, 'accounts/scheduled_posts.html', context)
    
    except Exception as e:
        error_msg = f"Error in scheduled_posts_view: {str(e)}"
        print(error_msg, file=sys.stderr)
        
        # Instead of rendering an error template, log the error and render the regular template
        # with an error message in the context
        context = {
            'username': request.session.get('tiktok_username', 'TikTok User'),
            'profile_picture': request.session.get('tiktok_profile_picture', None),
            'error': 'There was a problem loading your scheduled posts. Please try again later.'
        }
        return render(request, 'accounts/scheduled_posts.html', context)

@tiktok_login_required
def edit_scheduled_post(request, post_id):
    """Edit a scheduled post"""
    try:
        # Get the post
        user_id = request.session.get('user_id')
        try:
            post = get_object_or_404(ScheduledPost, id=post_id, user_id=user_id)
        except:
            error_context = {
                'error_title': 'Post Not Found',
                'error_message': 'The scheduled post you are trying to edit could not be found.'
            }
            return render(request, 'accounts/error.html', error_context)
        
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
    
    except Exception as e:
        print(f"Error in edit_scheduled_post: {str(e)}", file=sys.stderr)
        error_context = {
            'error_title': 'Edit Post Error',
            'error_message': 'There was a problem editing your scheduled post. Please try again later.'
        }
        return render(request, 'accounts/error.html', error_context)

@tiktok_login_required
def delete_scheduled_post(request, post_id):
    """Delete a scheduled post"""
    try:
        # Get the post
        user_id = request.session.get('user_id')
        try:
            post = get_object_or_404(ScheduledPost, id=post_id, user_id=user_id)
        except:
            error_context = {
                'error_title': 'Post Not Found',
                'error_message': 'The scheduled post you are trying to delete could not be found.'
            }
            return render(request, 'accounts/error.html', error_context)
        
        # Only allow deletion of scheduled posts
        if not post.is_scheduled:
            return redirect('accounts:scheduled_posts')
        
        if request.method == 'POST':
            post_title = post.title
            
            # Delete Cloudinary media if it exists
            cloudinary_deleted = False
            if post.cloudinary_public_id:
                try:
                    delete_media(post.cloudinary_public_id, resource_type="image")
                    cloudinary_deleted = True
                except Exception as e:
                    print(f"Error deleting Cloudinary media for post {post.id}: {str(e)}", file=sys.stderr)
            
            # Delete post from database
            post.delete()
            
            # Create a notification
            msg = f"Video '{post_title}' has been deleted"
            if cloudinary_deleted:
                msg += " along with its associated media"
                
            Notification.objects.create(
                user_id=user_id,
                message=msg,
                type='info'
            )
            
            return redirect('accounts:scheduled_posts')
        
        context = {
            'username': request.session.get('tiktok_username', 'TikTok User'),
            'profile_picture': request.session.get('tiktok_profile_picture', None),
            'post': post
        }
        
        return render(request, 'accounts/delete_scheduled_post.html', context)
    
    except Exception as e:
        print(f"Error in delete_scheduled_post: {str(e)}", file=sys.stderr)
        error_context = {
            'error_title': 'Delete Post Error',
            'error_message': 'There was a problem deleting your scheduled post. Please try again later.'
        }
        return render(request, 'accounts/error.html', error_context)

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
                
                # Wait a short while to check if the post is published
                for i in range(3):  # Try up to 3 times
                    time.sleep(5)  # Wait 5 seconds between checks
                    status_result = check_post_status_internal(post.user_id, post.publish_id)
                    if status_result.get('status') == 'PUBLISH_DONE':
                        post.status = 'published'
                        
                        # Delete Cloudinary media now that it's successfully published
                        if post.cloudinary_public_id:
                            try:
                                delete_media(post.cloudinary_public_id, resource_type="image")
                                post.cloudinary_public_id = ''  # Clear the public_id after deletion
                            except Exception as cloud_error:
                                print(f"Error deleting Cloudinary media for post {post.id}: {str(cloud_error)}", file=sys.stderr)
                        
                        # Update notification
                        Notification.objects.create(
                            user_id=post.user_id,
                            message=f"Your {post.media_type} '{post.title}' has been published to TikTok",
                            type='success',
                            post=post
                        )
                        break
                    elif status_result.get('status') == 'PUBLISH_FAILED':
                        post.status = 'failed'
                        post.error_message = status_result.get('error_message', 'Unknown error from TikTok')
                        
                        # Create failure notification
                        Notification.objects.create(
                            user_id=post.user_id,
                            message=f"Failed to publish {post.media_type} '{post.title}': {post.error_message}",
                            type='error',
                            post=post
                        )
                        break
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
                
                # We don't delete media on failure so user can try again
            
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
            
            # We don't delete media on exception so user can try again

def check_post_status_internal(user_id, publish_id):
    """Internal utility to check post status"""
    try:
        # Get user's access token
        profile = TikTokProfile.objects.get(user_id=user_id)
        access_token = profile.access_token
        
        status_url = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json; charset=UTF-8'
        }
        
        payload = {
            'publish_id': publish_id
        }
        
        response = requests.post(status_url, headers=headers, json=payload)
        print(f"Status check response: {response.status_code}", file=sys.stderr)
        print(f"Status check content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get('data', {}).get('status')
            return {
                'success': True,
                'status': status,
                'error_message': data.get('error', {}).get('message', '')
            }
        
        return {
            'success': False,
            'status': 'UNKNOWN',
            'error_message': f"Status check failed: {response.status_code}"
        }
    
    except Exception as e:
        print(f"Error in check_post_status_internal: {str(e)}", file=sys.stderr)
        return {
            'success': False,
            'status': 'ERROR',
            'error_message': str(e)
        }

def post_video_to_tiktok(user_id, title, video_url, privacy_level, disable_comment, disable_duet, disable_stitch):
    """Post a video to TikTok using the Direct Post API"""
    try:
        # Get user's access token
        profile = TikTokProfile.objects.get(user_id=user_id)
        access_token = profile.access_token
        
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
    
    except TikTokProfile.DoesNotExist:
        return {'success': False, 'error': 'TikTok profile not found for this user'}
    except Exception as e:
        print(f"Error in post_video_to_tiktok: {str(e)}", file=sys.stderr)
        return {'success': False, 'error': str(e)}

@tiktok_login_required
def notifications_view(request):
    """Display user notifications"""
    try:
        context = {
            'username': request.session.get('tiktok_username', 'TikTok User'),
            'profile_picture': request.session.get('tiktok_profile_picture', None),
        }
        
        # Get notifications
        user_id = request.session.get('user_id')
        if user_id:
            try:
                notifications = Notification.objects.filter(user_id=user_id)
                context['notifications'] = notifications
            except Exception as e:
                print(f"Error fetching notifications: {str(e)}", file=sys.stderr)
                context['error'] = "Could not retrieve your notifications"
        
        return render(request, 'accounts/notifications.html', context)
    
    except Exception as e:
        print(f"Error in notifications_view: {str(e)}", file=sys.stderr)
        error_context = {
            'error_title': 'Notifications Error',
            'error_message': 'There was a problem loading your notifications. Please try again later.'
        }
        return render(request, 'accounts/error.html', error_context)

@tiktok_login_required
def mark_notification_read(request, notification_id):
    """Mark a notification as read"""
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        notification = get_object_or_404(Notification, id=notification_id, user_id=user_id)
        notification.read = True
        notification.save()
        return JsonResponse({'success': True})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})

@tiktok_login_required
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
    try:
        # Check if user is authenticated with TikTok
        tiktok_authenticated = request.session.get('tiktok_authenticated', False)
        
        context = {
            'tiktok_authenticated': tiktok_authenticated
        }
        
        if tiktok_authenticated:
            # Get user profile information from session
            context.update({
                'username': request.session.get('tiktok_username', 'TikTok User'),
                'profile_picture': request.session.get('tiktok_profile_picture', None),
            })
            
            # Get access token for API calls
            access_token = request.session.get('tiktok_access_token')
            
            # Get published posts for analytics
            user_id = request.session.get('user_id')
            if user_id:
                try:
                    published_posts = ScheduledPost.objects.filter(
                        user_id=user_id, 
                        status='published'
                    ).select_related('analytics')
                    
                    # Try to update analytics for posts that have a TikTok ID
                    if access_token:
                        from .tiktok_api import update_post_analytics
                        for post in published_posts:
                            if post.tiktok_post_id:
                                update_post_analytics(post, access_token)
                    
                    context['published_posts'] = published_posts
                    
                    # Calculate totals safely using try/except to handle missing analytics
                    total_views = 0
                    total_likes = 0
                    total_comments = 0
                    total_shares = 0
                    
                    for post in published_posts:
                        try:
                            if hasattr(post, 'analytics'):
                                total_views += post.analytics.views
                                total_likes += post.analytics.likes
                                total_comments += post.analytics.comments
                                total_shares += post.analytics.shares
                        except Exception as e:
                            print(f"Error processing analytics for post {post.id}: {str(e)}", file=sys.stderr)
                    
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
                except Exception as e:
                    print(f"Error fetching published posts: {str(e)}", file=sys.stderr)
                    context['error'] = "Could not retrieve post analytics data"
        
        return render(request, 'accounts/analytics.html', context)
    
    except Exception as e:
        print(f"Error in analytics_view: {str(e)}", file=sys.stderr)
        context = {
            'error': "An error occurred while loading analytics."
        }
        return render(request, 'accounts/analytics.html', context)