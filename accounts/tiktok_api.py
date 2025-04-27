"""
TikTok API Helper Functions
"""
import sys
import requests
import json
from datetime import datetime, timedelta

def fetch_post_analytics(post_id, access_token):
    """
    Fetch analytics data for a specific post from TikTok API
    
    Args:
        post_id (str): The TikTok post ID
        access_token (str): The user's TikTok access token
        
    Returns:
        dict: Analytics data for the post or None if failed
    """
    try:
        # TikTok API endpoint for video analytics
        analytics_url = "https://open.tiktokapis.com/v2/video/query/analytics/"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        # Request data - get analytics metrics
        data = {
            'video_ids': [post_id],
            'metrics': ['video_view_count', 'like_count', 'comment_count', 'share_count']
        }
        
        print(f"Fetching analytics for post {post_id}", file=sys.stderr)
        response = requests.post(analytics_url, headers=headers, json=data)
        
        print(f"Analytics response code: {response.status_code}", file=sys.stderr)
        print(f"Analytics response content: {response.text}", file=sys.stderr)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'videos' in data['data']:
                videos = data['data']['videos']
                if videos and len(videos) > 0:
                    return {
                        'views': videos[0].get('video_view_count', 0),
                        'likes': videos[0].get('like_count', 0),
                        'comments': videos[0].get('comment_count', 0),
                        'shares': videos[0].get('share_count', 0)
                    }
        
        return None
    except Exception as e:
        print(f"Error fetching post analytics: {str(e)}", file=sys.stderr)
        return None

def update_post_analytics(post, access_token):
    """
    Update analytics data for a post
    
    Args:
        post (ScheduledPost): The post model instance
        access_token (str): TikTok access token
        
    Returns:
        bool: True if successful, False otherwise
    """
    from .models import PostAnalytics
    
    try:
        # Only attempt to update if we have a TikTok post ID
        if not post.tiktok_post_id:
            return False
            
        # Fetch analytics data
        analytics_data = fetch_post_analytics(post.tiktok_post_id, access_token)
        if not analytics_data:
            return False
            
        # Update or create analytics record
        analytics, created = PostAnalytics.objects.get_or_create(post=post)
        
        # Update fields
        analytics.views = analytics_data['views']
        analytics.likes = analytics_data['likes']
        analytics.comments = analytics_data['comments']
        analytics.shares = analytics_data['shares']
        
        # Calculate engagement rate
        if analytics.views > 0:
            engagement_actions = analytics.likes + analytics.comments + analytics.shares
            analytics.engagement_rate = round((engagement_actions / analytics.views) * 100, 2)
        else:
            analytics.engagement_rate = 0
            
        analytics.save()
        return True
        
    except Exception as e:
        print(f"Error updating post analytics: {str(e)}", file=sys.stderr)
        return False 