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
    path('post/photo/', views.post_photo_view, name='post_photo'),
    path('post/status/<str:publish_id>/', views.check_post_status, name='check_post_status'),
    
    # Legacy media proxy endpoint - now Cloudflare Workers handles proxying at https://media.emmanueltech.store/
    path('media/<str:media_id>/<str:filename>', views.proxy_media, name='proxy_media'),
    path('media/test/', views.test_media_endpoint, name='test_media_endpoint'),  # Test endpoint
    
    # New Video Scheduling Routes
    path('post/video/', views.schedule_video_view, name='schedule_video'),
    path('scheduled/', views.scheduled_posts_view, name='scheduled_posts'),
    path('scheduled/<int:post_id>/edit/', views.edit_scheduled_post, name='edit_scheduled_post'),
    path('scheduled/<int:post_id>/delete/', views.delete_scheduled_post, name='delete_scheduled_post'),
    
    # Analytics
    path('analytics/', views.analytics_view, name='analytics'),
    
    # Notifications
    path('notifications/', views.notifications_view, name='notifications'),
    path('notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),
    path('notifications/read-all/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
]