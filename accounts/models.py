# models.py in accounts app

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class TikTokProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    tiktok_id = models.CharField(max_length=255, unique=True)
    username = models.CharField(max_length=255, blank=True)
    profile_picture = models.URLField(max_length=500, blank=True)
    access_token = models.CharField(max_length=500)
    refresh_token = models.CharField(max_length=500)
    token_expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"{self.user.username}'s TikTok Profile"

class ScheduledPost(models.Model):
    STATUS_CHOICES = (
        ('scheduled', 'Scheduled'),
        ('processing', 'Processing'),
        ('published', 'Published'),
        ('failed', 'Failed'),
    )
    
    POST_TYPE_CHOICES = (
        ('video', 'Video'),
        ('photo', 'Photo'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scheduled_posts')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    media_type = models.CharField(max_length=10, choices=POST_TYPE_CHOICES, default='video')
    media_url = models.URLField(max_length=500)  # For remote videos
    media_file = models.FileField(upload_to='tiktok_uploads/', blank=True, null=True)  # For local uploads
    cloudinary_public_id = models.CharField(max_length=500, blank=True)  # Store Cloudinary public_id
    thumbnail_url = models.URLField(max_length=500, blank=True)
    privacy_level = models.CharField(max_length=50, default='PUBLIC_TO_EVERYONE')
    disable_comment = models.BooleanField(default=False)
    disable_duet = models.BooleanField(default=False)
    disable_stitch = models.BooleanField(default=False)
    auto_add_music = models.BooleanField(default=True)
    hashtags = models.CharField(max_length=500, blank=True)  # Stored as comma-separated values
    
    # For scheduling
    scheduled_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # For tracking status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    publish_id = models.CharField(max_length=100, blank=True)
    tiktok_post_id = models.CharField(max_length=100, blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-scheduled_time']
    
    def __str__(self):
        return f"{self.title} - {self.get_status_display()}"
    
    @property
    def is_published(self):
        return self.status == 'published'
    
    @property
    def is_scheduled(self):
        return self.status == 'scheduled'
    
    @property
    def is_pending(self):
        return self.status == 'processing'
    
    @property
    def is_failed(self):
        return self.status == 'failed'
    
    @property
    def is_past_due(self):
        return self.scheduled_time <= timezone.now() and self.status == 'scheduled'
    
    def delete_cloudinary_media(self):
        """Delete media from Cloudinary if public_id exists"""
        from .cloudinary_utils import delete_media, extract_public_id_from_url
        
        if self.cloudinary_public_id:
            # If we have stored the public_id directly
            delete_media(self.cloudinary_public_id, resource_type="image")
            self.cloudinary_public_id = ''
            self.save(update_fields=['cloudinary_public_id'])
        elif self.media_url and 'res.cloudinary.com' in self.media_url:
            # Try to extract public_id from URL if we don't have it stored
            public_id = extract_public_id_from_url(self.media_url)
            if public_id:
                delete_media(public_id, resource_type="image")

class PostAnalytics(models.Model):
    post = models.OneToOneField(ScheduledPost, on_delete=models.CASCADE, related_name='analytics')
    views = models.PositiveIntegerField(default=0)
    likes = models.PositiveIntegerField(default=0)
    comments = models.PositiveIntegerField(default=0)
    shares = models.PositiveIntegerField(default=0)
    engagement_rate = models.FloatField(default=0.0)
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Analytics for {self.post.title}"
    
class Notification(models.Model):
    TYPE_CHOICES = (
        ('success', 'Success'),
        ('error', 'Error'),
        ('info', 'Information'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='info')
    post = models.ForeignKey(ScheduledPost, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.get_type_display()}: {self.message[:30]}..."