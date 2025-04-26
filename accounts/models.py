# models.py in accounts app

from django.db import models
from django.contrib.auth.models import User

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