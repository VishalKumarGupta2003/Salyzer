from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
import uuid
import os

# Create your models here.

def profile_picture_upload_path(instance, filename):
    """
    Generate upload path for profile pictures
    """
    ext = filename.split('.')[-1]
    filename = f"{instance.user.username}_{uuid.uuid4().hex[:8]}.{ext}"
    return os.path.join('profile_pics', filename)

class UserProfile(models.Model):
    """
    Extended user profile model to add additional information to the User model
    """
    # User connection
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE,
        related_name='profile'
    )
    
    # Personal information
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(
        validators=[phone_regex],
        max_length=17,
        blank=True,
        null=True,
        verbose_name=_("Phone Number")
    )
    
    address = models.TextField(
        blank=True, 
        null=True,
        verbose_name=_("Address")
    )
    
    date_of_birth = models.DateField(
        blank=True, 
        null=True,
        verbose_name=_("Date of Birth")
    )
    
    # Profile media
    profile_picture = models.ImageField(
        upload_to=profile_picture_upload_path,
        blank=True, 
        null=True,
        verbose_name=_("Profile Picture"),
        help_text=_("Upload a profile picture (max 2MB)")
    )
    
    # Additional details
    bio = models.TextField(
        blank=True, 
        null=True,
        max_length=500,
        verbose_name=_("Biography"),
        help_text=_("Tell us about yourself (max 500 characters)")
    )
    
    # Social links
    website = models.URLField(
        blank=True, 
        null=True,
        verbose_name=_("Website")
    )
    
    twitter = models.CharField(
        max_length=50,
        blank=True, 
        null=True,
        verbose_name=_("Twitter Handle")
    )
    
    # Preferences
    THEME_CHOICES = [
        ('light', _('Light')),
        ('dark', _('Dark')),
        ('auto', _('Auto')),
    ]
    
    theme_preference = models.CharField(
        max_length=10,
        choices=THEME_CHOICES,
        default='auto',
        verbose_name=_("Theme Preference")
    )
    
    email_notifications = models.BooleanField(
        default=True,
        verbose_name=_("Email Notifications")
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_activity = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("User Profile")
        verbose_name_plural = _("User Profiles")
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    def get_age(self):
        """Calculate user's age from date of birth"""
        if self.date_of_birth:
            today = timezone.now().date()
            return today.year - self.date_of_birth.year - (
                (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None
    
    @property
    def display_name(self):
        """Get display name (first name + last name or username)"""
        if self.user.first_name and self.user.last_name:
            return f"{self.user.first_name} {self.user.last_name}"
        return self.user.username

class LoginHistory(models.Model):
    """
    Model to track user login history with enhanced security features
    """
    # User connection
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='login_history'
    )
    
    # Login details
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(blank=True, null=True)
    
    # Device and location info
    ip_address = models.GenericIPAddressField(
        blank=True, 
        null=True,
        verbose_name=_("IP Address")
    )
    
    user_agent = models.TextField(
        blank=True, 
        null=True,
        verbose_name=_("User Agent")
    )
    
    # Security flags
    is_successful = models.BooleanField(default=True)
    failure_reason = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name=_("Failure Reason")
    )
    
    # Location data (could be populated via IP lookup service)
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name=_("Country")
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name=_("City")
    )
    
    # Session info
    session_key = models.CharField(
        max_length=40,
        blank=True,
        null=True,
        verbose_name=_("Session Key")
    )

    class Meta:
        verbose_name = _("Login History")
        verbose_name_plural = _("Login Histories")
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', 'login_time']),
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        status = "successfully" if self.is_successful else "failed"
        return f"{self.user.username} login {status} at {self.login_time}"
    
    def session_duration(self):
        """Calculate session duration if logout time is available"""
        if self.logout_time and self.login_time:
            return self.logout_time - self.login_time
        return None
    
    def mark_logout(self, logout_time=None):
        """Mark the logout time"""
        self.logout_time = logout_time or timezone.now()
        self.save()

class AuditLog(models.Model):
    """
    Enhanced model to track important user actions with categorization
    """
    ACTION_CATEGORIES = [
        ('AUTH', _('Authentication')),
        ('PROFILE', _('Profile Management')),
        ('SECURITY', _('Security')),
        ('SYSTEM', _('System')),
        ('OTHER', _('Other')),
    ]
    
    ACTION_CHOICES = [
        # Authentication actions
        ('LOGIN', _('User Login')),
        ('LOGIN_FAILED', _('Login Failed')),
        ('LOGOUT', _('User Logout')),
        ('PASSWORD_CHANGE', _('Password Changed')),
        ('PASSWORD_RESET', _('Password Reset')),
        
        # Profile actions
        ('PROFILE_CREATE', _('Profile Created')),
        ('PROFILE_UPDATE', _('Profile Updated')),
        ('PROFILE_PICTURE_UPDATE', _('Profile Picture Updated')),
        
        # Security actions
        ('TWO_FACTOR_ENABLED', _('Two-Factor Authentication Enabled')),
        ('TWO_FACTOR_DISABLED', _('Two-Factor Authentication Disabled')),
        ('BACKUP_CODES_GENERATED', _('Backup Codes Generated')),
        
        # System actions
        ('ACCOUNT_LOCKED', _('Account Locked')),
        ('ACCOUNT_UNLOCKED', _('Account Unlocked')),
        ('SESSION_EXPIRED', _('Session Expired')),
        
        # Other actions
        ('EMAIL_CHANGE', _('Email Address Changed')),
        ('PRIVACY_SETTINGS_UPDATE', _('Privacy Settings Updated')),
    ]

    # Unique identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # User connection (can be null for system actions)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='audit_logs',
        null=True,
        blank=True
    )
    
    # Action details
    category = models.CharField(
        max_length=10,
        choices=ACTION_CATEGORIES,
        default='OTHER'
    )
    
    action = models.CharField(
        max_length=30,
        choices=ACTION_CHOICES,
        verbose_name=_("Action Type")
    )
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Request details
    ip_address = models.GenericIPAddressField(
        blank=True, 
        null=True,
        verbose_name=_("IP Address")
    )
    
    user_agent = models.TextField(
        blank=True, 
        null=True,
        verbose_name=_("User Agent")
    )
    
    # Additional context - Using TextField instead of JSONField to avoid migration issues
    details = models.TextField(
        blank=True,
        null=True,
        verbose_name=_("Action Details"),
        help_text=_("Structured data about the action (stored as JSON string)")
    )
    
    # Severity level
    SEVERITY_LEVELS = [
        ('INFO', _('Information')),
        ('WARNING', _('Warning')),
        ('ERROR', _('Error')),
        ('CRITICAL', _('Critical')),
    ]
    
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_LEVELS,
        default='INFO'
    )

    class Meta:
        verbose_name = _("Audit Log")
        verbose_name_plural = _("Audit Logs")
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['category']),
        ]

    def __str__(self):
        username = self.user.username if self.user else 'System'
        return f"{username} - {self.get_action_display()} at {self.timestamp}"
    
    def get_details_dict(self):
        """Parse details as JSON and return as dictionary"""
        import json
        if self.details:
            try:
                return json.loads(self.details)
            except (json.JSONDecodeError, TypeError):
                return {'raw_details': self.details}
        return {}
    
    def set_details_dict(self, details_dict):
        """Set details as JSON string from dictionary"""
        import json
        if details_dict:
            self.details = json.dumps(details_dict)
        else:
            self.details = None
    
    @classmethod
    def log_action(cls, user, action, ip_address=None, user_agent=None, details=None, severity='INFO'):
        """Helper method to quickly log actions"""
        # Determine category based on action
        category_map = {
            'LOGIN': 'AUTH', 'LOGIN_FAILED': 'AUTH', 'LOGOUT': 'AUTH',
            'PASSWORD_CHANGE': 'SECURITY', 'PASSWORD_RESET': 'SECURITY',
            'PROFILE_CREATE': 'PROFILE', 'PROFILE_UPDATE': 'PROFILE',
            'TWO_FACTOR_ENABLED': 'SECURITY', 'TWO_FACTOR_DISABLED': 'SECURITY',
        }
        
        category = category_map.get(action, 'OTHER')
        
        # Convert details to JSON string if it's a dict
        details_str = None
        if details is not None:
            import json
            if isinstance(details, dict):
                details_str = json.dumps(details)
            else:
                details_str = str(details)
        
        return cls.objects.create(
            user=user,
            category=category,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details_str,
            severity=severity
        )

class UserSettings(models.Model):
    """
    Model for user preferences and settings
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='settings'
    )
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    security_alerts = models.BooleanField(default=True)
    
    # Privacy settings
    profile_visibility = models.CharField(
        max_length=10,
        choices=[
            ('PUBLIC', _('Public')),
            ('PRIVATE', _('Private')),
            ('FRIENDS', _('Friends Only')),
        ],
        default='PRIVATE'
    )
    
    # UI preferences
    theme = models.CharField(
        max_length=10,
        choices=[
            ('LIGHT', _('Light')),
            ('DARK', _('Dark')),
            ('AUTO', _('Auto')),
        ],
        default='AUTO'
    )
    
    language = models.CharField(
        max_length=10,
        default='en',
        choices=[
            ('en', _('English')),
            ('es', _('Spanish')),
            ('fr', _('French')),
        ]
    )
    
    # Security preferences
    two_factor_enabled = models.BooleanField(default=False)
    login_alerts = models.BooleanField(default=True)
    
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("User Settings")
        verbose_name_plural = _("User Settings")

    def __str__(self):
        return f"Settings for {self.user.username}"

# Signals to automatically create profile and settings
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile and UserSettings when a new User is created"""
    if created:
        UserProfile.objects.create(user=instance)
        UserSettings.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save UserProfile when User is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()
    if hasattr(instance, 'settings'):
        instance.settings.save()