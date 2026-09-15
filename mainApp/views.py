from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from .models import LoginHistory, AuditLog, UserProfile
import json
from datetime import timedelta

def login_view(request):
    """
    Handle user login with enhanced security and logging
    """
    if request.user.is_authenticated:
        messages.info(request, 'You are already logged in.')
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        # Basic validation
        if not username or not password:
            messages.error(request, 'Please enter both username and password.')
            return render(request, 'login.html')
        
        # Rate limiting check (basic implementation)
        if is_rate_limited(request):
            messages.error(request, 'Too many login attempts. Please try again later.')
            return render(request, 'login.html')
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.is_active:
                login(request, user)
                
                # Get client information
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]  # Limit length
                
                # Log login history
                LoginHistory.objects.create(
                    user=user,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Log audit action
                AuditLog.log_action(
                    user=user,
                    action='LOGIN',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        'user_agent': user_agent,
                        'timestamp': timezone.now().isoformat()
                    }
                )
                
                # Update user profile last activity
                profile, created = UserProfile.objects.get_or_create(user=user)
                profile.last_activity = timezone.now()
                profile.save()
                
                messages.success(request, f'Welcome back, {user.username}!')
                
                # Redirect to next page if specified
                next_page = request.GET.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect('dashboard')
            else:
                messages.error(request, 'This account is inactive.')
        else:
            messages.error(request, 'Invalid username or password.')
            
            # Log failed login attempt
            AuditLog.log_action(
                user=None,
                action='LOGIN_FAILED',
                ip_address=get_client_ip(request),
                details={
                    'attempted_username': username,
                    'timestamp': timezone.now().isoformat()
                }
            )
    
    return render(request, 'login.html')

def get_client_ip(request):
    """
    Get the client's IP address with enhanced detection
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip

def is_rate_limited(request):
    """
    Basic rate limiting for login attempts
    """
    ip_address = get_client_ip(request)
    one_minute_ago = timezone.now() - timedelta(minutes=1)
    
    # Count failed login attempts from this IP in the last minute
    recent_failures = AuditLog.objects.filter(
        ip_address=ip_address,
        action='LOGIN_FAILED',
        timestamp__gte=one_minute_ago
    ).count()
    
    return recent_failures >= 5  # Allow 5 attempts per minute

@login_required
def dashboard_view(request):
    """
    Enhanced dashboard with comprehensive user data
    """
    user = request.user
    
    # Get recent login history (last 5 logins)
    recent_logins = LoginHistory.objects.filter(user=user).order_by('-login_time')[:5]
    
    # Get total login count
    total_logins = LoginHistory.objects.filter(user=user).count()
    
    # Get today's login count
    today = timezone.now().date()
    today_logins = LoginHistory.objects.filter(
        user=user, 
        login_time__date=today
    ).count()
    
    # Get user's audit logs (last 10 actions)
    recent_actions = AuditLog.objects.filter(user=user).order_by('-timestamp')[:10]
    
    # Get login statistics for the last 7 days (optimized query)
    seven_days_ago = timezone.now() - timedelta(days=7)
    
    weekly_logins = LoginHistory.objects.filter(
        user=user,
        login_time__gte=seven_days_ago
    ).annotate(
        date=TruncDate('login_time')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')
    
    # Prepare weekly login data properly
    weekly_data = {
        'dates': [],
        'counts': []
    }
    
    for login in weekly_logins:
        if login['date']:  # Ensure date is not None
            weekly_data['dates'].append(login['date'].strftime('%Y-%m-%d'))
            weekly_data['counts'].append(login['count'])
    
    # Get or create user profile
    user_profile, created = UserProfile.objects.get_or_create(user=user)
    
    context = {
        'user': user,
        'user_profile': user_profile,
        'recent_logins': recent_logins,
        'recent_actions': recent_actions,
        'total_logins': total_logins,
        'today_logins': today_logins,
        'weekly_data': weekly_data,
        'login_streak': calculate_login_streak(user),
    }
    
    return render(request, 'dashboard.html', context)

@login_required
def profile_view(request):
    """
    User profile management view
    """
    user = request.user
    profile, created = UserProfile.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        # Handle profile updates
        profile.phone_number = request.POST.get('phone_number', '')
        profile.address = request.POST.get('address', '')
        profile.bio = request.POST.get('bio', '')
        profile.website = request.POST.get('website', '')
        profile.twitter = request.POST.get('twitter', '')
        
        # Handle date of birth
        dob = request.POST.get('date_of_birth')
        if dob:
            try:
                profile.date_of_birth = dob
            except ValueError:
                messages.error(request, 'Invalid date format.')
        
        profile.save()
        
        # Log profile update
        AuditLog.log_action(
            user=user,
            action='PROFILE_UPDATE',
            ip_address=get_client_ip(request),
            details='User updated their profile information'
        )
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('dashboard')
    
    return render(request, 'profile.html', {
        'user': user,
        'profile': profile
    })

@login_required
def security_view(request):
    """
    Security settings and login history view
    """
    user = request.user
    
    # Get comprehensive login history
    login_history = LoginHistory.objects.filter(user=user).order_by('-login_time')[:20]
    
    # Get security-related audit logs
    security_logs = AuditLog.objects.filter(
        user=user,
        action__in=['LOGIN', 'LOGOUT', 'PASSWORD_CHANGE', 'PROFILE_UPDATE']
    ).order_by('-timestamp')[:15]
    
    context = {
        'user': user,
        'login_history': login_history,
        'security_logs': security_logs,
    }
    
    return render(request, 'security.html', context)

@login_required
def change_password_view(request):
    """
    Handle password change with security best practices
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            
            # Update session to prevent logout
            update_session_auth_hash(request, user)
            
            # Log password change action
            AuditLog.log_action(
                user=user,
                action='PASSWORD_CHANGE',
                ip_address=get_client_ip(request),
                details='User changed their password successfully'
            )
            
            messages.success(request, 'Your password was successfully updated!')
            return redirect('security')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'change_password.html', {
        'form': form,
        'user': request.user
    })

@login_required
def password_strength_check(request):
    """
    API endpoint to check password strength (for AJAX calls)
    """
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        password = request.POST.get('password', '')
        try:
            validate_password(password)
            return JsonResponse({'valid': True, 'message': 'Password is strong'})
        except ValidationError as e:
            return JsonResponse({'valid': False, 'errors': e.messages})
    
    return JsonResponse({'error': 'Invalid request'}, status=400)

def logout_view(request):
    """
    Handle user logout with comprehensive logging
    """
    if request.user.is_authenticated:
        user = request.user
        
        # Log audit action before logout
        AuditLog.log_action(
            user=user,
            action='LOGOUT',
            ip_address=get_client_ip(request),
            details={
                'timestamp': timezone.now().isoformat()
            }
        )
        
        logout(request)
        messages.success(request, 'You have been successfully logged out.')
    else:
        messages.info(request, 'You were not logged in.')
    
    return redirect('login')

# Utility functions
def calculate_login_streak(user):
    """
    Calculate user's current login streak - FIXED VERSION
    """
    try:
        logins = LoginHistory.objects.filter(
            user=user, 
            is_successful=True
        )

        if not logins.exists():
            return 0

        dates_set = {l.login_time.date() for l in logins}
        sorted_dates = sorted(list(dates_set), reverse=True)

        streak = 1
        for i in range(len(sorted_dates) - 1):
            if (sorted_dates[i] - sorted_dates[i+1]).days == 1:
                streak += 1
            else:
                break

        return streak
    except Exception as e:
        print(f"Error calculating login streak: {e}")
        return 0

@login_required
def activity_view(request):
    """
    User activity overview
    """
    user = request.user
    
    # Get various activity metrics
    today = timezone.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    
    activities = {
        'logins_today': LoginHistory.objects.filter(user=user, login_time__date=today).count(),
        'logins_week': LoginHistory.objects.filter(user=user, login_time__date__gte=week_ago).count(),
        'logins_month': LoginHistory.objects.filter(user=user, login_time__date__gte=month_ago).count(),
        'total_actions': AuditLog.objects.filter(user=user).count(),
        'last_action': AuditLog.objects.filter(user=user).order_by('-timestamp').first(),
    }
    
    return render(request, 'activity.html', {
        'user': user,
        'activities': activities
    })

# Simple dashboard view without complex analytics (if you still have issues)
@login_required
def simple_dashboard_view(request):
    """
    Simplified dashboard without complex queries
    """
    user = request.user
    
    # Get recent login history (last 5 logins)
    recent_logins = LoginHistory.objects.filter(user=user).order_by('-login_time')[:5]
    
    # Get total login count
    total_logins = LoginHistory.objects.filter(user=user).count()
    
    # Get user profile
    user_profile, created = UserProfile.objects.get_or_create(user=user)
    
    context = {
        'user': user,
        'user_profile': user_profile,
        'recent_logins': recent_logins,
        'total_logins': total_logins,
    }
    
    return render(request, 'dashboard.html', context)

# Additional utility functions for password management
def manually_hash_password(password):
    """
    Utility function to manually hash passwords when needed
    Useful for creating users outside of Django's auth system
    """
    from django.contrib.auth.hashers import make_password
    return make_password(password)

def verify_password(plain_password, hashed_password):
    """
    Utility function to verify passwords without User object
    Useful for custom authentication scenarios
    """
    from django.contrib.auth.hashers import check_password
    return check_password(plain_password, hashed_password)

# Error handling views
def handler404(request, exception):
    """
    Custom 404 error handler
    """
    return render(request, '404.html', status=404)

def handler500(request):
    """
    Custom 500 error handler
    """
    return render(request, '500.html', status=500)

def handler403(request, exception):
    """
    Custom 403 error handler
    """
    return render(request, '403.html', status=403)

def handler400(request, exception):
    """
    Custom 400 error handler
    """
    return render(request, '400.html', status=400)

# Security middleware functions
def check_password_complexity(password):
    """
    Check password complexity beyond Django's validators
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    
    if not any(char.isdigit() for char in password):
        errors.append("Password must contain at least one number.")
    
    if not any(char.isupper() for char in password):
        errors.append("Password must contain at least one uppercase letter.")
    
    if not any(char.islower() for char in password):
        errors.append("Password must contain at least one lowercase letter.")
    
    if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for char in password):
        errors.append("Password must contain at least one special character.")
    
    return errors

def get_password_strength_indicator(password):
    """
    Calculate password strength score (0-100)
    """
    score = 0
    
    # Length check
    if len(password) >= 8:
        score += 25
    elif len(password) >= 6:
        score += 15
    
    # Character variety
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for char in password)
    
    variety_count = sum([has_upper, has_lower, has_digit, has_special])
    score += variety_count * 15
    
    # Bonus for length beyond minimum
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    
    return min(score, 100)