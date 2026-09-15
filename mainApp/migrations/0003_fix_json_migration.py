from django.db import migrations, models
import json

def convert_text_to_json(apps, schema_editor):
    """
    Convert existing text details to JSON format
    """
    AuditLog = apps.get_model('mainApp', 'AuditLog')
    
    for audit_log in AuditLog.objects.all():
        if audit_log.details and not isinstance(audit_log.details, dict):
            try:
                # Try to parse as JSON
                if audit_log.details.strip():
                    audit_log.details = json.loads(audit_log.details)
                else:
                    audit_log.details = None
            except (json.JSONDecodeError, TypeError):
                # If it's not valid JSON, wrap it in a message field
                audit_log.details = {'message': audit_log.details}
        elif not audit_log.details:
            audit_log.details = None
        
        audit_log.save()

def convert_json_to_text(apps, schema_editor):
    """
    Convert JSON back to text for backwards migration
    """
    AuditLog = apps.get_model('mainApp', 'AuditLog')
    
    for audit_log in AuditLog.objects.all():
        if audit_log.details and isinstance(audit_log.details, dict):
            audit_log.details = json.dumps(audit_log.details)
        audit_log.save()

class Migration(migrations.Migration):

    dependencies = [
        ('mainApp', '0002_usersettings_alter_auditlog_options_and_more'),
    ]

    operations = [
        migrations.RunPython(convert_text_to_json, convert_json_to_text),
    ]