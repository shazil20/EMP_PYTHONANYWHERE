# Generated by Django 5.0.4 on 2024-06-06 07:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Employee_management_system', '0013_alter_notification_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='designation',
            field=models.CharField(blank=True, max_length=155, null=True),
        ),
    ]
