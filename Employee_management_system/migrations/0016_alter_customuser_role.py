# Generated by Django 5.0.4 on 2024-06-26 12:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Employee_management_system', '0015_remove_customuser_remaining_leave'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='role',
            field=models.CharField(blank=True, choices=[('admin', 'Admin'), ('user', 'User')], default='User', max_length=50, null=True),
        ),
    ]
