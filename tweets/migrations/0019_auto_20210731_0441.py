# Generated by Django 2.2.13 on 2021-07-31 11:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tweets', '0018_auto_20210731_0025'),
    ]

    operations = [
        migrations.AlterField(
            model_name='post',
            name='img',
            field=models.ImageField(blank=True, null=True, upload_to='post/'),
        ),
    ]
