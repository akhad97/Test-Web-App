# Generated by Django 2.2.13 on 2021-07-31 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tweets', '0015_auto_20210730_2342'),
    ]

    operations = [
        migrations.AlterField(
            model_name='post',
            name='img',
            field=models.ImageField(blank=True, null=True, upload_to='media/post'),
        ),
    ]
