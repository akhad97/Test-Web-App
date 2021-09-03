from django.contrib import admin

from .models import Post, Comment, Follow


# Register your models here.

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'author', 'add_date')
    readonly_fields = ('add_date',)


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'author', 'add_date')
    readonly_fields = ('add_date',)


# @admin.register(UserProfile)
# class UserProfileAdmin(admin.ModelAdmin):
#     pass


@admin.register(Follow)
class FollowAdmin(admin.ModelAdmin):
    pass
