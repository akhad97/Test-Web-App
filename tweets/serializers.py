from rest_framework import serializers
from .models import Post

from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.base_user import BaseUserManager
from rest_framework.authtoken.models import Token

User = get_user_model()



class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ('id', 'content', 'img', 'add_date', 'author')
        read_only_fields = ('author',)


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=300, required=True)
    password = serializers.CharField(required=True, write_only=True)
    

class AuthUserSerializer(serializers.ModelSerializer):
    auth_token = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'username','is_active', 'is_staff', 'auth_token')
        read_only_fields = ('id', 'is_active', 'is_staff', 'auth_token')
    
    def get_auth_token(self, obj):
        token, created = Token.objects.get_or_create(user=obj)
        return token.key

class EmptySerializer(serializers.Serializer):
    pass


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password')

    def validate_email(username, value):
        user = User.objects.filter(username=username)
        if user:
            raise serializers.ValidationError("Email is already taken")
        return BaseUserManager.normalize_email(value)

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value


class ResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100)
    
    class Meta:
        model = User
        fields = '__all__'
    def save(self):
        email = self.validated_data['email']
        password = self.validated_data['password']
    
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            user.set_password(password)
            user.save()
            return user
        else:
            raise serializers.ValidationError({'error':'Please enter valid credentials!'})