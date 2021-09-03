from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings
from .views import *
from rest_framework import routers
from rest_framework_swagger.views import get_swagger_view


schema_view = get_swagger_view(title='Pastebin API')



router = routers.DefaultRouter(trailing_slash=False)
router.register(r'api', AuthViewSet, basename='api')


urlpatterns = [ 

    path('api_swagger', schema_view),

    path('',  first_page, name='first-page'),

    path('home_view', home, name='home_view'),

    path('add_tweet/',  TweetCreateView.as_view(), name='add_tweet'),

    path('tweet/<int:pk>/', post_view, name='post_view'),

    path('mypost_view/', mypost_view, name='mypost_view'),

    path('comment/add/<id>', add_comment, name='add_comment'),

    path('user/<user>/', user_view, name='user_view'),

    path('settings/', settings_view, name="settings"),

    path('follow/<int:followed>/<int:follower>/', follow, name="follow"),
    path('search/', search, name="search"),

    path('user/<str:username>/follows', FollowsListView.as_view(), name='user-follows'),
    path('user/<str:username>/followers', FollowersListView.as_view(), name='user-followers'),

    path('post/<int:pk>/preference/<int:userpreference>', postpreference, name='postpreference'),

    path('tweet/<int:pk>/update/', TweetUpdateView.as_view(), name='tweet-update'),
    path('tweet/<int:pk>/del/', TweetDeleteView.as_view(), name='tweet-delete'),

    path('post-list/', PostListView.as_view(), name='post-list'),
    path('post-create/', PostCreateView.as_view(), name='post-create'),
    path('post-update/<int:pk>/', PostUpdateView.as_view(), name='post-update'),
    path('post-delete/<int:pk>/', PostDeleteView.as_view(), name='post-delete'),

    path('social-auth/', include('social_django.urls', namespace='social')),

    path('api-auth/', include('rest_framework.urls', namespace='rest-framework')),
    path('', include(router.urls)),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
