# def home(request):
#     return HttpResponse("Home page " + str(request.user))
from allauth.account.signals import user_signed_up
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.dispatch import receiver
from django.shortcuts import render, redirect, get_object_or_404

from tweets.models import Post, Comment, Follow
from .forms import *

from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin

from rest_framework.schemas import AutoSchema
from rest_framework.response import Response
from rest_framework import status

from rest_framework import generics, viewsets
from .serializers import *
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny

from .pagination import CustomPagination
from .utils import get_and_authenticate_user, create_user_account

from rest_framework.views import APIView




@login_required(redirect_field_name='account_login')
def home(request):
    users = User.objects.filter(is_superuser=False)
    posts = Post.objects.all()
    tweets = Post.objects.filter(
        author__follow_user__user=request.user) | Post.objects.filter(author=request.user).order_by('-add_date')

    paginator = Paginator(tweets, 3)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'users':users,
        "user_info": request.user,
        # "user_profile": UserProfile.objects.get(user=request.user),
        "tweets": page_obj,
        'posts':posts
    }
    return render(request, 'feed/home.html', context)

@login_required(redirect_field_name='account_login')
def mypost_view(request):
    tweets = Post.objects.filter(author=request.user)
    context = {
        'tweets':tweets,
        "user_info": request.user,
        # "user_profile": UserProfile.objects.get(user=request.user),
        # "tweet": Post.objects.get(pk=pk),
    }
    return render(request, 'feed/mypost.html', context)

@login_required(redirect_field_name='account_login')
def post_view(request, pk):
    context = {
        "user_info": request.user,
        # "user_profile": UserProfile.objects.get(user=request.user),
        "tweet": Post.objects.get(pk=pk),
        "pk": pk,
    }
    return render(request, 'feed/post.html', context)


@login_required(redirect_field_name='account_login')
def user_view(request, user):
    user = User.objects.get(username=user)
    tweets = Post.objects.filter(author=user).order_by("-add_date")
    paginator = Paginator(tweets, 3)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        "user_info": user,
        # "user_profile": UserProfile.objects.get(user=user),
        "tweets": page_obj,
        "following": len(Follow.objects.filter(user=request.user).filter(follow_user=user)),
    }
    return render(request, 'feed/user.html', context)


@login_required(redirect_field_name='account_login')
def settings_view(request):
    user = request.user

    if request.method == "POST":
        if user.username != request.POST.get('username'):
            if not len(User.objects.filter(username__exact=request.POST.get('username'))):
                request.user.username = request.POST.get('username')

        if user.email != request.POST.get('email'):
            if not len(User.objects.filter(email__exact=request.POST.get('email'))):
                request.user.email = request.POST.get('email')

        if request.FILES:
            UserProfile(avatar=request.FILES['avatar'], user=user).save()

    user.profile.save()
    user.save()
    context = {
        "user_info": user,
        # "user_profile": UserProfile.objects.get(user=user),

    }
    return render(request, 'feed/settings.html', context)


@receiver(user_signed_up)
def add_UserProfile(user, **kwargs):
    profile = UserProfile(user=user)
    profile.save()


class TweetCreateView(LoginRequiredMixin, CreateView):
    model = Post
    fields = ['content', 'img']
    template_name = 'feed/add_tweet.html'
    context_object_name = 'tweets'
    success_url = '/home_view'

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        data['tag_line'] = 'Add a new post'
        data['user_info'] = self.request.user
        # data['user_profile'] = UserProfile.objects.get(user=self.request.user)
        return data


def first_page(request):
    return render(request, 'feed/first-page.html')


def is_users(post_user, logged_user):
    return post_user == logged_user


class TweetDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Post
    template_name = 'feed/post-delete.html'
    context_object_name = 'post'
    success_url = '/home_view'

    def test_func(self):
        return is_users(self.get_object().author, self.request.user)


class TweetUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Post
    fields = ['content', 'img']
    template_name = 'feed/post-update.html'
    success_url = '/home_view'

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

    def test_func(self):
        return is_users(self.get_object().author, self.request.user)

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        data['tag_line'] = 'Edit a post'
        return data


@login_required(redirect_field_name='account_login')
def add_comment(request, id):
    comment = Comment(content=request.POST.get('content'), author=request.user, post=Post.objects.get(pk=id))
    comment.save()

    return redirect('post_view', pk=id)


@login_required(redirect_field_name='account_login')
def follow(request, followed, follower):
    follower = User.objects.get(id=follower)
    followed = User.objects.get(id=followed)

    obj = Follow.objects.filter(user=follower).filter(follow_user=followed)
    if obj:
        obj.delete()
    else:
        Follow(user=follower, follow_user=followed).save()

    return redirect('user_view', followed)


@login_required(redirect_field_name='account_login')
def search(request):
    results = User.objects.filter(username__icontains=request.POST.get("search"))
    context = {
        "user_info": request.user,
        # "user_profile": UserProfile.objects.get(user=request.user),
        "results": results,
    }
    return render(request, 'feed/results.html', context)



@login_required
def postpreference(request, pk, userpreference):
        
        if request.method == "POST":
                eachpost= get_object_or_404(Post, id=pk)

                obj=''

                valueobj=''

                try:
                        obj= Preference.objects.get(user= request.user, post= eachpost)

                        valueobj= obj.value #value of userpreference


                        valueobj= int(valueobj)

                        userpreference= int(userpreference)
                
                        if valueobj != userpreference:
                                obj.delete()


                                upref= Preference()
                                upref.user= request.user

                                upref.post= eachpost

                                upref.value= userpreference


                                if userpreference == 1 and valueobj != 1:
                                        eachpost.likes += 1
                                        eachpost.dislikes -=1
                                elif userpreference == 2 and valueobj != 2:
                                        eachpost.dislikes += 1
                                        eachpost.likes -= 1
                                

                                upref.save()

                                eachpost.save()
                        
                        
                                context= {'eachpost': eachpost,
                                  'pk': pk}

                                return redirect('home_view')

                        elif valueobj == userpreference:
                                obj.delete()
                        
                                if userpreference == 1:
                                        eachpost.likes -= 1
                                elif userpreference == 2:
                                        eachpost.dislikes -= 1

                                eachpost.save()

                                context= {'eachpost': eachpost,
                                  'pk': pk}

                                return redirect('home_view')
                                
                        
        
                
                except Preference.DoesNotExist:
                        upref= Preference()

                        upref.user= request.user

                        upref.post= eachpost

                        upref.value= userpreference

                        userpreference= int(userpreference)

                        if userpreference == 1:
                                eachpost.likes += 1
                        elif userpreference == 2:
                                eachpost.dislikes +=1

                        upref.save()

                        eachpost.save()                            


                        context= {'eachpost': eachpost,
                          'pk': pk}

                        return redirect('home_view')


        else:
                eachpost= get_object_or_404(Post, id=pk)
                context= {'eachpost': eachpost,
                          'pk': pk}

                return redirect('home_view')


class FollowsListView(ListView):
    model = Follow
    template_name = 'feed/follow.html'
    context_object_name = 'follows'

    def visible_user(self):
        return get_object_or_404(User, username=self.kwargs.get('username'))

    def get_queryset(self):
        user = self.visible_user()
        return Follow.objects.filter(user=user).order_by('-date')

    def get_context_data(self, *, object_list=None, **kwargs):
        data = super().get_context_data(**kwargs)
        data['follow'] = 'follows'
        data["user_profile"]= UserProfile.objects.get(user=self.request.user)
        return data


class FollowersListView(ListView):
    model = Follow
    template_name = 'feed/follow.html'
    context_object_name = 'follows'

    def visible_user(self):
        return get_object_or_404(User, username=self.kwargs.get('username'))

    def get_queryset(self):
        user = self.visible_user()
        return Follow.objects.filter(follow_user=user).order_by('-date')

    def get_context_data(self, *, object_list=None, **kwargs):
        data = super().get_context_data(**kwargs)
        data['follow'] = 'followers'
        # data["user_profile"]= UserProfile.objects.get(user=self.request.user)
        return data





class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny, ]
    serializer_class = EmptySerializer
    queryset = ''
    serializer_classes = {
        'login': UserLoginSerializer,
        'register': UserRegisterSerializer
    }

    @action(methods=['POST', ], detail=False)
    def register(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = create_user_account(**serializer.validated_data)
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_201_CREATED)

    @action(methods=['POST', ], detail=False)
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_and_authenticate_user(**serializer.validated_data)
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST', ], detail=False)
    def logout(self, request):
        logout(request)
        data = {'success': 'Sucessfully logged out'}
        return Response(data=data, status=status.HTTP_200_OK)

    def get_serializer_class(self):
        if not isinstance(self.serializer_classes, dict):
            raise ImproperlyConfigured("serializer_classes should be a dict mapping.")

        if self.action in self.serializer_classes.keys():
            return self.serializer_classes[self.action]
        return super().get_serializer_class()


class reset_password(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        alldatas={}
        
        if serializer.is_valid(raise_exception=True):
            mname=serializer.save()
            alldatas['data'] = 'successfully registered'
            return Response(alldatas)
        return Response('failed retry after some time')


class PostListViewSchema(AutoSchema):
    def get_manual_fields(self, path, method):
        extra_fields = []
        if method.lower() in ['post', 'put']:
            extra_fields = [
                coreapi.Field('desc')
            ]
        manual_fields = super().get_manual_fields(path, method)
        return manual_fields + extra_fields


class PostListView(generics.ListAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    pagination_class = CustomPagination
    schema = PostListViewSchema()


class PostCreateView(generics.CreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    schema = PostListViewSchema()

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class PostUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    schema = PostListViewSchema()


class PostDeleteView(generics.RetrieveDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    schema = PostListViewSchema()