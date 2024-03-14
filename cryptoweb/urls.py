from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name="home"),
    path('signup', views.signup, name="signup"),
    path('message', views.sendmessage, name="digital"),
    path('messageRSA', views.sendmessagersa, name="rsa"),
    path('signin', views.signin, name="signin"),
    path('logout', views.logout_view, name="logout"),
]