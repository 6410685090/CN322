from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name="home"),
    path('signup', views.signup, name="signup"),
    path('message', views.sendmessage, name="digital"),
    path('messageRSA', views.sendmessagersa, name="rsa"),
    path('custommessage', views.custommessage, name="custommessage"),
    path('signin', views.signin, name="signin"),
    path('logout', views.logout_view, name="logout"),
    path('messageINdb', views.messageINdb, name="messageINdb"),
    path('test', views.test, name="test"),
    path('testRSA', views.testRSA, name="testRSA"),
]