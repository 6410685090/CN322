from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name="home"),
    path('passwdenc', views.passenc, name="passenc"),
    path('message', views.digital, name="digital"),
]